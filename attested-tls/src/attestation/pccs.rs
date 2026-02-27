use std::{
    collections::HashMap,
    sync::{Arc, Weak},
    time::{SystemTime, UNIX_EPOCH},
};

use dcap_qvl::{QuoteCollateralV3, collateral::get_collateral_for_fmspc, tcb_info::TcbInfo};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{
    sync::RwLock,
    task::JoinHandle,
    time::{Duration, sleep},
};

use crate::attestation::dcap::{DcapVerificationError, PCS_URL};

const REFRESH_MARGIN_SECS: i64 = 300;
const REFRESH_RETRY_SECS: u64 = 60;

/// PCCS collateral cache with proactive background refresh
#[derive(Clone)]
pub struct Pccs {
    pccs_url: String,
    cache: Arc<RwLock<HashMap<PccsInput, CacheEntry>>>,
}

impl std::fmt::Debug for Pccs {
    /// Formats PCCS config for debug output without exposing cache internals
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pccs")
            .field("pccs_url", &self.pccs_url)
            .finish_non_exhaustive()
    }
}

impl Pccs {
    /// Creates a new PCCS cache using the provided URL or Intel PCS default
    pub fn new(pccs_url: Option<String>) -> Self {
        Self {
            pccs_url: pccs_url.unwrap_or(PCS_URL.to_string()),
            cache: RwLock::new(HashMap::new()).into(),
        }
    }

    /// Returns collateral from cache when valid, otherwise fetches and caches fresh collateral
    pub async fn get_collateral(
        &self,
        fmspc: String,
        ca: &'static str,
        now: i64,
    ) -> Result<(QuoteCollateralV3, bool), DcapVerificationError> {
        let cache_key = PccsInput::new(fmspc.clone(), ca);

        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(&cache_key) {
                if now < entry.next_update {
                    return Ok((entry.collateral.clone(), false));
                }
                tracing::warn!(
                    fmspc,
                    next_update = entry.next_update,
                    now,
                    "Cached collateral expired, refreshing from PCCS"
                );
            }
        }

        let collateral = fetch_collateral(&self.pccs_url, fmspc.clone(), ca).await?;
        let next_update = extract_next_update(&collateral, now)?;

        let mut cache = self.cache.write().await;
        if let Some(existing) = cache.get(&cache_key) {
            if now < existing.next_update {
                return Ok((existing.collateral.clone(), false));
            }
        }

        upsert_cache_entry(
            &mut cache,
            cache_key.clone(),
            collateral.clone(),
            next_update,
        );
        drop(cache);
        self.ensure_refresh_task(&cache_key).await;
        Ok((collateral, true))
    }

    /// Fetches fresh collateral, overwrites cache, and ensures proactive refresh is scheduled
    pub async fn refresh_collateral(
        &self,
        fmspc: String,
        ca: &'static str,
        now: i64,
    ) -> Result<QuoteCollateralV3, DcapVerificationError> {
        let collateral = fetch_collateral(&self.pccs_url, fmspc.clone(), ca).await?;
        let next_update = extract_next_update(&collateral, now)?;
        let cache_key = PccsInput::new(fmspc, ca);

        {
            let mut cache = self.cache.write().await;
            upsert_cache_entry(
                &mut cache,
                cache_key.clone(),
                collateral.clone(),
                next_update,
            );
        }
        self.ensure_refresh_task(&cache_key).await;
        Ok(collateral)
    }

    /// Starts a background refresh loop for a cache key when no task is active
    async fn ensure_refresh_task(&self, cache_key: &PccsInput) {
        let mut cache = self.cache.write().await;
        let Some(entry) = cache.get_mut(cache_key) else {
            return;
        };
        if entry.refresh_task.is_some() {
            return;
        }

        let weak_cache = Arc::downgrade(&self.cache);
        let key = cache_key.clone();
        let pccs_url = self.pccs_url.clone();
        entry.refresh_task = Some(tokio::spawn(async move {
            refresh_loop(weak_cache, pccs_url, key).await;
        }));
    }
}

/// Cache key for PCCS collateral entries
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct PccsInput {
    fmspc: String,
    ca: String,
}

impl PccsInput {
    /// Builds a cache key from FMSPC and CA identifier
    fn new(fmspc: String, ca: &'static str) -> Self {
        Self {
            fmspc,
            ca: ca.to_string(),
        }
    }
}

/// Fetches collateral from PCCS for a given FMSPC and CA
async fn fetch_collateral(
    pccs_url: &str,
    fmspc: String,
    ca: &'static str,
) -> Result<QuoteCollateralV3, DcapVerificationError> {
    get_collateral_for_fmspc(
        pccs_url, fmspc, ca, false, // Indicates not SGX
    )
    .await
    .map_err(Into::into)
}

/// Extracts the earliest next update timestamp from collateral metadata
fn extract_next_update(
    collateral: &QuoteCollateralV3,
    now: i64,
) -> Result<i64, DcapVerificationError> {
    let tcb_info: TcbInfo = serde_json::from_str(&collateral.tcb_info).map_err(|e| {
        DcapVerificationError::PccsCollateralParse(format!("Failed to parse TCB info JSON: {e}"))
    })?;
    let qe_identity: QeIdentityNextUpdate =
        serde_json::from_str(&collateral.qe_identity).map_err(|e| {
            DcapVerificationError::PccsCollateralParse(format!(
                "Failed to parse QE identity JSON: {e}"
            ))
        })?;

    let tcb_next_update = parse_next_update("tcb_info.nextUpdate", &tcb_info.next_update)?;
    let qe_next_update = parse_next_update("qe_identity.nextUpdate", &qe_identity.next_update)?;
    let next_update = tcb_next_update.min(qe_next_update);

    if now >= next_update {
        return Err(DcapVerificationError::PccsCollateralExpired(format!(
            "Collateral expired (tcb_next_update={}, qe_next_update={}, now={now})",
            tcb_info.next_update, qe_identity.next_update
        )));
    }

    Ok(next_update)
}

/// Parses an RFC3339 nextUpdate value into a unix timestamp
fn parse_next_update(field: &str, value: &str) -> Result<i64, DcapVerificationError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|e| {
            DcapVerificationError::PccsCollateralParse(format!(
                "Failed to parse {field} as RFC3339: {e}"
            ))
        })
        .map(|parsed| parsed.unix_timestamp())
}

/// Returns current unix time in seconds
fn unix_now() -> Result<i64, DcapVerificationError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64)
}

/// Computes how many seconds to sleep before refresh should start
fn refresh_sleep_seconds(next_update: i64, now: i64) -> u64 {
    let refresh_at = next_update - REFRESH_MARGIN_SECS;
    if refresh_at <= now {
        0
    } else {
        (refresh_at - now) as u64
    }
}

/// Inserts or updates a cache entry while preserving any active refresh task
fn upsert_cache_entry(
    cache: &mut HashMap<PccsInput, CacheEntry>,
    key: PccsInput,
    collateral: QuoteCollateralV3,
    next_update: i64,
) {
    match cache.get_mut(&key) {
        Some(existing) => {
            existing.collateral = collateral;
            existing.next_update = next_update;
        }
        None => {
            cache.insert(
                key,
                CacheEntry {
                    collateral,
                    next_update,
                    refresh_task: None,
                },
            );
        }
    }
}

/// Converts CA identifier string into the expected static literal
fn ca_as_static(ca: &str) -> Option<&'static str> {
    match ca {
        "processor" => Some("processor"),
        "platform" => Some("platform"),
        _ => None,
    }
}

/// Background loop that refreshes collateral for a single cache key
async fn refresh_loop(
    weak_cache: Weak<RwLock<HashMap<PccsInput, CacheEntry>>>,
    pccs_url: String,
    key: PccsInput,
) {
    let Some(ca_static) = ca_as_static(&key.ca) else {
        tracing::warn!(
            ca = key.ca,
            "Unsupported collateral CA value, refresh loop stopping"
        );
        return;
    };

    loop {
        let Some(cache) = weak_cache.upgrade() else {
            return;
        };
        let next_update = {
            let cache_guard = cache.read().await;
            let Some(entry) = cache_guard.get(&key) else {
                return;
            };
            entry.next_update
        };

        let now = match unix_now() {
            Ok(now) => now,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to read system time for PCCS refresh");
                sleep(Duration::from_secs(REFRESH_RETRY_SECS)).await;
                continue;
            }
        };
        let sleep_secs = refresh_sleep_seconds(next_update, now);
        sleep(Duration::from_secs(sleep_secs)).await;

        match fetch_collateral(&pccs_url, key.fmspc.clone(), ca_static).await {
            Ok(collateral) => match extract_next_update(&collateral, now) {
                Ok(new_next_update) => {
                    let Some(cache) = weak_cache.upgrade() else {
                        return;
                    };
                    let mut cache_guard = cache.write().await;
                    let Some(entry) = cache_guard.get_mut(&key) else {
                        return;
                    };
                    entry.collateral = collateral;
                    entry.next_update = new_next_update;
                    tracing::debug!(
                        fmspc = key.fmspc,
                        ca = key.ca,
                        next_update = new_next_update,
                        "Refreshed PCCS collateral in background"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        fmspc = key.fmspc,
                        ca = key.ca,
                        error = %e,
                        "Fetched PCCS collateral but nextUpdate validation failed"
                    );
                    sleep(Duration::from_secs(REFRESH_RETRY_SECS)).await;
                }
            },
            Err(e) => {
                tracing::warn!(
                    fmspc = key.fmspc,
                    ca = key.ca,
                    error = %e,
                    "Background PCCS collateral refresh failed"
                );
                sleep(Duration::from_secs(REFRESH_RETRY_SECS)).await;
            }
        }
    }
}

/// Cached collateral entry with refresh metadata
struct CacheEntry {
    collateral: QuoteCollateralV3,
    next_update: i64,
    refresh_task: Option<JoinHandle<()>>,
}

/// Minimal QE identity shape needed to read nextUpdate
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct QeIdentityNextUpdate {
    next_update: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::{
        Json, Router,
        extract::{Query, State},
        response::IntoResponse,
        routing::get,
    };
    use dcap_qvl::QuoteCollateralV3;
    use serde_json::{Value, json};
    use std::{collections::HashMap as StdHashMap, net::SocketAddr, sync::Arc};
    use tokio::{net::TcpListener, task::JoinHandle};

    #[derive(Clone)]
    struct MockPcsConfig {
        fmspc: String,
        ca: &'static str,
        tcb_next_update: String,
        qe_next_update: String,
    }

    struct MockPcsServer {
        base_url: String,
        _task: JoinHandle<()>,
    }

    impl Drop for MockPcsServer {
        fn drop(&mut self) {
            self._task.abort();
        }
    }

    #[derive(Clone)]
    struct MockPcsState {
        fmspc: String,
        ca: String,
        tcb_response: Value,
        qe_response: Value,
        pck_crl: Vec<u8>,
        pck_crl_issuer_chain: String,
        tcb_issuer_chain: String,
        qe_issuer_chain: String,
        root_ca_crl_hex: String,
    }

    async fn spawn_mock_pcs_server(config: MockPcsConfig) -> MockPcsServer {
        let base_collateral: QuoteCollateralV3 = serde_json::from_slice(include_bytes!(
            "../../test-assets/dcap-quote-collateral-00.json"
        ))
        .unwrap();

        let mut tcb_info: Value = serde_json::from_str(&base_collateral.tcb_info).unwrap();
        tcb_info["nextUpdate"] = Value::String(config.tcb_next_update.clone());

        let mut qe_identity: Value = serde_json::from_str(&base_collateral.qe_identity).unwrap();
        qe_identity["nextUpdate"] = Value::String(config.qe_next_update.clone());

        let state = Arc::new(MockPcsState {
            fmspc: config.fmspc,
            ca: config.ca.to_string(),
            tcb_response: json!({
                "tcbInfo": tcb_info,
                "signature": hex::encode(&base_collateral.tcb_info_signature),
            }),
            qe_response: json!({
                "enclaveIdentity": qe_identity,
                "signature": hex::encode(&base_collateral.qe_identity_signature),
            }),
            pck_crl: base_collateral.pck_crl,
            pck_crl_issuer_chain: "mock-pck-crl-issuer-chain".to_string(),
            tcb_issuer_chain: "mock-tcb-info-issuer-chain".to_string(),
            qe_issuer_chain: "mock-qe-issuer-chain".to_string(),
            root_ca_crl_hex: hex::encode(base_collateral.root_ca_crl),
        });

        let app = Router::new()
            .route("/sgx/certification/v4/pckcrl", get(mock_pck_crl_handler))
            .route("/tdx/certification/v4/tcb", get(mock_tcb_handler))
            .route(
                "/tdx/certification/v4/qe/identity",
                get(mock_qe_identity_handler),
            )
            .route(
                "/sgx/certification/v4/rootcacrl",
                get(mock_root_ca_crl_handler),
            )
            .with_state(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        MockPcsServer {
            base_url: format!("http://{addr}"),
            _task: task,
        }
    }

    async fn mock_pck_crl_handler(
        State(state): State<Arc<MockPcsState>>,
        Query(params): Query<StdHashMap<String, String>>,
    ) -> impl IntoResponse {
        assert_eq!(params.get("ca"), Some(&state.ca));
        assert_eq!(params.get("encoding"), Some(&"der".to_string()));
        (
            [(
                "SGX-PCK-CRL-Issuer-Chain",
                state.pck_crl_issuer_chain.clone(),
            )],
            state.pck_crl.clone(),
        )
    }

    async fn mock_tcb_handler(
        State(state): State<Arc<MockPcsState>>,
        Query(params): Query<StdHashMap<String, String>>,
    ) -> impl IntoResponse {
        assert_eq!(params.get("fmspc"), Some(&state.fmspc));
        (
            [("SGX-TCB-Info-Issuer-Chain", state.tcb_issuer_chain.clone())],
            Json(state.tcb_response.clone()),
        )
    }

    async fn mock_qe_identity_handler(
        State(state): State<Arc<MockPcsState>>,
        Query(params): Query<StdHashMap<String, String>>,
    ) -> impl IntoResponse {
        assert_eq!(params.get("update"), Some(&"standard".to_string()));
        (
            [(
                "SGX-Enclave-Identity-Issuer-Chain",
                state.qe_issuer_chain.clone(),
            )],
            Json(state.qe_response.clone()),
        )
    }

    async fn mock_root_ca_crl_handler(State(state): State<Arc<MockPcsState>>) -> impl IntoResponse {
        state.root_ca_crl_hex.clone()
    }

    #[tokio::test]
    async fn test_mock_pcs_server_helper_with_get_collateral() {
        let mock = spawn_mock_pcs_server(MockPcsConfig {
            fmspc: "00806F050000".to_string(),
            ca: "processor",
            tcb_next_update: "2999-01-01T00:00:00Z".to_string(),
            qe_next_update: "2999-01-01T00:00:00Z".to_string(),
        })
        .await;

        let pccs = Pccs::new(Some(mock.base_url.clone()));
        let now = 1_700_000_000_i64;
        let (_, is_fresh) = pccs
            .get_collateral("00806F050000".to_string(), "processor", now)
            .await
            .unwrap();
        assert!(is_fresh);
    }
}
