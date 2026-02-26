use std::{collections::HashMap, sync::Arc};

use dcap_qvl::{QuoteCollateralV3, collateral::get_collateral_for_fmspc};
use tokio::sync::RwLock;

use crate::attestation::dcap::{DcapVerificationError, PCS_URL};

#[derive(Clone, Debug)]
pub struct Pccs {
    pccs_url: String,
    cache: Arc<RwLock<HashMap<PccsInput, QuoteCollateralV3>>>,
}

impl Pccs {
    pub fn new(pccs_url: Option<String>) -> Self {
        Self {
            pccs_url: pccs_url.unwrap_or(PCS_URL.to_string()),
            cache: RwLock::new(HashMap::new()).into(),
        }
    }

    pub async fn get_collateral(
        &self,
        fmspc: String,
        ca: &'static str,
    ) -> Result<(QuoteCollateralV3, bool), DcapVerificationError> {
        let cache_key = PccsInput::new(fmspc.clone(), ca);
        if let Some(collateral) = self.cache.read().await.get(&cache_key).cloned() {
            return Ok((collateral, false));
        }

        let collateral = get_collateral_for_fmspc(
            &self.pccs_url,
            fmspc,
            ca,
            false, // Indicates not SGX
        )
        .await?;

        let mut cache = self.cache.write().await;
        let cached = cache
            .entry(cache_key)
            .or_insert_with(|| collateral.clone())
            .clone();
        Ok((cached, true))
    }

    pub async fn refresh_collateral(
        &self,
        fmspc: String,
        ca: &'static str,
    ) -> Result<QuoteCollateralV3, DcapVerificationError> {
        let collateral = get_collateral_for_fmspc(
            &self.pccs_url,
            fmspc.clone(),
            ca,
            false, // Indicates not SGX
        )
        .await?;

        self.cache
            .write()
            .await
            .insert(PccsInput::new(fmspc, ca), collateral.clone());
        Ok(collateral)
    }
}

#[derive(Debug, Hash, PartialEq, Eq)]
struct PccsInput {
    fmspc: String,
    ca: String,
}

impl PccsInput {
    fn new(fmspc: String, ca: &'static str) -> Self {
        Self {
            fmspc,
            ca: ca.to_string(),
        }
    }
}
