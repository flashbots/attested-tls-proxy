//! Experimental, process-local attestation-aware TLS session stores.
//!
//! Tickets are issued before attestation finishes. Each entry therefore references
//! a connection record that is promoted only after authentication succeeds.
//! These POC caches deliberately have no capacity or attestation-age limit.

#[cfg(test)]
mod tests;

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
};

use crate::AttestedTlsError;
use attestation::{AttestationType, measurements::MultiMeasurements};
use tokio_rustls::rustls::{
    NamedGroup,
    client::{ClientSessionStore, Tls12ClientSessionValue, Tls13ClientSessionValue},
    pki_types::ServerName,
    server::StoresServerSessions,
};

/// Peer attestation results retained for authenticated TLS resumption.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedPeer {
    pub measurements: Option<MultiMeasurements>,
    pub attestation_type: AttestationType,
}

/// Shared verification state; `None` means tickets are not yet eligible for reuse.
type Authentication = Arc<Mutex<Option<VerifiedPeer>>>;

/// Tracks authentication for tickets issued by and selected for one connection.
#[derive(Clone, Debug, Default)]
pub(crate) struct ConnectionRecord {
    issued: Authentication,
    selected: Authentication,
}

impl ConnectionRecord {
    /// Returns the verified peer metadata associated with the selected ticket.
    pub fn verified_peer(&self) -> Result<Option<VerifiedPeer>, AttestedTlsError> {
        Ok(self
            .selected
            .lock()
            .map_err(|_| AttestedTlsError::PoisonedResumptionState)?
            .clone())
    }

    /// Authorizes this connection's existing and future tickets using verified peer metadata.
    pub fn authenticate(&self, peer: VerifiedPeer) -> Result<(), AttestedTlsError> {
        *self
            .issued
            .lock()
            .map_err(|_| AttestedTlsError::PoisonedResumptionState)? = Some(peer);
        Ok(())
    }
}

/// Pairs opaque TLS session state with its originating connection's authentication state.
struct Ticket<T> {
    value: T,
    authentication: Authentication,
}

/// Holds client tickets across connections, partitioned by the complete target string.
#[derive(Default)]
pub(crate) struct ClientCache {
    // Scope by the caller's complete target (including port), not just SNI.
    tickets: Mutex<HashMap<String, Vec<Ticket<Tls13ClientSessionValue>>>>,
}

impl fmt::Debug for ClientCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCache").finish_non_exhaustive()
    }
}

/// Adapts the shared client cache to one connection's ticket callbacks.
#[derive(Debug)]
pub(crate) struct ClientStore {
    pub cache: Arc<ClientCache>,
    pub target: String,
    pub record: ConnectionRecord,
}

impl ClientSessionStore for ClientStore {
    fn set_kx_hint(&self, _: ServerName<'static>, _: NamedGroup) {}
    fn kx_hint(&self, _: &ServerName<'_>) -> Option<NamedGroup> {
        None
    }
    fn set_tls12_session(&self, _: ServerName<'static>, _: Tls12ClientSessionValue) {}
    fn tls12_session(&self, _: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        None
    }
    fn remove_tls12_session(&self, _: &ServerName<'static>) {}

    /// Associates an arriving ticket with this connection's authentication state.
    fn insert_tls13_ticket(&self, _: ServerName<'static>, value: Tls13ClientSessionValue) {
        let Ok(mut cache) = self.cache.tickets.lock() else {
            return;
        };
        cache.entry(self.target.clone()).or_default().push(Ticket {
            value,
            authentication: self.record.issued.clone(),
        });
    }

    /// Consumes an authenticated ticket and records its peer metadata for this connection.
    fn take_tls13_ticket(&self, _: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        let mut cache = self.cache.tickets.lock().ok()?;
        let tickets = cache.get_mut(&self.target)?;
        let (index, peer) = tickets
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, ticket)| {
                Some((index, ticket.authentication.lock().ok()?.clone()?))
            })?;
        let mut selected = self.record.selected.lock().ok()?;
        let ticket = tickets.remove(index);
        *selected = Some(peer);
        Some(ticket.value)
    }
}

/// Holds server session state and authentication records indexed by ticket identity.
#[derive(Default)]
pub(crate) struct ServerCache {
    tickets: Mutex<HashMap<Vec<u8>, Ticket<Vec<u8>>>>,
    #[cfg(test)]
    rejected_tickets: std::sync::atomic::AtomicUsize,
}

impl fmt::Debug for ServerCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerCache").finish_non_exhaustive()
    }
}

/// Adapts the shared server cache to one connection's ticket callbacks.
#[derive(Debug)]
pub(crate) struct ServerStore {
    pub cache: Arc<ServerCache>,
    pub record: ConnectionRecord,
}

impl StoresServerSessions for ServerStore {
    /// Associates newly issued session state with this connection's authentication state.
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        let Ok(mut cache) = self.cache.tickets.lock() else {
            return false;
        };
        cache.insert(
            key,
            Ticket {
                value,
                authentication: self.record.issued.clone(),
            },
        );
        true
    }

    /// Disables non-consuming lookups; TLS 1.3 resumption uses `take` instead.
    fn get(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }

    /// Consumes authenticated session state and records its peer metadata, rejecting pending tickets.
    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        let mut cache = self.cache.tickets.lock().ok()?;
        let peer = cache.get(key)?.authentication.lock().ok()?.clone();
        let Some(peer) = peer else {
            #[cfg(test)]
            self.cache
                .rejected_tickets
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        };
        let mut selected = self.record.selected.lock().ok()?;
        let ticket = cache.remove(key)?;
        *selected = Some(peer);
        Some(ticket.value)
    }

    fn can_cache(&self) -> bool {
        !self.cache.tickets.is_poisoned()
    }
}

/// Counts calls to attestation generation and verification across cloned endpoints.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct AttestationCounts {
    pub generated: std::sync::atomic::AtomicUsize,
    pub verified: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl ClientCache {
    pub fn clear(&self) {
        self.tickets.lock().unwrap().clear();
    }
    pub fn pending_count(&self) -> usize {
        self.tickets
            .lock()
            .unwrap()
            .values()
            .flatten()
            .filter(|ticket| ticket.authentication.lock().unwrap().is_none())
            .count()
    }
}

#[cfg(test)]
impl ServerCache {
    /// Returns how many offered tickets were rejected because authentication was still pending.
    pub fn rejected_count(&self) -> usize {
        self.rejected_tickets
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn clear(&self) {
        self.tickets.lock().unwrap().clear();
    }
    pub fn pending_count(&self) -> usize {
        self.tickets
            .lock()
            .unwrap()
            .values()
            .filter(|ticket| ticket.authentication.lock().unwrap().is_none())
            .count()
    }
}
