use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer};
use rand_core::OsRng;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{RwLock, mpsc};

use crate::attestation::{
    AttestationError, AttestationExchangeMessage, AttestationGenerator, AttestationType,
};

/// Target number of pre-generated attestations kept in memory
const POOL_CAPACITY: usize = 5;
/// Time-based rotation interval in seconds
const ROTATION_FREQUENCY_SECONDS: u64 = 60;

/// Pre-generated attestation bundle with signing key and quote payload
struct PreEmptiveAttestation {
    key: SigningKey,
    attestation: AttestationExchangeMessage,
}

impl PreEmptiveAttestation {
    /// Creates a new signing key and matching attestation payload
    async fn new(
        attestation_generator: &AttestationGenerator,
    ) -> Result<Self, PreEmptiveAttestationError> {
        // Make a keypair
        let key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&key);
        // Use uncompressed SEC1 point bytes and drop the `0x04` prefix so
        // attestation input is always the raw 64-byte `x || y`.
        let encoded_point = verifying_key.to_encoded_point(false);
        let input: [u8; 64] = encoded_point.as_bytes()[1..]
            .try_into()
            .expect("P-256 uncompressed public key must be 65 bytes");
        // Generate an attestation
        let attestation = attestation_generator.generate_attestation(input).await?;
        Ok(Self { key, attestation })
    }

    /// Signs the given message and returns the signature with cloned attestation
    fn sign(&self, message: &[u8; 64]) -> (Signature, AttestationExchangeMessage) {
        (self.key.sign(message), self.attestation.clone())
    }
}

/// Shared pre-generated attestation pool with background rotation
pub struct PreEmptiveAttestations {
    pool: Arc<RwLock<VecDeque<PreEmptiveAttestation>>>,
    rotation_tx: mpsc::UnboundedSender<()>,
}

impl PreEmptiveAttestations {
    /// Initializes the pool and starts a background rotation task
    pub async fn new(
        attestation_type: AttestationType,
        attestation_provider_url: Option<String>,
    ) -> Result<Self, PreEmptiveAttestationError> {
        let mut initial_pool = VecDeque::new();
        let attestation_generator = Arc::new(AttestationGenerator::new(
            attestation_type,
            attestation_provider_url,
        )?);

        let pre_made = PreEmptiveAttestation::new(&attestation_generator).await?;
        initial_pool.push_back(pre_made);

        let pool = Arc::new(RwLock::new(initial_pool));
        let pool_for_task = Arc::clone(&pool);
        let generator_for_task = Arc::clone(&attestation_generator);
        let (rotation_tx, mut rotation_rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            loop {
                {
                    let mut pool_guard = pool_for_task.write().await;
                    while pool_guard.len() < POOL_CAPACITY {
                        drop(pool_guard);
                        let next = match PreEmptiveAttestation::new(&generator_for_task).await {
                            Ok(next) => next,
                            Err(err) => {
                                tracing::warn!("Failed to pre-fill preemptive pool: {err}");
                                tokio::time::sleep(Duration::from_secs(1)).await;
                                pool_guard = pool_for_task.write().await;
                                continue;
                            }
                        };
                        pool_guard = pool_for_task.write().await;
                        pool_guard.push_back(next);
                    }
                }

                let sleep = tokio::time::sleep(Duration::from_secs(ROTATION_FREQUENCY_SECONDS));
                tokio::pin!(sleep);

                tokio::select! {
                    _ = &mut sleep => {}
                    maybe_rotate = rotation_rx.recv() => {
                        if maybe_rotate.is_none() {
                            break;
                        }
                    }
                }

                let next = match PreEmptiveAttestation::new(&generator_for_task).await {
                    Ok(next) => next,
                    Err(err) => {
                        tracing::warn!("Failed to rotate preemptive attestation: {err}");
                        continue;
                    }
                };
                let mut pool_guard = pool_for_task.write().await;
                pool_guard.push_back(next);
                while pool_guard.len() > POOL_CAPACITY {
                    pool_guard.pop_front();
                }
            }
        });

        Ok(Self { pool, rotation_tx })
    }

    /// Returns a signature and attestation from the pool and requests fast rotation
    pub async fn get_attestation(
        &self,
        input: &[u8; 64],
    ) -> Result<(Signature, AttestationExchangeMessage), PreEmptiveAttestationError> {
        // Pop when we can still leave `POOL_CAPACITY - 1` entries, otherwise reuse front.
        let signed = {
            let mut pool_guard = self.pool.write().await;
            if pool_guard.len() > (POOL_CAPACITY - 1) {
                pool_guard
                    .pop_front()
                    .ok_or(PreEmptiveAttestationError::EmptyPool)?
                    .sign(input)
            } else {
                pool_guard
                    .front()
                    .ok_or(PreEmptiveAttestationError::EmptyPool)?
                    .sign(input)
            }
        };

        // Request an immediate background rotation in addition to time-based rotation.
        self.rotation_tx
            .send(())
            .map_err(|_| PreEmptiveAttestationError::RotationChannelClosed)?;

        Ok(signed)
    }
}

/// Errors for preemptive attestation pool initialization and use
#[derive(Debug, Error)]
pub enum PreEmptiveAttestationError {
    #[error("Attestation operation failed: {0}")]
    Attestation(#[from] AttestationError),
    #[error("Preemptive attestation pool is empty")]
    EmptyPool,
    #[error("Preemptive rotation channel is closed")]
    RotationChannelClosed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::AttestationVerifier;
    use p256::ecdsa::signature::Verifier;
    use std::error::Error;
    use tokio::time::{Duration, sleep};

    #[tokio::test]
    async fn preemptive_get_attestation_works_with_mock_dcap() -> Result<(), Box<dyn Error>> {
        let preemptive = PreEmptiveAttestations::new(AttestationType::DcapTdx, None).await?;
        for _ in 0..100 {
            if preemptive.pool.read().await.len() == POOL_CAPACITY {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(preemptive.pool.read().await.len(), POOL_CAPACITY);

        let message = [42u8; 64];
        let second_message = [7u8; 64];

        let (signature, attestation) = preemptive.get_attestation(&message).await?;
        let (second_signature, second_attestation) =
            preemptive.get_attestation(&second_message).await?;
        assert_eq!(attestation.attestation_type, AttestationType::DcapTdx);
        assert_eq!(
            second_attestation.attestation_type,
            AttestationType::DcapTdx
        );

        // In test mode DCAP quotes are mocked; extract report input data and use it as
        // the expected input for verification.
        let quote = tdx_quote::Quote::from_bytes(&attestation.attestation)?;
        let quote_input = quote.report_input_data();
        let second_quote = tdx_quote::Quote::from_bytes(&second_attestation.attestation)?;
        let second_quote_input = second_quote.report_input_data();

        // Consecutive calls should use distinct pre-generated keypairs when pool is at capacity.
        assert_ne!(quote_input, second_quote_input);

        // The quote input is the preemptive public key encoded as raw `x || y`.
        let mut sec1_uncompressed = [0u8; 65];
        sec1_uncompressed[0] = 0x04;
        sec1_uncompressed[1..].copy_from_slice(&quote_input);
        let verifying_key = VerifyingKey::from_sec1_bytes(&sec1_uncompressed)?;
        verifying_key.verify(&message, &signature)?;
        sec1_uncompressed[1..].copy_from_slice(&second_quote_input);
        let second_verifying_key = VerifyingKey::from_sec1_bytes(&sec1_uncompressed)?;
        second_verifying_key.verify(&second_message, &second_signature)?;

        let verified = AttestationVerifier::mock()
            .verify_attestation(attestation, quote_input)
            .await?;
        assert!(verified.is_some());
        let second_verified = AttestationVerifier::mock()
            .verify_attestation(second_attestation, second_quote_input)
            .await?;
        assert!(second_verified.is_some());
        Ok(())
    }
}
