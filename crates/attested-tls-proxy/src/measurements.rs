//! The proxy's measurement header format: register indices mapped to hex values.
use attested_tls::attestation::measurements::{MeasurementFormatError, MultiMeasurements};
use http::HeaderValue;
use std::collections::HashMap;

/// Preserves the proxy's wire format independently of upstream policy formats.
pub trait MeasurementHeaders {
    fn to_header_format(&self) -> Result<HeaderValue, MeasurementFormatError>;

    #[cfg(test)]
    fn from_header_format(
        input: &str,
        attestation_type: attested_tls::attestation::AttestationType,
    ) -> Result<MultiMeasurements, MeasurementFormatError>;
}

impl MeasurementHeaders for MultiMeasurements {
    fn to_header_format(&self) -> Result<HeaderValue, MeasurementFormatError> {
        let values: HashMap<String, String> = match self {
            Self::Dcap(m) => [&m.mrtd, &m.rtmr0, &m.rtmr1, &m.rtmr2, &m.rtmr3]
                .into_iter()
                .enumerate()
                .map(|(index, value)| (index.to_string(), hex::encode(value)))
                .collect(),
            Self::Azure(m) => m
                .iter()
                .map(|(index, value)| (index.to_string(), hex::encode(value)))
                .collect(),
            Self::NoAttestation => HashMap::new(),
        };
        Ok(HeaderValue::from_str(&serde_json::to_string(&values)?)?)
    }

    #[cfg(test)]
    fn from_header_format(
        input: &str,
        attestation_type: attested_tls::attestation::AttestationType,
    ) -> Result<Self, MeasurementFormatError> {
        use attested_tls::attestation::{AttestationType, measurements::DcapMeasurements};

        fn decode<const N: usize>(value: &str) -> Result<[u8; N], MeasurementFormatError> {
            hex::decode(value).map_err(Into::into).and_then(|bytes| {
                bytes
                    .try_into()
                    .map_err(|_| MeasurementFormatError::BadLength)
            })
        }

        let values: HashMap<u8, String> = serde_json::from_str(input)?;
        Ok(match attestation_type {
            AttestationType::None => Self::NoAttestation,
            AttestationType::AzureTdx => Self::Azure(
                values
                    .into_iter()
                    .map(|(k, v)| Ok((u32::from(k), decode(&v)?)))
                    .collect::<Result<_, MeasurementFormatError>>()?,
            ),
            AttestationType::DcapTdx | AttestationType::GcpTdx => {
                if values.len() != 5 || values.keys().any(|k| *k > 4) {
                    return Err(MeasurementFormatError::BadRegisterIndex);
                }
                Self::Dcap(DcapMeasurements::new(
                    decode(&values[&0])?,
                    decode(&values[&1])?,
                    decode(&values[&2])?,
                    decode(&values[&3])?,
                    decode(&values[&4])?,
                ))
            }
        })
    }
}
