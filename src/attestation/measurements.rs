//! Measurements and policy for enforcing them when validating a remote attestation
use crate::attestation::{dcap::DcapVerificationError, AttestationError, AttestationType};
use std::{collections::HashMap, path::PathBuf};

use dcap_qvl::quote::Report;
use http::{header::InvalidHeaderValue, HeaderValue};
use serde::Deserialize;
use thiserror::Error;

/// Represents the measurement register types in a TDX quote
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DcapMeasurementRegister {
    MRTD,
    RTMR0,
    RTMR1,
    RTMR2,
    RTMR3,
}

impl TryFrom<u8> for DcapMeasurementRegister {
    type Error = MeasurementFormatError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::MRTD),
            1 => Ok(Self::RTMR0),
            2 => Ok(Self::RTMR1),
            3 => Ok(Self::RTMR2),
            4 => Ok(Self::RTMR3),
            _ => Err(MeasurementFormatError::BadRegisterIndex),
        }
    }
}

/// Represents a set of measurements values for one of the supported CVM platforms
#[derive(Debug, Clone, PartialEq)]
pub enum MultiMeasurements {
    Dcap(HashMap<DcapMeasurementRegister, [u8; 48]>),
    Azure(HashMap<u32, [u8; 32]>),
    NoAttestation,
}

impl MultiMeasurements {
    /// Convert to the JSON format used in HTTP headers
    pub fn to_header_format(&self) -> Result<HeaderValue, MeasurementFormatError> {
        let measurements_map = match self {
            MultiMeasurements::Dcap(dcap_measurements) => dcap_measurements
                .iter()
                .map(|(register, value)| ((register.clone() as u8).to_string(), hex::encode(value)))
                .collect(),
            MultiMeasurements::Azure(azure_measurements) => azure_measurements
                .iter()
                .map(|(index, value)| (index.to_string(), hex::encode(value)))
                .collect(),
            MultiMeasurements::NoAttestation => HashMap::new(),
        };

        Ok(HeaderValue::from_str(&serde_json::to_string(
            &measurements_map,
        )?)?)
    }

    /// Parse the JSON used in HTTP headers
    pub fn from_header_format(
        input: &str,
        attestation_type: AttestationType,
    ) -> Result<Self, MeasurementFormatError> {
        let measurements_map: HashMap<u8, String> = serde_json::from_str(input)?;

        Ok(match attestation_type {
            AttestationType::AzureTdx => Self::Azure(
                measurements_map
                    .into_iter()
                    .map(|(k, v)| {
                        Ok((
                            k as u32,
                            hex::decode(v)?
                                .try_into()
                                .map_err(|_| MeasurementFormatError::BadLength)?,
                        ))
                    })
                    .collect::<Result<_, MeasurementFormatError>>()?,
            ),
            AttestationType::None => Self::NoAttestation,
            _ => {
                let measurements_map = measurements_map
                    .into_iter()
                    .map(|(k, v)| {
                        Ok((
                            k.try_into()?,
                            hex::decode(v)?
                                .try_into()
                                .map_err(|_| MeasurementFormatError::BadLength)?,
                        ))
                    })
                    .collect::<Result<_, MeasurementFormatError>>()?;
                Self::Dcap(measurements_map)
            }
        })
    }

    /// Given a quote from the dcap_qvl library, extract the measurements
    pub fn from_dcap_qvl_quote(
        quote: &dcap_qvl::quote::Quote,
    ) -> Result<Self, DcapVerificationError> {
        let report = match quote.report {
            Report::TD10(report) => report,
            Report::TD15(report) => report.base,
            Report::SgxEnclave(_) => {
                return Err(DcapVerificationError::SgxNotSupported);
            }
        };
        Ok(Self::Dcap(HashMap::from([
            (DcapMeasurementRegister::MRTD, report.mr_td),
            (DcapMeasurementRegister::RTMR0, report.rt_mr0),
            (DcapMeasurementRegister::RTMR1, report.rt_mr1),
            (DcapMeasurementRegister::RTMR2, report.rt_mr2),
            (DcapMeasurementRegister::RTMR3, report.rt_mr3),
        ])))
    }

    #[cfg(test)]
    pub fn from_tdx_quote(quote: &tdx_quote::Quote) -> Self {
        Self::Dcap(HashMap::from([
            (DcapMeasurementRegister::MRTD, quote.mrtd()),
            (DcapMeasurementRegister::RTMR0, quote.rtmr0()),
            (DcapMeasurementRegister::RTMR1, quote.rtmr1()),
            (DcapMeasurementRegister::RTMR2, quote.rtmr2()),
            (DcapMeasurementRegister::RTMR3, quote.rtmr3()),
        ]))
    }

    pub fn from_pcrs<'a>(pcrs: impl Iterator<Item = &'a [u8; 32]>) -> Self {
        Self::Azure(
            pcrs.copied()
                .enumerate()
                .map(|(index, value)| (index as u32, value))
                .collect(),
        )
    }
}

/// An error when converting measurements / to or from HTTP header format
#[derive(Error, Debug)]
pub enum MeasurementFormatError {
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Missing value: {0}")]
    MissingValue(String),
    #[error("Invalid header value: {0}")]
    BadHeaderValue(#[from] InvalidHeaderValue),
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("Attestation type not valid")]
    AttestationTypeNotValid,
    #[error("Hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Expected 48 byte value")]
    BadLength,
    #[error("TDX quote register index must be in the ranger 0-3")]
    BadRegisterIndex,
    #[error("ParseInt: {0}")]
    ParseInt(#[from] std::num::ParseIntError),
    #[error("Failed to read measurements from URL: {0}")]
    Reqwest(#[from] reqwest::Error),
}

/// Represents a set of acceptable measurement values for policy enforcement
///
/// Unlike `MultiMeasurements` which stores single values (for actual quote measurements),
/// this stores multiple acceptable values per register with OR semantics - any matching value
/// is accepted.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyMeasurements {
    Dcap(HashMap<DcapMeasurementRegister, Vec<[u8; 48]>>),
    Azure(HashMap<u32, Vec<[u8; 32]>>),
    NoAttestation,
}

/// An accepted measurement value given in the measurements file
#[derive(Clone, Debug, PartialEq)]
pub struct MeasurementRecord {
    /// An identifier, for example the name and version of the corresponding OS image
    pub measurement_id: String,
    /// The expected measurement register values (supports multiple acceptable values per register)
    pub measurements: PolicyMeasurements,
}

impl MeasurementRecord {
    pub fn allow_no_attestation() -> Self {
        Self {
            measurement_id: "Allow no attestation".to_string(),
            measurements: PolicyMeasurements::NoAttestation,
        }
    }

    pub fn allow_any_measurement(attestation_type: AttestationType) -> Self {
        Self {
            measurement_id: format!("Any measurement for {attestation_type}"),
            measurements: match attestation_type {
                AttestationType::None => PolicyMeasurements::NoAttestation,
                AttestationType::AzureTdx => PolicyMeasurements::Azure(HashMap::new()),
                _ => PolicyMeasurements::Dcap(HashMap::new()),
            },
        }
    }
}

/// Represents the measurement policy
///
/// This is a set of acceptable attestation types (CVM platforms) which may or may not enforce
/// acceptable measurement values for each attestation type
#[derive(Clone, Debug)]
pub struct MeasurementPolicy {
    /// A map of accepted attestation types to accepted measurement values
    /// A value of None means accept any measurement value for this measurement type
    pub(crate) accepted_measurements: Vec<MeasurementRecord>,
}

impl MeasurementPolicy {
    /// This will only allow no attestation - and will reject it if one is given
    pub fn expect_none() -> Self {
        Self {
            accepted_measurements: vec![MeasurementRecord::allow_no_attestation()],
        }
    }

    /// Allow any measurements with the given attestation type
    pub fn single_attestation_type(attestation_type: AttestationType) -> Self {
        Self {
            accepted_measurements: vec![MeasurementRecord::allow_any_measurement(attestation_type)],
        }
    }

    /// Accept any attestation type with any measurements
    pub fn accept_anything() -> Self {
        Self {
            accepted_measurements: vec![
                MeasurementRecord::allow_no_attestation(),
                MeasurementRecord::allow_any_measurement(AttestationType::Dummy),
                MeasurementRecord::allow_any_measurement(AttestationType::DcapTdx),
                MeasurementRecord::allow_any_measurement(AttestationType::QemuTdx),
                MeasurementRecord::allow_any_measurement(AttestationType::GcpTdx),
                MeasurementRecord::allow_any_measurement(AttestationType::AzureTdx),
            ],
        }
    }

    /// Expect mock measurements used in tests
    #[cfg(test)]
    pub fn mock() -> Self {
        Self {
            accepted_measurements: vec![MeasurementRecord {
                measurement_id: "test".to_string(),
                measurements: PolicyMeasurements::Dcap(HashMap::from([
                    (DcapMeasurementRegister::MRTD, vec![[0; 48]]),
                    (DcapMeasurementRegister::RTMR0, vec![[0; 48]]),
                    (DcapMeasurementRegister::RTMR1, vec![[0; 48]]),
                    (DcapMeasurementRegister::RTMR2, vec![[0; 48]]),
                    (DcapMeasurementRegister::RTMR3, vec![[0; 48]]),
                ])),
            }],
        }
    }

    /// Given an attestation type and set of measurements, check whether they are acceptable
    pub fn check_measurement(
        &self,
        measurements: &MultiMeasurements,
    ) -> Result<(), AttestationError> {
        if self
            .accepted_measurements
            .iter()
            .any(|measurement_record| match measurements {
                MultiMeasurements::Dcap(dcap_measurements) => {
                    if let PolicyMeasurements::Dcap(d) = &measurement_record.measurements {
                        // All measurements in our policy must be given and must match at least one expected value
                        for (k, acceptable_values) in d.iter() {
                            match dcap_measurements.get(k) {
                                // Check if actual value matches ANY of the acceptable values (OR semantics)
                                Some(actual_value)
                                    if acceptable_values.iter().any(|v| actual_value == v) => {}
                                _ => return false,
                            }
                        }
                        return true;
                    }
                    false
                }
                MultiMeasurements::Azure(azure_measurements) => {
                    if let PolicyMeasurements::Azure(a) = &measurement_record.measurements {
                        for (k, acceptable_values) in a.iter() {
                            match azure_measurements.get(k) {
                                // Check if actual value matches ANY of the acceptable values (OR semantics)
                                Some(actual_value)
                                    if acceptable_values.iter().any(|v| actual_value == v) => {}
                                _ => return false,
                            }
                        }
                        return true;
                    }
                    false
                }
                MultiMeasurements::NoAttestation => {
                    matches!(
                        measurement_record.measurements,
                        PolicyMeasurements::NoAttestation
                    )
                }
            })
        {
            Ok(())
        } else {
            Err(AttestationError::MeasurementsNotAccepted)
        }
    }

    /// Whether or not we require attestation
    pub fn has_remote_attestion(&self) -> bool {
        !self
            .accepted_measurements
            .iter()
            .any(|a| a.measurements == PolicyMeasurements::NoAttestation)
    }

    /// Given either a URL or the path to a file, parse the measurement policy from JSON
    pub async fn from_file_or_url(file_or_url: String) -> Result<Self, MeasurementFormatError> {
        if file_or_url.starts_with("https://") || file_or_url.starts_with("http://") {
            let measurements_json = reqwest::get(file_or_url).await?.bytes().await?;
            Self::from_json_bytes(measurements_json.to_vec()).await
        } else {
            Self::from_file(file_or_url.into()).await
        }
    }

    /// Given the path to a JSON file containing measurements, return a [MeasurementPolicy]
    pub async fn from_file(measurement_file: PathBuf) -> Result<Self, MeasurementFormatError> {
        let measurements_json = tokio::fs::read(measurement_file).await?;
        Self::from_json_bytes(measurements_json).await
    }

    /// Parse from JSON
    pub async fn from_json_bytes(json_bytes: Vec<u8>) -> Result<Self, MeasurementFormatError> {
        #[derive(Debug, Deserialize)]
        struct MeasurementRecordSimple {
            measurement_id: Option<String>,
            attestation_type: String,
            measurements: Option<HashMap<String, MeasurementEntry>>,
        }

        /// Represents the `expected` field which can be either a single string or a list of strings
        #[derive(Debug, Deserialize)]
        #[serde(untagged)]
        enum ExpectedValue {
            Single(String),
            Multiple(Vec<String>),
        }

        impl ExpectedValue {
            fn into_vec(self) -> Vec<String> {
                match self {
                    ExpectedValue::Single(s) => vec![s],
                    ExpectedValue::Multiple(v) => v,
                }
            }
        }

        #[derive(Debug, Deserialize)]
        struct MeasurementEntry {
            expected: ExpectedValue,
        }

        let measurements_simple: Vec<MeasurementRecordSimple> =
            serde_json::from_slice(&json_bytes)?;

        let mut measurement_policy = Vec::new();

        for measurement in measurements_simple {
            let attestation_type =
                serde_json::from_value(serde_json::Value::String(measurement.attestation_type))?;

            if let Some(measurements) = measurement.measurements {
                let policy_measurement = match attestation_type {
                    AttestationType::AzureTdx => {
                        let azure_measurements = measurements
                            .into_iter()
                            .map(|(index, entry)| {
                                let index = index.parse()?;

                                if index > 23 {
                                    return Err(MeasurementFormatError::BadRegisterIndex);
                                }

                                let values = entry
                                    .expected
                                    .into_vec()
                                    .into_iter()
                                    .map(|hex_str| {
                                        hex::decode(hex_str)?
                                            .try_into()
                                            .map_err(|_| MeasurementFormatError::BadLength)
                                    })
                                    .collect::<Result<Vec<[u8; 32]>, MeasurementFormatError>>()?;

                                Ok((index, values))
                            })
                            .collect::<Result<HashMap<u32, Vec<[u8; 32]>>, MeasurementFormatError>>(
                            )?;
                        PolicyMeasurements::Azure(azure_measurements)
                    }
                    AttestationType::None => PolicyMeasurements::NoAttestation,
                    _ => PolicyMeasurements::Dcap(
                        measurements
                            .into_iter()
                            .map(|(index, entry)| {
                                let index: u8 = index.parse()?;

                                let values = entry
                                    .expected
                                    .into_vec()
                                    .into_iter()
                                    .map(|hex_str| {
                                        hex::decode(hex_str)?
                                            .try_into()
                                            .map_err(|_| MeasurementFormatError::BadLength)
                                    })
                                    .collect::<Result<Vec<[u8; 48]>, MeasurementFormatError>>()?;

                                Ok((DcapMeasurementRegister::try_from(index)?, values))
                            })
                            .collect::<Result<
                                HashMap<DcapMeasurementRegister, Vec<[u8; 48]>>,
                                MeasurementFormatError,
                            >>()?,
                    ),
                };

                measurement_policy.push(MeasurementRecord {
                    measurement_id: measurement.measurement_id.unwrap_or_default(),
                    measurements: policy_measurement,
                });
            } else {
                measurement_policy.push(MeasurementRecord::allow_any_measurement(attestation_type));
            };
        }

        Ok(MeasurementPolicy {
            accepted_measurements: measurement_policy,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::test_helpers::mock_dcap_measurements;

    use super::*;

    #[tokio::test]
    async fn test_read_measurements_file() {
        let specific_measurements =
            MeasurementPolicy::from_file("test-assets/measurements.json".into())
                .await
                .unwrap();

        assert_eq!(specific_measurements.accepted_measurements.len(), 3);

        let m = &specific_measurements.accepted_measurements[0];
        if let PolicyMeasurements::Azure(a) = &m.measurements {
            assert_eq!(
                a.keys().collect::<HashSet<_>>(),
                HashSet::from([&9, &4, &11])
            );
        } else {
            panic!("Unexpected measurement type");
        }

        let m = &specific_measurements.accepted_measurements[1];
        if let PolicyMeasurements::Azure(a) = &m.measurements {
            assert_eq!(a.keys().collect::<HashSet<_>>(), HashSet::from([&9, &4]));
        } else {
            panic!("Unexpected measurement type");
        }

        let m = &specific_measurements.accepted_measurements[2];
        if let PolicyMeasurements::Dcap(d) = &m.measurements {
            assert!(d.contains_key(&DcapMeasurementRegister::MRTD));
            assert!(d.contains_key(&DcapMeasurementRegister::RTMR0));
            assert!(d.contains_key(&DcapMeasurementRegister::RTMR1));
            assert!(d.contains_key(&DcapMeasurementRegister::RTMR2));
            assert!(d.contains_key(&DcapMeasurementRegister::RTMR3));
        } else {
            panic!("Unexpected measurement type");
        }

        // Will not match mock measurements
        assert!(matches!(
            specific_measurements
                .check_measurement(&mock_dcap_measurements())
                .unwrap_err(),
            AttestationError::MeasurementsNotAccepted
        ));

        // Will not match another attestation type
        assert!(matches!(
            specific_measurements
                .check_measurement(&MultiMeasurements::NoAttestation)
                .unwrap_err(),
            AttestationError::MeasurementsNotAccepted
        ));

        // A non-specific measurement fails
        assert!(matches!(
            specific_measurements
                .check_measurement(&MultiMeasurements::Azure(HashMap::new()))
                .unwrap_err(),
            AttestationError::MeasurementsNotAccepted
        ));
    }

    #[tokio::test]
    async fn test_read_measurements_file_non_specific() {
        // This specifies a particular attestation type, but not specific measurements
        let allowed_attestation_type =
            MeasurementPolicy::from_file("test-assets/measurements_2.json".into())
                .await
                .unwrap();

        allowed_attestation_type
            .check_measurement(&mock_dcap_measurements())
            .unwrap();

        // Will not match another attestation type
        assert!(matches!(
            allowed_attestation_type
                .check_measurement(&MultiMeasurements::NoAttestation)
                .unwrap_err(),
            AttestationError::MeasurementsNotAccepted
        ));
    }

    #[tokio::test]
    async fn test_read_remote_buildernet_measurements() {
        // Check that the buildernet measurements are available and parse correctly
        let policy = MeasurementPolicy::from_file_or_url(
            "https://measurements.builder.flashbots.net".to_string(),
        )
        .await
        .unwrap();

        assert!(!policy.accepted_measurements.is_empty());

        assert!(matches!(
            policy
                .check_measurement(&MultiMeasurements::NoAttestation)
                .unwrap_err(),
            AttestationError::MeasurementsNotAccepted
        ));

        // A non-specific measurement fails
        assert!(matches!(
            policy
                .check_measurement(&MultiMeasurements::Azure(HashMap::new()))
                .unwrap_err(),
            AttestationError::MeasurementsNotAccepted
        ));
    }

    #[tokio::test]
    async fn test_expected_list_values_or_semantics() {
        // Test that list of expected values works with OR semantics
        let json = r#"[
            {
                "measurement_id": "dcap-list-test",
                "attestation_type": "dcap-tdx",
                "measurements": {
                    "0": {
                        "expected": [
                            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                            "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
                        ]
                    },
                    "1": {
                        "expected": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                    }
                }
            }
        ]"#;

        let policy = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec())
            .await
            .unwrap();

        // Should match the first expected value for register 0
        let measurements_first = MultiMeasurements::Dcap(HashMap::from([
            (DcapMeasurementRegister::MRTD, [0; 48]),
            (DcapMeasurementRegister::RTMR0, [0; 48]),
        ]));
        policy.check_measurement(&measurements_first).unwrap();

        // Should match the second expected value for register 0
        let measurements_second = MultiMeasurements::Dcap(HashMap::from([
            (DcapMeasurementRegister::MRTD, [0x11; 48]),
            (DcapMeasurementRegister::RTMR0, [0; 48]),
        ]));
        policy.check_measurement(&measurements_second).unwrap();

        // Should fail when neither expected value matches
        let measurements_neither = MultiMeasurements::Dcap(HashMap::from([
            (DcapMeasurementRegister::MRTD, [0x22; 48]),
            (DcapMeasurementRegister::RTMR0, [0; 48]),
        ]));
        assert!(matches!(
            policy
                .check_measurement(&measurements_neither)
                .unwrap_err(),
            AttestationError::MeasurementsNotAccepted
        ));
    }

    #[tokio::test]
    async fn test_expected_list_values_azure() {
        // Test that list of expected values works for Azure measurements
        let json = r#"[
            {
                "measurement_id": "azure-list-test",
                "attestation_type": "azure-tdx",
                "measurements": {
                    "4": {
                        "expected": [
                            "0000000000000000000000000000000000000000000000000000000000000000",
                            "1111111111111111111111111111111111111111111111111111111111111111"
                        ]
                    }
                }
            }
        ]"#;

        let policy = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec())
            .await
            .unwrap();

        // Should match the first expected value
        let measurements_first = MultiMeasurements::Azure(HashMap::from([(4, [0; 32])]));
        policy.check_measurement(&measurements_first).unwrap();

        // Should match the second expected value
        let measurements_second = MultiMeasurements::Azure(HashMap::from([(4, [0x11; 32])]));
        policy.check_measurement(&measurements_second).unwrap();

        // Should fail when neither expected value matches
        let measurements_neither = MultiMeasurements::Azure(HashMap::from([(4, [0x22; 32])]));
        assert!(matches!(
            policy
                .check_measurement(&measurements_neither)
                .unwrap_err(),
            AttestationError::MeasurementsNotAccepted
        ));
    }

    #[tokio::test]
    async fn test_backwards_compatibility_single_string() {
        // Test that single string values still work (backwards compatibility)
        let json = r#"[
            {
                "measurement_id": "single-value-test",
                "attestation_type": "dcap-tdx",
                "measurements": {
                    "0": {
                        "expected": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                    }
                }
            }
        ]"#;

        let policy = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec())
            .await
            .unwrap();

        let measurements = MultiMeasurements::Dcap(HashMap::from([(
            DcapMeasurementRegister::MRTD,
            [0; 48],
        )]));
        policy.check_measurement(&measurements).unwrap();
    }

    #[tokio::test]
    async fn test_read_measurements_file_with_list() {
        // Test reading measurement file that contains list values
        let policy = MeasurementPolicy::from_file("test-assets/measurements_list.json".into())
            .await
            .unwrap();

        assert_eq!(policy.accepted_measurements.len(), 1);

        let m = &policy.accepted_measurements[0];
        if let PolicyMeasurements::Dcap(d) = &m.measurements {
            // Check that MRTD has multiple acceptable values
            let mrtd_values = d.get(&DcapMeasurementRegister::MRTD).unwrap();
            assert_eq!(mrtd_values.len(), 2);
        } else {
            panic!("Expected Dcap measurements");
        }

        // Should match either of the two MRTD values
        let measurements_first = MultiMeasurements::Dcap(HashMap::from([
            (DcapMeasurementRegister::MRTD, [0; 48]),
            (DcapMeasurementRegister::RTMR0, [0; 48]),
        ]));
        policy.check_measurement(&measurements_first).unwrap();

        let measurements_second = MultiMeasurements::Dcap(HashMap::from([
            (DcapMeasurementRegister::MRTD, [0x11; 48]),
            (DcapMeasurementRegister::RTMR0, [0; 48]),
        ]));
        policy.check_measurement(&measurements_second).unwrap();
    }
}
