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

/// Expected measurement values for policy enforcement
#[derive(Debug, Clone, PartialEq)]
pub enum ExpectedMeasurements {
    Dcap(HashMap<DcapMeasurementRegister, Vec<[u8; 48]>>),
    Azure(HashMap<u32, Vec<[u8; 32]>>),
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

    #[cfg(any(test, feature = "mock"))]
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
    #[error("Measurement entry for register '{0}' has both 'expected' and 'expected_any'")]
    BothExpectedAndExpectedAny(String),
    #[error("Measurement entry for register '{0}' has neither 'expected' nor 'expected_any'")]
    NoExpectedValue(String),
    #[error("Measurement entry for register '{0}' has empty 'expected_any' list")]
    EmptyExpectedAny(String),
}

/// An accepted measurement value given in the measurements file
#[derive(Clone, Debug, PartialEq)]
pub struct MeasurementRecord {
    /// An identifier, for example the name and version of the corresponding OS image
    pub measurement_id: String,
    /// The expected measurement register values
    pub measurements: ExpectedMeasurements,
}

impl MeasurementRecord {
    pub fn allow_no_attestation() -> Self {
        Self {
            measurement_id: "Allow no attestation".to_string(),
            measurements: ExpectedMeasurements::NoAttestation,
        }
    }

    pub fn allow_any_measurement(attestation_type: AttestationType) -> Self {
        Self {
            measurement_id: format!("Any measurement for {attestation_type}"),
            measurements: match attestation_type {
                AttestationType::None => ExpectedMeasurements::NoAttestation,
                AttestationType::AzureTdx => ExpectedMeasurements::Azure(HashMap::new()),
                _ => ExpectedMeasurements::Dcap(HashMap::new()),
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
                MeasurementRecord::allow_any_measurement(AttestationType::DcapTdx),
                MeasurementRecord::allow_any_measurement(AttestationType::QemuTdx),
                MeasurementRecord::allow_any_measurement(AttestationType::GcpTdx),
                MeasurementRecord::allow_any_measurement(AttestationType::AzureTdx),
            ],
        }
    }

    /// Expect mock measurements used in tests
    #[cfg(any(test, feature = "mock"))]
    pub fn mock() -> Self {
        Self {
            accepted_measurements: vec![MeasurementRecord {
                measurement_id: "test".to_string(),
                measurements: ExpectedMeasurements::Dcap(HashMap::from([
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
                    if let ExpectedMeasurements::Dcap(expected) = &measurement_record.measurements {
                        // All measurements in our policy must be given and must match
                        for (k, v) in expected.iter() {
                            match dcap_measurements.get(k) {
                                Some(actual_value) if v.iter().any(|v| actual_value == v) => {}
                                _ => return false,
                            }
                        }
                        return true;
                    }
                    false
                }
                MultiMeasurements::Azure(azure_measurements) => {
                    if let ExpectedMeasurements::Azure(expected) = &measurement_record.measurements
                    {
                        for (k, v) in expected.iter() {
                            match azure_measurements.get(k) {
                                Some(actual_value) if v.iter().any(|v| actual_value == v) => {}
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
                        ExpectedMeasurements::NoAttestation
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
            .any(|a| a.measurements == ExpectedMeasurements::NoAttestation)
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

        /// Measurement entry for a single register in the measurements JSON file.
        /// Use `expected_any` for new configurations; `expected` is deprecated.
        #[derive(Debug, Deserialize)]
        struct MeasurementEntry {
            /// Deprecated: use `expected_any` instead. Single hex-encoded expected value.
            #[serde(default)]
            expected: Option<String>,
            /// List of acceptable hex-encoded values (OR semantics - any value matches).
            #[serde(default)]
            expected_any: Option<Vec<String>>,
        }

        fn parse_measurement_entry<const N: usize>(
            entry: &MeasurementEntry,
            register_name: &str,
        ) -> Result<Vec<[u8; N]>, MeasurementFormatError> {
            match (&entry.expected, &entry.expected_any) {
                (Some(single), None) => {
                    let bytes: [u8; N] = hex::decode(single)?
                        .try_into()
                        .map_err(|_| MeasurementFormatError::BadLength)?;
                    Ok(vec![bytes])
                }
                (None, Some(any_list)) => {
                    if any_list.is_empty() {
                        return Err(MeasurementFormatError::EmptyExpectedAny(
                            register_name.to_string(),
                        ));
                    }
                    let values = any_list
                        .iter()
                        .map(|hex_str| {
                            hex::decode(hex_str)?
                                .try_into()
                                .map_err(|_| MeasurementFormatError::BadLength)
                        })
                        .collect::<Result<Vec<[u8; N]>, _>>()?;
                    Ok(values)
                }
                (Some(_), Some(_)) => Err(MeasurementFormatError::BothExpectedAndExpectedAny(
                    register_name.to_string(),
                )),
                (None, None) => Err(MeasurementFormatError::NoExpectedValue(
                    register_name.to_string(),
                )),
            }
        }

        let measurements_simple: Vec<MeasurementRecordSimple> =
            serde_json::from_slice(&json_bytes)?;

        let mut measurement_policy = Vec::new();

        for measurement in measurements_simple {
            let attestation_type =
                serde_json::from_value(serde_json::Value::String(measurement.attestation_type))?;

            if let Some(measurements) = measurement.measurements {
                let expected_measurements = match attestation_type {
                    AttestationType::AzureTdx => {
                        let azure_measurements = measurements
                            .iter()
                            .map(|(index_str, entry)| {
                                let index: u32 = index_str.parse()?;

                                if index > 23 {
                                    return Err(MeasurementFormatError::BadRegisterIndex);
                                }

                                Ok((index, parse_measurement_entry::<32>(entry, index_str)?))
                            })
                            .collect::<Result<HashMap<u32, Vec<[u8; 32]>>, MeasurementFormatError>>(
                            )?;
                        ExpectedMeasurements::Azure(azure_measurements)
                    }
                    AttestationType::None => ExpectedMeasurements::NoAttestation,
                    _ => ExpectedMeasurements::Dcap(
                        measurements
                            .iter()
                            .map(|(index_str, entry)| {
                                let index: u8 = index_str.parse()?;
                                Ok((
                                    DcapMeasurementRegister::try_from(index)?,
                                    parse_measurement_entry::<48>(entry, index_str)?,
                                ))
                            })
                            .collect::<Result<
                                HashMap<DcapMeasurementRegister, Vec<[u8; 48]>>,
                                MeasurementFormatError,
                            >>()?,
                    ),
                };

                measurement_policy.push(MeasurementRecord {
                    measurement_id: measurement.measurement_id.unwrap_or_default(),
                    measurements: expected_measurements,
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
        if let ExpectedMeasurements::Azure(a) = &m.measurements {
            assert_eq!(
                a.keys().collect::<HashSet<_>>(),
                HashSet::from([&9, &4, &11])
            );
        } else {
            panic!("Unexpected measurement type");
        }

        let m = &specific_measurements.accepted_measurements[1];
        if let ExpectedMeasurements::Azure(a) = &m.measurements {
            assert_eq!(a.keys().collect::<HashSet<_>>(), HashSet::from([&9, &4]));
        } else {
            panic!("Unexpected measurement type");
        }

        let m = &specific_measurements.accepted_measurements[2];
        if let ExpectedMeasurements::Dcap(d) = &m.measurements {
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
    async fn test_parse_expected_any() {
        let json = r#"[
            {
                "measurement_id": "test-any",
                "attestation_type": "dcap-tdx",
                "measurements": {
                    "0": {
                        "expected_any": [
                            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                            "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
                        ]
                    }
                }
            }
        ]"#;

        let policy = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec())
            .await
            .unwrap();
        assert_eq!(policy.accepted_measurements.len(), 1);

        let record = &policy.accepted_measurements[0];
        if let ExpectedMeasurements::Dcap(dcap) = &record.measurements {
            let expected = dcap.get(&DcapMeasurementRegister::MRTD).unwrap();
            assert_eq!(expected.len(), 2);
        } else {
            panic!("Expected ExpectedMeasurements::Dcap");
        }
    }

    #[tokio::test]
    async fn test_check_measurement_with_or_semantics() {
        let json = r#"[
            {
                "measurement_id": "test-or",
                "attestation_type": "dcap-tdx",
                "measurements": {
                    "0": {
                        "expected_any": [
                            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                            "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
                        ]
                    }
                }
            }
        ]"#;

        let policy = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec())
            .await
            .unwrap();

        // First value should match
        let measurements1 =
            MultiMeasurements::Dcap(HashMap::from([(DcapMeasurementRegister::MRTD, [0u8; 48])]));
        assert!(policy.check_measurement(&measurements1).is_ok());

        // Second value should also match
        let measurements2 = MultiMeasurements::Dcap(HashMap::from([(
            DcapMeasurementRegister::MRTD,
            [0x11u8; 48],
        )]));
        assert!(policy.check_measurement(&measurements2).is_ok());

        // Different value should not match
        let measurements3 = MultiMeasurements::Dcap(HashMap::from([(
            DcapMeasurementRegister::MRTD,
            [0x22u8; 48],
        )]));
        assert!(policy.check_measurement(&measurements3).is_err());
    }

    #[tokio::test]
    async fn test_parse_both_expected_and_expected_any_error() {
        let json = r#"[
            {
                "attestation_type": "dcap-tdx",
                "measurements": {
                    "0": {
                        "expected": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "expected_any": ["111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"]
                    }
                }
            }
        ]"#;

        let result = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec()).await;
        assert!(matches!(
            result,
            Err(MeasurementFormatError::BothExpectedAndExpectedAny(_))
        ));
    }

    #[tokio::test]
    async fn test_parse_neither_expected_nor_expected_any_error() {
        let json = r#"[
            {
                "attestation_type": "dcap-tdx",
                "measurements": {
                    "0": {}
                }
            }
        ]"#;

        let result = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec()).await;
        assert!(matches!(
            result,
            Err(MeasurementFormatError::NoExpectedValue(_))
        ));
    }

    #[tokio::test]
    async fn test_parse_empty_expected_any_error() {
        let json = r#"[
            {
                "attestation_type": "dcap-tdx",
                "measurements": {
                    "0": {
                        "expected_any": []
                    }
                }
            }
        ]"#;

        let result = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec()).await;
        assert!(matches!(
            result,
            Err(MeasurementFormatError::EmptyExpectedAny(_))
        ));
    }

    #[tokio::test]
    async fn test_mixed_expected_and_expected_any_in_different_registers() {
        let json = r#"[
            {
                "measurement_id": "mixed-test",
                "attestation_type": "dcap-tdx",
                "measurements": {
                    "0": {
                        "expected": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                    },
                    "1": {
                        "expected_any": [
                            "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
                            "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"
                        ]
                    }
                }
            }
        ]"#;

        let policy = MeasurementPolicy::from_json_bytes(json.as_bytes().to_vec())
            .await
            .unwrap();

        // Both match (single + first of any)
        let measurements1 = MultiMeasurements::Dcap(HashMap::from([
            (DcapMeasurementRegister::MRTD, [0u8; 48]),
            (DcapMeasurementRegister::RTMR0, [0x11u8; 48]),
        ]));
        assert!(policy.check_measurement(&measurements1).is_ok());

        // Both match (single + second of any)
        let measurements2 = MultiMeasurements::Dcap(HashMap::from([
            (DcapMeasurementRegister::MRTD, [0u8; 48]),
            (DcapMeasurementRegister::RTMR0, [0x22u8; 48]),
        ]));
        assert!(policy.check_measurement(&measurements2).is_ok());

        // Single matches but any doesn't
        let measurements3 = MultiMeasurements::Dcap(HashMap::from([
            (DcapMeasurementRegister::MRTD, [0u8; 48]),
            (DcapMeasurementRegister::RTMR0, [0x33u8; 48]),
        ]));
        assert!(policy.check_measurement(&measurements3).is_err());
    }
}
