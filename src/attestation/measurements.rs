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
}

/// An accepted measurement value given in the measurements file
#[derive(Clone, Debug, PartialEq)]
pub struct MeasurementRecord {
    /// An identifier, for example the name and version of the corresponding OS image
    pub measurement_id: String,
    /// The expected measurement register values
    pub measurements: MultiMeasurements,
}

impl MeasurementRecord {
    pub fn allow_no_attestation() -> Self {
        Self {
            measurement_id: "Allow no attestation".to_string(),
            measurements: MultiMeasurements::NoAttestation,
        }
    }

    pub fn allow_any_measurement(attestation_type: AttestationType) -> Self {
        Self {
            measurement_id: format!("Any measurement for {attestation_type}"),
            measurements: match attestation_type {
                AttestationType::None => MultiMeasurements::NoAttestation,
                AttestationType::AzureTdx => MultiMeasurements::Azure(HashMap::new()),
                _ => MultiMeasurements::Dcap(HashMap::new()),
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
                measurements: MultiMeasurements::Dcap(HashMap::from([
                    (DcapMeasurementRegister::MRTD, [0; 48]),
                    (DcapMeasurementRegister::RTMR0, [0; 48]),
                    (DcapMeasurementRegister::RTMR1, [0; 48]),
                    (DcapMeasurementRegister::RTMR2, [0; 48]),
                    (DcapMeasurementRegister::RTMR3, [0; 48]),
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
                    if let MultiMeasurements::Dcap(d) = measurement_record.measurements.clone() {
                        for (k, v) in dcap_measurements.iter() {
                            if d.get(k).is_some_and(|x| x != v) {
                                return false;
                            }
                        }
                        return true;
                    }
                    false
                }
                MultiMeasurements::Azure(azure_measurements) => {
                    if let MultiMeasurements::Azure(a) = measurement_record.measurements.clone() {
                        for (k, v) in azure_measurements.iter() {
                            if a.get(k).is_some_and(|x| x != v) {
                                return false;
                            }
                        }
                        return true;
                    }
                    false
                }
                MultiMeasurements::NoAttestation => {
                    if MultiMeasurements::NoAttestation == measurement_record.measurements.clone() {
                        return true;
                    }
                    false
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
            .any(|a| a.measurements == MultiMeasurements::NoAttestation)
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

        #[derive(Debug, Deserialize)]
        struct MeasurementEntry {
            expected: String,
        }

        let measurements_simple: Vec<MeasurementRecordSimple> =
            serde_json::from_slice(&json_bytes)?;

        let mut measurement_policy = Vec::new();

        for measurement in measurements_simple {
            let attestation_type =
                serde_json::from_value(serde_json::Value::String(measurement.attestation_type))?;

            if let Some(measurements) = measurement.measurements {
                let multi_measurement = match attestation_type {
                    AttestationType::AzureTdx => {
                        let azure_measurements = measurements
                            .into_iter()
                            .map(|(index, entry)| {
                                let index = index.parse()?;

                                if index > 23 {
                                    return Err(MeasurementFormatError::BadRegisterIndex);
                                }

                                Ok((
                                    index,
                                    hex::decode(entry.expected)?
                                        .try_into()
                                        .map_err(|_| MeasurementFormatError::BadLength)?,
                                ))
                            })
                            .collect::<Result<HashMap<u32, [u8; 32]>, MeasurementFormatError>>()?;
                        MultiMeasurements::Azure(azure_measurements)
                    }
                    AttestationType::None => MultiMeasurements::NoAttestation,
                    _ => MultiMeasurements::Dcap(
                        measurements
                            .into_iter()
                            .map(|(index, entry)| {
                                let index: u8 = index.parse()?;
                                Ok((
                                    DcapMeasurementRegister::try_from(index)?,
                                    hex::decode(entry.expected)?
                                        .try_into()
                                        .map_err(|_| MeasurementFormatError::BadLength)?,
                                ))
                            })
                            .collect::<Result<
                                HashMap<DcapMeasurementRegister, [u8; 48]>,
                                MeasurementFormatError,
                            >>()?,
                    ),
                };

                measurement_policy.push(MeasurementRecord {
                    measurement_id: measurement.measurement_id.unwrap_or_default(),
                    measurements: multi_measurement,
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
        if let MultiMeasurements::Azure(a) = &m.measurements {
            assert_eq!(
                a.keys().collect::<HashSet<_>>(),
                HashSet::from([&9, &4, &11])
            );
        } else {
            panic!("Unexpected measurement type");
        }

        let m = &specific_measurements.accepted_measurements[1];
        if let MultiMeasurements::Azure(a) = &m.measurements {
            assert_eq!(a.keys().collect::<HashSet<_>>(), HashSet::from([&9, &4]));
        } else {
            panic!("Unexpected measurement type");
        }

        let m = &specific_measurements.accepted_measurements[2];
        if let MultiMeasurements::Dcap(d) = &m.measurements {
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
}
