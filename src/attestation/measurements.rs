//! Measurements and policy for enforcing them when validating a remote attestation
use crate::attestation::{AttestationError, AttestationType};
use std::{collections::HashMap, path::PathBuf};

use dcap_qvl::quote::Report;
use http::{header::InvalidHeaderValue, HeaderValue};
use serde::Deserialize;
use thiserror::Error;

/// Measurements determined by the CVM platform
#[derive(Clone, PartialEq, Debug)]
pub struct PlatformMeasurements {
    /// MRTD register value
    pub mrtd: [u8; 48],
    /// RTMR0 register value
    pub rtmr0: [u8; 48],
}

impl PlatformMeasurements {
    /// Given a quote from the dcap_qvl library, extract the platform measurements
    pub fn from_dcap_qvl_quote(quote: &dcap_qvl::quote::Quote) -> Result<Self, AttestationError> {
        let report = match quote.report {
            Report::TD10(report) => report,
            Report::TD15(report) => report.base,
            Report::SgxEnclave(_) => {
                return Err(AttestationError::SgxNotSupported);
            }
        };
        Ok(Self {
            mrtd: report.mr_td,
            rtmr0: report.rt_mr0,
        })
    }

    pub fn from_tdx_quote(quote: &tdx_quote::Quote) -> Self {
        Self {
            mrtd: quote.mrtd(),
            rtmr0: quote.rtmr0(),
        }
    }
}

/// Measurements determined by the CVM image or application
#[derive(Clone, PartialEq, Debug)]
pub struct CvmImageMeasurements {
    /// RTMR1 register value
    pub rtmr1: [u8; 48],
    /// RTMR2 register value
    pub rtmr2: [u8; 48],
    /// RTMR3 register value
    pub rtmr3: [u8; 48],
}

impl CvmImageMeasurements {
    /// Given a quote from the dcap_qvl library, extract the CVM image / application measurements
    pub fn from_dcap_qvl_quote(quote: &dcap_qvl::quote::Quote) -> Result<Self, AttestationError> {
        let report = match quote.report {
            Report::TD10(report) => report,
            Report::TD15(report) => report.base,
            Report::SgxEnclave(_) => {
                return Err(AttestationError::SgxNotSupported);
            }
        };
        Ok(Self {
            rtmr1: report.rt_mr1,
            rtmr2: report.rt_mr2,
            rtmr3: report.rt_mr3,
        })
    }

    pub fn from_tdx_quote(quote: &tdx_quote::Quote) -> Self {
        Self {
            rtmr1: quote.rtmr1(),
            rtmr2: quote.rtmr2(),
            rtmr3: quote.rtmr3(),
        }
    }
}

/// A full set of measurement register values
#[derive(Debug, Clone, PartialEq)]
pub struct Measurements {
    pub platform: PlatformMeasurements,
    pub cvm_image: CvmImageMeasurements,
}

impl Measurements {
    /// Convert to the JSON format used in HTTP headers
    pub fn to_header_format(&self) -> Result<HeaderValue, MeasurementFormatError> {
        let mut measurements_map = HashMap::new();
        measurements_map.insert(0, hex::encode(self.platform.mrtd));
        measurements_map.insert(1, hex::encode(self.platform.rtmr0));
        measurements_map.insert(2, hex::encode(self.cvm_image.rtmr1));
        measurements_map.insert(3, hex::encode(self.cvm_image.rtmr2));
        measurements_map.insert(4, hex::encode(self.cvm_image.rtmr3));
        Ok(HeaderValue::from_str(&serde_json::to_string(
            &measurements_map,
        )?)?)
    }

    /// Parse the JSON used in HTTP headers
    pub fn from_header_format(input: &str) -> Result<Self, MeasurementFormatError> {
        let measurements_map: HashMap<u32, String> = serde_json::from_str(input)?;
        let measurements_map: HashMap<u32, [u8; 48]> = measurements_map
            .into_iter()
            .map(|(k, v)| {
                Ok((
                    k,
                    hex::decode(v)?
                        .try_into()
                        .map_err(|_| MeasurementFormatError::BadLength)?,
                ))
            })
            .collect::<Result<_, MeasurementFormatError>>()?;

        Ok(Self {
            platform: PlatformMeasurements {
                mrtd: *measurements_map
                    .get(&0)
                    .ok_or(MeasurementFormatError::MissingValue("MRTD".to_string()))?,
                rtmr0: *measurements_map
                    .get(&1)
                    .ok_or(MeasurementFormatError::MissingValue("RTMR0".to_string()))?,
            },
            cvm_image: CvmImageMeasurements {
                rtmr1: *measurements_map
                    .get(&2)
                    .ok_or(MeasurementFormatError::MissingValue("RTMR1".to_string()))?,
                rtmr2: *measurements_map
                    .get(&3)
                    .ok_or(MeasurementFormatError::MissingValue("RTMR2".to_string()))?,
                rtmr3: *measurements_map
                    .get(&4)
                    .ok_or(MeasurementFormatError::MissingValue("RTMR3".to_string()))?,
            },
        })
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
}

/// An accepted measurement value given in the measurements file
#[derive(Clone, Debug)]
pub struct MeasurementRecord {
    /// An identifier, for example the name and version of the corresponding OS image
    pub measurement_id: String,
    /// The expected measurement register values
    pub measurements: Measurements,
}

/// Represents the measurement policy
///
/// This is a set of acceptable attestation types (CVM platforms) which may or may not enforce
/// acceptable measurement values for each attestation type
#[derive(Clone, Debug)]
pub struct MeasurementPolicy {
    /// A map of accepted attestation types to accepted measurement values
    /// A value of None means accept any measurement value for this measurement type
    pub(crate) accepted_measurements: HashMap<AttestationType, Option<Vec<MeasurementRecord>>>,
}

impl MeasurementPolicy {
    /// This will only allow no attestation - and will reject it if one is given
    pub fn expect_none() -> Self {
        Self {
            accepted_measurements: HashMap::from([(AttestationType::None, None)]),
        }
    }

    /// Allow any measurements with the given attestation type
    pub fn single_attestation_type(attestation_type: AttestationType) -> Self {
        Self {
            accepted_measurements: HashMap::from([(attestation_type, None)]),
        }
    }

    /// Accept any attestation type with any measurements
    pub fn accept_anything() -> Self {
        Self {
            accepted_measurements: HashMap::from([
                (AttestationType::None, None),
                (AttestationType::Dummy, None),
                (AttestationType::DcapTdx, None),
                (AttestationType::QemuTdx, None),
                (AttestationType::AzureTdx, None),
                (AttestationType::GcpTdx, None),
            ]),
        }
    }

    /// Expect mock measurements used in tests
    #[cfg(test)]
    pub fn mock() -> Self {
        Self {
            accepted_measurements: HashMap::from([(
                AttestationType::DcapTdx,
                Some(vec![MeasurementRecord {
                    measurement_id: "test".to_string(),
                    measurements: Measurements {
                        platform: PlatformMeasurements {
                            mrtd: [0; 48],
                            rtmr0: [0; 48],
                        },
                        cvm_image: CvmImageMeasurements {
                            rtmr1: [0; 48],
                            rtmr2: [0; 48],
                            rtmr3: [0; 48],
                        },
                    },
                }]),
            )]),
        }
    }

    /// Given an attestation type and set of measurements, check whether they are acceptable
    pub fn check_measurement(
        &self,
        attestation_type: AttestationType,
        measurements: &Measurements,
    ) -> Result<(), AttestationError> {
        match self.accepted_measurements.get(&attestation_type) {
            Some(Some(measurement_set)) => {
                if measurement_set
                    .iter()
                    .any(|a| &a.measurements == measurements)
                {
                    Ok(())
                } else {
                    Err(AttestationError::MeasurementsNotAccepted)
                }
            }
            Some(None) => Ok(()),
            None => Err(AttestationError::AttestationTypeNotAccepted),
        }
    }

    /// Whether or not we require attestation
    pub fn has_remote_attestion(&self) -> bool {
        !self
            .accepted_measurements
            .contains_key(&AttestationType::None)
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

        let mut measurement_policy = HashMap::new();

        for measurement in measurements_simple {
            let attestation_type =
                serde_json::from_value(serde_json::Value::String(measurement.attestation_type))
                    .unwrap();

            if let Some(measurements) = measurement.measurements {
                let measurement_record = MeasurementRecord {
                    measurement_id: measurement.measurement_id.unwrap_or_default(),
                    measurements: Measurements {
                        platform: PlatformMeasurements {
                            mrtd: hex::decode(&measurements["0"].expected)?
                                .try_into()
                                .map_err(|_| MeasurementFormatError::BadLength)?,
                            rtmr0: hex::decode(&measurements["1"].expected)?
                                .try_into()
                                .map_err(|_| MeasurementFormatError::BadLength)?,
                        },
                        cvm_image: CvmImageMeasurements {
                            rtmr1: hex::decode(&measurements["2"].expected)?
                                .try_into()
                                .map_err(|_| MeasurementFormatError::BadLength)?,
                            rtmr2: hex::decode(&measurements["3"].expected)?
                                .try_into()
                                .map_err(|_| MeasurementFormatError::BadLength)?,
                            rtmr3: hex::decode(&measurements["4"].expected)?
                                .try_into()
                                .map_err(|_| MeasurementFormatError::BadLength)?,
                        },
                    },
                };

                measurement_policy
                    .entry(attestation_type)
                    .and_modify(|maybe_vec: &mut Option<Vec<MeasurementRecord>>| {
                        match maybe_vec.as_mut() {
                            Some(vec) => vec.push(measurement_record.clone()),
                            None => *maybe_vec = Some(vec![measurement_record.clone()]),
                        }
                    })
                    .or_insert_with(|| Some(vec![measurement_record]));
            } else {
                measurement_policy.entry(attestation_type).or_insert(None);
            };
        }

        Ok(MeasurementPolicy {
            accepted_measurements: measurement_policy,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_measurements() -> Measurements {
        Measurements {
            platform: PlatformMeasurements {
                mrtd: [0; 48],
                rtmr0: [0; 48],
            },
            cvm_image: CvmImageMeasurements {
                rtmr1: [0; 48],
                rtmr2: [0; 48],
                rtmr3: [0; 48],
            },
        }
    }

    #[tokio::test]
    async fn test_read_measurements_file() {
        let specific_measurements =
            MeasurementPolicy::from_file("test-assets/measurements.json".into())
                .await
                .unwrap();

        assert!(specific_measurements
            .accepted_measurements
            .get(&AttestationType::DcapTdx)
            .unwrap()
            .is_some());

        // Will not match mock measurements
        assert!(matches!(
            specific_measurements
                .check_measurement(AttestationType::DcapTdx, &mock_measurements())
                .unwrap_err(),
            AttestationError::MeasurementsNotAccepted
        ));

        // Will not match another attestation type
        assert!(matches!(
            specific_measurements
                .check_measurement(AttestationType::None, &mock_measurements())
                .unwrap_err(),
            AttestationError::AttestationTypeNotAccepted
        ));
    }

    #[tokio::test]
    async fn test_read_measurements_file_non_specific() {
        let mock_measurements = mock_measurements();
        // This specifies a particular attestation type, but not specific measurements
        let allowed_attestation_type =
            MeasurementPolicy::from_file("test-assets/measurements_2.json".into())
                .await
                .unwrap();

        allowed_attestation_type
            .check_measurement(AttestationType::DcapTdx, &mock_measurements)
            .unwrap();

        assert!(allowed_attestation_type
            .accepted_measurements
            .get(&AttestationType::DcapTdx)
            .unwrap()
            .is_none());

        // Will match mock measurements
        allowed_attestation_type
            .check_measurement(AttestationType::DcapTdx, &mock_measurements)
            .unwrap();
    }
}
