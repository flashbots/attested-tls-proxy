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
    /// The associated attestation platform
    pub attestation_type: AttestationType,
    /// The expected measurement register values
    pub measurements: Measurements,
}

/// Given the path to a JSON file containing measurements, return a [Vec<MeasurementRecord>]
pub async fn get_measurements_from_file(
    measurement_file: PathBuf,
) -> Result<Vec<MeasurementRecord>, MeasurementFormatError> {
    #[derive(Debug, Deserialize)]
    struct MeasurementRecordSimple {
        measurement_id: String,
        attestation_type: String,
        measurements: HashMap<String, MeasurementEntry>,
    }

    #[derive(Debug, Deserialize)]
    struct MeasurementEntry {
        expected: String,
    }

    let measurements_json = tokio::fs::read(measurement_file).await?;
    let measurements_simple: Vec<MeasurementRecordSimple> =
        serde_json::from_slice(&measurements_json)?;
    let mut measurements = Vec::new();
    for measurement in measurements_simple {
        measurements.push(MeasurementRecord {
            measurement_id: measurement.measurement_id,
            attestation_type: serde_json::from_value(serde_json::Value::String(
                measurement.attestation_type,
            ))
            .map_err(|_| MeasurementFormatError::AttestationTypeNotValid)?,
            measurements: Measurements {
                platform: PlatformMeasurements {
                    mrtd: hex::decode(&measurement.measurements["0"].expected)?
                        .try_into()
                        .map_err(|_| MeasurementFormatError::BadLength)?,
                    rtmr0: hex::decode(&measurement.measurements["1"].expected)?
                        .try_into()
                        .map_err(|_| MeasurementFormatError::BadLength)?,
                },
                cvm_image: CvmImageMeasurements {
                    rtmr1: hex::decode(&measurement.measurements["2"].expected)?
                        .try_into()
                        .map_err(|_| MeasurementFormatError::BadLength)?,
                    rtmr2: hex::decode(&measurement.measurements["3"].expected)?
                        .try_into()
                        .map_err(|_| MeasurementFormatError::BadLength)?,
                    rtmr3: hex::decode(&measurement.measurements["4"].expected)?
                        .try_into()
                        .map_err(|_| MeasurementFormatError::BadLength)?,
                },
            },
        });
    }

    Ok(measurements)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_read_measurements_file() {
        get_measurements_from_file("test-assets/measurements.json".into())
            .await
            .unwrap();
    }
}
