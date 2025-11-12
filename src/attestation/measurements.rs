use crate::attestation::AttestationError;
use dcap_qvl::quote::Report;
use http::{header::InvalidHeaderValue, HeaderValue};
use std::collections::HashMap;
use thiserror::Error;

/// Measurements determined by the CVM platform
#[derive(Clone, PartialEq, Debug)]
pub struct PlatformMeasurements {
    pub mrtd: [u8; 48],
    pub rtmr0: [u8; 48],
}

impl PlatformMeasurements {
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

/// Measurements determined by the CVM image
#[derive(Clone, PartialEq, Debug)]
pub struct CvmImageMeasurements {
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
    pub rtmr3: [u8; 48],
}

impl CvmImageMeasurements {
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
#[derive(Debug, Clone, PartialEq)]
pub struct Measurements {
    pub platform: PlatformMeasurements,
    pub cvm_image: CvmImageMeasurements,
}

impl Measurements {
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

    pub fn from_header_format(input: &str) -> Result<Self, MeasurementFormatError> {
        let measurements_map: HashMap<u32, String> = serde_json::from_str(input)?;
        let measurements_map: HashMap<u32, [u8; 48]> = measurements_map
            .into_iter()
            .map(|(k, v)| (k, hex::decode(v).unwrap().try_into().unwrap()))
            .collect();

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

#[derive(Error, Debug)]
pub enum MeasurementFormatError {
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Missing value: {0}")]
    MissingValue(String),
    #[error("Invalid header value: {0}")]
    BadHeaderValue(#[from] InvalidHeaderValue),
}
