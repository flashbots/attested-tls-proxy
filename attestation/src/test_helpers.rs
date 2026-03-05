use crate::{MultiMeasurements, measurements::DcapMeasurementRegister};
use std::collections::HashMap;

/// All-zero measurment values used in some tests
pub fn mock_dcap_measurements() -> MultiMeasurements {
    MultiMeasurements::Dcap(HashMap::from([
        (DcapMeasurementRegister::MRTD, [0u8; 48]),
        (DcapMeasurementRegister::RTMR0, [0u8; 48]),
        (DcapMeasurementRegister::RTMR1, [0u8; 48]),
        (DcapMeasurementRegister::RTMR2, [0u8; 48]),
        (DcapMeasurementRegister::RTMR3, [0u8; 48]),
    ]))
}
