use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Telemetry {
    pub watchdog_ping_ms: usize,
    pub version: String,
}
