use async_trait::async_trait;
use nanorpc::nanorpc_derive;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use crate::binder::protocol::BlindToken;

#[derive(Serialize, Deserialize, Debug, Clone)]
/// A client telemetry message.
pub struct ClientTelemetry {
    pub version: SmolStr,
    pub platform: SmolStr,
}

/// The nanorpc_derive trait describing the client/exit protocol that runs over sosistab2.
#[nanorpc_derive]
#[async_trait]
pub trait ClientExitProtocol {
    /// Authenticates the user. Before this method is called, no user traffic can pass. Idempotent.
    async fn validate(&self, token: BlindToken) -> bool;

    /// Uploads a telemetry sample. Also used as a keepalive "heartbeat".
    async fn telemetry_heartbeat(&self, tele: ClientTelemetry);
}

/// The special "hostname" that serves the client-exit protocol through sosistab2.
pub const CLIENT_EXIT_PSEUDOHOST: &str = "@client-exit";
