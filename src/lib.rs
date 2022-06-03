pub use binder::*;
use binder::{BinderParams, CachedBinderClient};
use smol::future::FutureExt;
use std::time::Duration;
pub use telemetry::*;
pub use tunnel::*;
use tunnel::{Tunnel, TunnelParams};
pub use vpn::*;
pub mod binder;
mod telemetry;
pub mod tunnel;
pub mod vpn;

pub struct Client {
    tunnel_params: TunnelParams,
    binder_params: BinderParams,
}

impl Client {
    /// Create a client
    pub fn new(tunnel_params: TunnelParams, binder_params: BinderParams) -> Self {
        Client {
            tunnel_params,
            binder_params,
        }
    }

    /// Returns a tunnel that may or may not be connected
    pub async fn start_tunnel(&self) -> anyhow::Result<Tunnel> {
        Tunnel::new(self.tunnel_params.clone()).await
    }

    /// Returns a connected tunnel
    pub async fn start_connected_tunnel(&self) -> anyhow::Result<Tunnel> {
        let tun = self.start_tunnel().await?;
        async {
            loop {
                match tun.current_state().clone() {
                    tunnel::TunnelState::Connecting => {
                        smol::Timer::after(Duration::from_secs(1)).await;
                    }
                    tunnel::TunnelState::Connected { mux: _ } => return Ok(tun),
                }
            }
        }
        .or({
            async {
                smol::Timer::after(Duration::from_secs(10)).await;
                anyhow::bail!("could not start tunnel")
            }
        })
        .await
    }

    pub fn new_binder(&self) -> CachedBinderClient {
        CachedBinderClient::new(self.binder_params.clone())
    }
}
