use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use async_net::{SocketAddr, UdpSocket};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::TryFutureExt;
use nanorpc::{nanorpc_derive, JrpcRequest, JrpcResponse, RpcService, RpcTransport};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use smol_timeout::TimeoutExt;

/// An RpcTransport that implements the symmetrically authenticated bridge-exit protocol.
#[derive(Clone)]
pub struct BridgeExitTransport {
    key: [u8; 32],
    dest: SocketAddr,
}

impl BridgeExitTransport {
    /// Creates a new BridgeExitTransport with the given bridge secret and destination.
    pub fn new(secret: [u8; 32], exit: SocketAddr) -> Self {
        Self {
            key: secret,
            dest: exit,
        }
    }
}

/// Serve the authenticated bridge-exit protocol, given an RpcService.
pub async fn serve_bridge_exit<R: RpcService>(
    socket: UdpSocket,
    key: [u8; 32],
    service: R,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 2048];
    let service = Arc::new(service);
    loop {
        let (n, client_addr) = socket.recv_from(&mut buf).await?;
        let service = service.clone();
        let request = Bytes::copy_from_slice(&buf[..n]);
        let socket = socket.clone();
        smolscale::spawn(
            async move {
                let (mac, timestamp, plain): ([u8; 32], u64, Bytes) =
                    stdcode::deserialize(&request)?;
                let correct_timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                if timestamp > correct_timestamp + 60
                    || timestamp < correct_timestamp.saturating_sub(60)
                {
                    anyhow::bail!("timestamp out of range")
                }
                let mac_key = blake3::keyed_hash(&key, &timestamp.to_be_bytes());
                let correct_mac = blake3::keyed_hash(mac_key.as_bytes(), &plain);
                if correct_mac != blake3::Hash::from(mac) {
                    anyhow::bail!("MAC is wrong")
                }
                let request: JrpcRequest = serde_json::from_slice(&plain)?;
                let response = service.respond_raw(request).await;
                socket
                    .send_to(&serde_json::to_vec(&response)?, client_addr)
                    .await?;
                anyhow::Ok(())
            }
            .map_err(move |e| log::warn!("bad bridge_exit pkt from {client_addr}: {e}")),
        )
        .detach()
    }
}

#[async_trait]
impl RpcTransport for BridgeExitTransport {
    type Error = anyhow::Error;

    async fn call_raw(&self, jrpc: JrpcRequest) -> Result<JrpcResponse, Self::Error> {
        let plain_vec = serde_json::to_vec(&jrpc)?;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mac_key = blake3::keyed_hash(&self.key, &timestamp.to_be_bytes());
        let mac = blake3::keyed_hash(mac_key.as_bytes(), &plain_vec);
        let to_send = stdcode::serialize(&(mac.as_bytes(), timestamp, plain_vec))?;
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(&to_send, self.dest).await?;
        let mut buff = [0u8; 2048];
        let (n, _) = socket
            .recv_from(&mut buff)
            .timeout(Duration::from_secs(10))
            .await
            .context("udp receive timeout")??;
        // response is NOT authenticated. this is generally fine.
        Ok(serde_json::from_slice(&buff[..n])?)
    }
}

/// An available raw, kernel-forwardable protocol
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Hash, Deserialize, Serialize)]
pub enum RawProtocol {
    Tcp,
    Udp,
}

/// The nanorpc_derive trait describing the bridge/exit protocol.
#[nanorpc_derive]
#[async_trait]
pub trait BridgeExitProtocol {
    /// Advertises an available raw port. If enough resources are available, returns the address to forward traffic to.
    async fn advertise_raw(
        &self,
        protocol: RawProtocol,
        bridge_addr: SocketAddr,
        bridge_group: SmolStr,
    ) -> SocketAddr;
}
