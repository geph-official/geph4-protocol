use async_net::SocketAddr;
use geph4_protocol::bridge_exit::{BridgeExitClient, BridgeExitTransport, LegacyProtocol};

fn main() -> anyhow::Result<()> {
    smol::future::block_on(async {
        let bridge_secret = blake3::hash(std::env::var("BRIDGE_SECRET").unwrap().as_bytes());
        let exit_addr: SocketAddr = "155.138.252.132:28080".parse().unwrap();
        let transport = BridgeExitTransport::new(*bridge_secret.as_bytes(), exit_addr);
        let client = BridgeExitClient(transport);
        dbg!(
            client
                .advertise_raw(LegacyProtocol::Udp, exit_addr, "fake-lol".into())
                .await?
        );
        Ok(())
    })
}
