use anyhow::Context;
use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use smol_timeout::TimeoutExt;
use sosistab::{Buff, BuffMut};
use std::net::Ipv4Addr;
use std::{ops::DerefMut, sync::Arc, time::Duration};

use crate::activity::notify_activity;

/// VPN on-the-wire message
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum VpnMessage {
    ClientHello {
        client_id: u128,
    },
    ServerHello {
        client_ip: Ipv4Addr,
        gateway: Ipv4Addr,
    },
    Payload(Bytes),
}

/// Stdio message
#[derive(Debug, Clone)]
pub struct VpnStdio {
    pub verb: u8,
    pub body: Bytes,
}

impl VpnStdio {
    /// Reads a new StdioMsg
    pub async fn read<R: smol::io::AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Self> {
        use smol::io::AsyncReadExt;
        // first we read one byte
        let mut scratch_space = [0u8; 2];
        reader.read_exact(&mut scratch_space[..1]).await?;
        let verb = scratch_space[0];
        reader.read_exact(&mut scratch_space).await?;
        let length = u16::from_le_bytes(scratch_space);
        let mut bts = BytesMut::new();
        bts.resize(length as usize, 0);
        reader.read_exact(&mut bts).await?;
        Ok(VpnStdio {
            verb,
            body: bts.into(),
        })
    }

    /// Reads a new StdioMsg, synchronously.
    pub fn read_blocking<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut scratch_space = [0u8; 2];
        reader.read_exact(&mut scratch_space[..1])?;
        let verb = scratch_space[0];
        reader.read_exact(&mut scratch_space)?;
        let length = u16::from_le_bytes(scratch_space);
        let mut bts = BytesMut::new();
        bts.resize(length as usize, 0);
        reader.read_exact(&mut bts)?;
        Ok(VpnStdio {
            verb,
            body: bts.into(),
        })
    }

    /// Write out the StdioMsg
    pub async fn write<W: smol::io::AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        use smol::io::AsyncWriteExt;
        let mut buf = Vec::with_capacity(2048);
        buf.write_all(&[self.verb]).await?;
        buf.write_all(&(self.body.len() as u16).to_le_bytes())
            .await?;
        buf.write_all(&self.body).await?;
        writer.write_all(&buf).await?;
        Ok(())
    }

    /// Write out the StdioMsg, blockingly.
    pub fn write_blocking<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        use std::io::Write;
        let mut buf = Vec::with_capacity(2048);
        buf.write_all(&[self.verb])?;
        buf.write_all(&(self.body.len() as u16).to_le_bytes())?;
        buf.write_all(&self.body)?;
        writer.write_all(&buf)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct Vpn {
    pub mux: Arc<sosistab::Multiplex>,
    pub client_ip: Ipv4Addr,
}

impl Vpn {
    // negotiates new VPN
    pub async fn new(mux: Arc<sosistab::Multiplex>) -> anyhow::Result<Vpn> {
        // first, we negotiate the vpn
        let client_id: u128 = rand::random();
        log::info!("negotiating VPN with client id {}...", client_id);
        let client_ip = loop {
            let hello = VpnMessage::ClientHello { client_id };
            mux.send_urel(bincode::serialize(&hello)?.as_slice())
                .await?;
            let resp = mux.recv_urel().timeout(Duration::from_secs(1)).await;
            if let Some(resp) = resp {
                let resp = resp?;
                let resp: VpnMessage = bincode::deserialize(&resp)?;
                match resp {
                    VpnMessage::ServerHello { client_ip, .. } => break client_ip,
                    _ => continue,
                }
            }
        };
        log::info!("negotiated IP address {}!", client_ip);

        Ok(Vpn {
            mux: mux.clone(),
            client_ip,
        })
    }

    pub async fn send_vpn(&self, msg: VpnMessage) -> anyhow::Result<()> {
        notify_activity();

        self.mux.send_urel(serialize(&msg)).await?;

        Ok(())
    }

    pub async fn recv_vpn(&self) -> anyhow::Result<VpnMessage> {
        let bts = self.mux.recv_urel().await.context("downstream failed")?;

        bincode::deserialize(&bts).context("invalid downstream data")
    }
}

pub fn serialize<T: Serialize>(val: &T) -> Buff {
    let mut bmut = BuffMut::new();
    bincode::serialize_into(bmut.deref_mut(), val).unwrap();
    bmut.freeze()
}
