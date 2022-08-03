use crate::{serialize, EndpointSource, Telemetry, VpnMessage};

use super::{
    activity::{notify_activity, wait_activity},
    getsess::get_session,
    reroute::rerouter_once,
    TunnelCtx,
};
use anyhow::Context;
// use parking_lot::RwLock;
use smol::{
    channel::{Receiver, Sender},
    prelude::*,
};
use smol_timeout::TimeoutExt;
use sosistab::Multiplex;
use std::{
    net::SocketAddr,
    sync::{atomic::Ordering, Arc},
    time::Duration,
    time::Instant,
};

/// Background task of a TunnelManager
pub async fn tunnel_actor(ctx: TunnelCtx) -> anyhow::Result<()> {
    loop {
        // Run until a failure happens, log the error, then restart
        if let Err(err) = tunnel_actor_once(ctx.clone()).await {
            log::warn!("tunnel_actor restarting: {:?}", err);
            smol::Timer::after(Duration::from_secs(1)).await;
        }
    }
}

async fn tunnel_actor_once(ctx: TunnelCtx) -> anyhow::Result<()> {
    let ctx1 = ctx.clone();
    ctx.current_state.store(0, Ordering::Relaxed);
    notify_activity();

    let protosess = get_session(ctx.clone(), None).await?;
    let protosess_remaddr = protosess.remote_addr();
    let tunnel_mux = Arc::new(protosess.multiplex());

    if let EndpointSource::Binder(binder_tunnel_params) = ctx.endpoint {
        // authenticate
        let token = binder_tunnel_params.ccache.get_auth_token().await?;
        authenticate_session(&tunnel_mux, &token)
            .timeout(Duration::from_secs(15))
            .await
            .ok_or_else(|| anyhow::anyhow!("authentication timed out"))??;
    }

    // negotiate vpn
    let client_id: u128 = rand::random();
    log::info!("negotiating VPN with client id {}...", client_id);
    let vpn_client_ip = loop {
        let hello = VpnMessage::ClientHello { client_id };
        tunnel_mux
            .send_urel(bincode::serialize(&hello)?.as_slice())
            .await?;
        let resp = tunnel_mux.recv_urel().timeout(Duration::from_secs(1)).await;
        if let Some(resp) = resp {
            let resp = resp?;
            let resp: VpnMessage = bincode::deserialize(&resp)?;
            match resp {
                VpnMessage::ServerHello { client_ip, .. } => break client_ip,
                _ => continue,
            }
        }
    };
    log::info!("negotiated IP address {}!", vpn_client_ip);
    log::info!("TUNNEL_ACTOR MAIN LOOP through {}", protosess_remaddr);

    ctx.current_state
        .store(vpn_client_ip.into(), Ordering::Relaxed);

    let (send_death, recv_death) = smol::channel::unbounded();

    connection_handler_loop(ctx1.clone(), tunnel_mux.clone(), send_death)
        .or(async {
            // kill the whole session if any one connection fails
            let e = recv_death.recv().await.context("death received")?;
            anyhow::bail!(e)
        })
        .or(watchdog_loop(
            ctx1.clone(),
            protosess_remaddr,
            tunnel_mux.clone(),
        ))
        .or(vpn_up_loop(tunnel_mux.clone(), ctx.recv_vpn_outgoing))
        .or(vpn_down_loop(tunnel_mux, ctx.send_vpn_incoming))
        .await
}

/// authenticates a muxed session
async fn authenticate_session(
    session: &sosistab::Multiplex,
    token: &crate::binder::Token,
) -> anyhow::Result<()> {
    let mut auth_conn = session.open_conn(None).await?;
    log::debug!("sending auth info...");
    geph4_aioutils::write_pascalish(
        &mut auth_conn,
        &(
            &token.unblinded_digest,
            &token.unblinded_signature,
            &token.level,
        ),
    )
    .await?;
    log::debug!("sent auth info!");
    let _: u8 = geph4_aioutils::read_pascalish(&mut auth_conn).await?;
    Ok(())
}

async fn vpn_up_loop(
    mux: Arc<Multiplex>,
    recv_outgoing: Receiver<VpnMessage>,
) -> anyhow::Result<()> {
    loop {
        if let Ok(msg) = recv_outgoing.recv().await {
            mux.send_urel(serialize(&msg)).await?;
        }
    }
}

async fn vpn_down_loop(
    mux: Arc<Multiplex>,
    send_incoming: Sender<VpnMessage>,
) -> anyhow::Result<()> {
    loop {
        let bts = mux.recv_urel().await.context("downstream failed")?;
        let msg = bincode::deserialize(&bts).context("invalid downstream data")?;
        send_incoming.try_send(msg)?;
    }
}

// handles socks5 connection requests
async fn connection_handler_loop(
    ctx: TunnelCtx,
    mux: Arc<Multiplex>,
    send_death: Sender<anyhow::Error>,
) -> anyhow::Result<()> {
    loop {
        let (conn_host, conn_reply) = ctx
            .recv_socks5_conn
            .recv()
            .await
            .context("cannot get socks5 connect request")?;
        let mux = mux.clone();
        let send_death = send_death.clone();
        smolscale::spawn(async move {
            let start = Instant::now();
            let remote = (&mux).open_conn(Some(conn_host.clone())).await;
            match remote {
                Ok(remote) => {
                    log::debug!(
                        "opened connection to {} in {} ms",
                        conn_host,
                        start.elapsed().as_millis(),
                    );

                    conn_reply.send(remote).await.context("conn_reply failed")?;
                    Ok::<(), anyhow::Error>(())
                }
                Err(err) => {
                    send_death
                        .send(anyhow::anyhow!(
                            "conn open error {} in {}s",
                            err,
                            start.elapsed().as_secs_f64()
                        ))
                        .await?;
                    Ok(())
                }
            }
        })
        .detach();
    }
}

// keeps the connection alive
async fn watchdog_loop(
    ctx: TunnelCtx,
    bridge_addr: SocketAddr,
    tunnel_mux: Arc<Multiplex>,
) -> anyhow::Result<()> {
    // We first request the ID of the other multiplex.
    let other_id = {
        let mut conn = tunnel_mux.open_conn(Some("!id".into())).await?;
        let mut buf = [0u8; 32];
        conn.read_exact(&mut buf).await.context("!id failed")?;
        buf
    };
    let version = env!("CARGO_PKG_VERSION");
    loop {
        wait_activity(Duration::from_secs(600)).await;
        let start = Instant::now();
        if tunnel_mux
            .open_conn(None)
            .timeout(Duration::from_secs(15))
            .await
            .is_none()
        {
            log::warn!("watchdog conn failed! rerouting...");
            rerouter_once(ctx.clone(), bridge_addr, &tunnel_mux, other_id)
                .timeout(Duration::from_secs(15))
                .await
                .context("rerouter timed out")??;
            log::warn!("rerouting done.");
        } else {
            let ping = start.elapsed();
            log::debug!("** watchdog completed in {:?} **", ping);
            ctx.tunnel_stats.last_ping_ms.store(
                ping.as_millis() as u32,
                std::sync::atomic::Ordering::Relaxed,
            );
            if fastrand::f32() < 0.1 {
                let tunnel_mux = tunnel_mux.clone();
                smolscale::spawn(async move {
                    let telemetry = Telemetry {
                        watchdog_ping_ms: ping.as_millis() as _,
                        version: version.replace('.', "-"),
                    };
                    log::debug!("** sending telemetry: {:?} **", telemetry);
                    let mut telemetry_conn = tunnel_mux
                        .open_conn(Some("!telemetry".into()))
                        .timeout(Duration::from_secs(10))
                        .await
                        .context("what now")??;
                    telemetry_conn
                        .write_all(
                            format!("{}\n", serde_json::to_string(&telemetry).unwrap()).as_bytes(),
                        )
                        .await?;
                    telemetry_conn.flush().await?;
                    smol::Timer::after(Duration::from_secs(1)).await;
                    Ok::<_, anyhow::Error>(())
                })
                .detach();
            }
            smol::Timer::after(Duration::from_secs(3)).await;
        }
    }
}