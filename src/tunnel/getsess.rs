use super::{protosess::ProtoSession, EndpointSource, TunnelCtx};
use anyhow::Context;
use async_net::SocketAddr;
use futures_util::stream::FuturesUnordered;
use geph4_binder_transport::ExitDescriptor;
use smol::prelude::*;
use smol_timeout::TimeoutExt;
use sosistab::Session;
use std::{
    convert::TryFrom,
    sync::Arc,
    time::{Duration, Instant},
};
use tap::{Pipe, Tap};

pub fn sosistab_udp(
    server_addr: SocketAddr,
    server_pk: x25519_dalek::PublicKey,
    shard_count: usize,
    reset_interval: Duration,
    stats_gatherer: Arc<sosistab::StatsGatherer>,
) -> sosistab::ClientConfig {
    sosistab::ClientConfig::new(
        sosistab::Protocol::DirectUdp,
        server_addr,
        server_pk,
        stats_gatherer,
    )
    .pipe(|mut cfg| {
        cfg.shard_count = shard_count;
        cfg.reset_interval = Some(reset_interval);
        cfg
    })
}

pub fn sosistab_tcp(
    server_addr: SocketAddr,
    server_pk: x25519_dalek::PublicKey,
    shard_count: usize,
    reset_interval: Duration,
    stats_gatherer: Arc<sosistab::StatsGatherer>,
) -> sosistab::ClientConfig {
    sosistab::ClientConfig::new(
        sosistab::Protocol::DirectTcp,
        server_addr,
        server_pk,
        stats_gatherer,
    )
    .pipe(|mut cfg| {
        cfg.shard_count = shard_count;
        cfg.reset_interval = Some(reset_interval);
        cfg
    })
}

pub fn parse_independent_endpoint(
    endpoint: &str,
) -> anyhow::Result<(SocketAddr, x25519_dalek::PublicKey)> {
    // parse endpoint addr
    let pk_and_url = endpoint.split('@').collect::<Vec<_>>();
    let server_pk = x25519_dalek::PublicKey::from(
        <[u8; 32]>::try_from(
            hex::decode(&pk_and_url.get(0).context("URL not in form PK@host:port")?)
                .context("PK is not hex")?,
        )
        .unwrap(),
    );
    let server_addr: SocketAddr = pk_and_url
        .get(1)
        .context("URL not in form PK@host:port")?
        .parse()
        .context("cannot parse host:port")?;
    Ok((server_addr, server_pk))
}

pub async fn ipv4_addr_from_hostname(hostname: String) -> anyhow::Result<SocketAddr> {
    // eprintln!("getting ipv4 addr from hostname!");
    let res = geph4_aioutils::resolve(&format!("{}:19831", hostname))
        .await
        .context("can't resolve hostname of exit")?
        .into_iter()
        .find(|v| v.is_ipv4())
        .context("can't find ipv4 address for exit")?;

    Ok(res)
}

pub async fn get_session(
    ctx: TunnelCtx,
    bias_for: Option<SocketAddr>,
) -> anyhow::Result<ProtoSession> {
    match &ctx.endpoint {
        EndpointSource::Independent { endpoint } => {
            let (server_addr, server_pk) = parse_independent_endpoint(endpoint)?;
            Ok(ProtoSession {
                inner: if ctx.options.use_tcp {
                    sosistab_tcp(
                        server_addr,
                        server_pk,
                        ctx.options.tcp_shard_count,
                        Duration::from_secs(ctx.options.tcp_shard_lifetime),
                        ctx.tunnel_stats.stats_gatherer,
                    )
                    .connect()
                    .await?
                } else {
                    // We spam this several times in parallel and take the "worst".
                    const TRY_COUNT: usize = 5;
                    let mut racer = FuturesUnordered::new();

                    for _ in 0..TRY_COUNT {
                        let ctx = ctx.clone();
                        let udp_shard_count = ctx.options.udp_shard_count;
                        let udp_shard_lifetime = ctx.options.udp_shard_lifetime;

                        racer.push(async move {
                            Ok::<_, anyhow::Error>(
                                sosistab_udp(
                                    server_addr,
                                    server_pk,
                                    udp_shard_count,
                                    Duration::from_secs(udp_shard_lifetime),
                                    ctx.tunnel_stats.stats_gatherer,
                                )
                                .connect()
                                .await?,
                            )
                        });
                    }
                    for _ in 0..TRY_COUNT - 1 {
                        // throw away all except one
                        racer.next().await.expect("racer ran out")?;
                    }
                    racer.next().await.expect("racer ran out")?
                },
                remote_addr: server_addr,
            })
        }
        EndpointSource::Binder(binder_tunnel_params) => {
            let selected_exit = binder_tunnel_params
                .ccache
                .get_closest_exit(binder_tunnel_params.exit_server.clone())
                .await?;
            // eprintln!("GOT CLOSEST EXIT!");
            let bridge_sess_async =
                get_through_fastest_bridge(ctx.clone(), selected_exit.clone(), bias_for);

            let connected_sess_async = async {
                if binder_tunnel_params.use_bridges {
                    bridge_sess_async.await
                } else {
                    geph4_aioutils::try_race(
                        async {
                            let server_addr =
                                ipv4_addr_from_hostname(selected_exit.hostname.clone()).await?;
                            Ok(ProtoSession {
                                inner: get_one_sess(
                                    ctx.clone(),
                                    server_addr,
                                    selected_exit.sosistab_key,
                                )
                                .await?,
                                remote_addr: server_addr,
                            })
                        },
                        async {
                            smol::Timer::after(Duration::from_secs(1)).await;
                            log::warn!(
                                "racing with bridges because direct connection took a while"
                            );
                            bridge_sess_async.await
                        },
                    )
                    .await
                }
            };

            Ok(connected_sess_async
                .or(async {
                    smol::Timer::after(Duration::from_secs(40)).await;
                    anyhow::bail!("initial connection timeout after 40");
                })
                .await
                .tap(|x| {
                    if x.is_err() {
                        log::warn!("** purging bridges **");
                        let _ = binder_tunnel_params
                            .ccache
                            .purge_bridges(&selected_exit.hostname);
                    }
                })?)
        }
    }
}

/// Gets a session, given a context and a destination
pub async fn get_one_sess(
    ctx: TunnelCtx,
    addr: SocketAddr,
    pubkey: x25519_dalek::PublicKey,
) -> anyhow::Result<Session> {
    let ctx1 = ctx.clone();

    let tcp_fut = sosistab_tcp(
        addr,
        pubkey,
        ctx.options.tcp_shard_count,
        Duration::from_secs(ctx.options.tcp_shard_lifetime),
        ctx.tunnel_stats.stats_gatherer,
    )
    .connect();
    if !ctx.options.use_tcp {
        Ok(geph4_aioutils::try_race(
            async {
                let ctx = ctx1.clone();
                let sess = sosistab_udp(
                    addr,
                    pubkey,
                    ctx.options.udp_shard_count,
                    Duration::from_secs(ctx.options.udp_shard_lifetime),
                    ctx.tunnel_stats.stats_gatherer,
                )
                .connect()
                .await?;
                log::info!("connected to UDP for {}", addr);
                Ok(sess)
            }
            .boxed(),
            async {
                smol::Timer::after(Duration::from_secs(2)).await;
                log::warn!("switching to TCP for {}!", addr);
                tcp_fut.await
            }
            .boxed(),
        )
        .await?)
    } else {
        Ok(tcp_fut.await?)
    }
}

/// Obtain a session through bridges
pub async fn get_through_fastest_bridge(
    ctx: TunnelCtx,
    selected_exit: ExitDescriptor,
    privileged: Option<SocketAddr>,
) -> anyhow::Result<ProtoSession> {
    let ctx1 = ctx.clone();

    if let EndpointSource::Binder(binder_tunnel_params) = ctx.endpoint {
        let mut bridges = binder_tunnel_params
            .ccache
            .get_bridges(&selected_exit.hostname, binder_tunnel_params.sticky_bridges)
            .await
            .context("can't get bridges")?;
        log::debug!("got {} bridges", bridges.len());
        if let Some(force_bridge) = binder_tunnel_params.force_bridge {
            bridges.retain(|f| f.endpoint.ip() == force_bridge);
        }
        for bridge in bridges.iter() {
            log::debug!("> {}", bridge.endpoint);
        }
        if bridges.is_empty() {
            anyhow::bail!("absolutely no bridges found")
        }
        let start = Instant::now();
        // spawn a task for *every* bridge
        let mut bridge_futures = FuturesUnordered::new();
        for bridge in bridges.iter().cloned() {
            let fut = async {
                if let Some(privileged) = privileged {
                    if bridge.endpoint != privileged {
                        smol::Timer::after(Duration::from_millis(500)).await;
                    }
                }
                let conn = get_one_sess(ctx1.clone(), bridge.endpoint, bridge.sosistab_key)
                    .timeout(Duration::from_secs(20))
                    .await
                    .context(format!("connection timed out for {}", bridge.endpoint))?
                    .context(format!("connection failed for {}", bridge.endpoint))?;
                Ok::<_, anyhow::Error>((conn, bridge))
            };
            bridge_futures.push(fut);
        }
        // wait for a successful result
        while let Some(res) = bridge_futures.next().await {
            match res {
                Ok((res, bdesc)) => {
                    log::info!(
                        "found fastest bridge {} in {} ms",
                        bdesc.endpoint,
                        start.elapsed().as_millis()
                    );
                    return Ok(ProtoSession {
                        inner: res,
                        remote_addr: bdesc.endpoint,
                    });
                }
                Err(err) => {
                    log::warn!("a bridge failed: {:?}", err);
                }
            }
        }
        anyhow::bail!("all bridges failed")
    } else {
        anyhow::bail!("no bridges for connections independent of binder")
    }
}
