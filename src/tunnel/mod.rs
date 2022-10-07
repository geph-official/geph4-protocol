use crate::{binder::client::CachedBinderClient, VpnMessage};

use smol::channel::{Receiver, Sender};
use sosistab::{RelConn, TimeSeries};
use std::{
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};
use tunnel_actor::tunnel_actor;
pub mod activity;
pub mod getsess;
pub mod protosess;
pub mod tunnel_actor;
pub use getsess::ipv4_addr_from_hostname;
use std::net::Ipv4Addr;

use self::activity::notify_activity;

#[derive(Clone)]
pub enum EndpointSource {
    Independent { endpoint: String },
    Binder(BinderTunnelParams),
}

#[derive(Clone)]
pub struct BinderTunnelParams {
    pub ccache: Arc<CachedBinderClient>,
    pub exit_server: Option<String>,
    pub use_bridges: bool,
    pub force_bridge: Option<Ipv4Addr>,
}

#[derive(Clone)]
pub struct TunnelStats {
    pub stats_gatherer: Arc<sosistab::StatsGatherer>,
    pub last_ping_ms: Arc<AtomicU32>,
}

#[derive(Clone, Copy)]
pub struct ConnectionOptions {
    pub udp_shard_count: usize,
    pub udp_shard_lifetime: u64,
    pub tcp_shard_count: usize,
    pub tcp_shard_lifetime: u64,
    pub use_tcp: bool,
}

#[derive(Clone)]
pub struct TunnelCtx {
    pub options: ConnectionOptions,
    pub endpoint: EndpointSource,
    pub recv_socks5_conn: Receiver<(String, Sender<sosistab::RelConn>)>,
    pub vpn_client_ip: Arc<AtomicU32>,
    pub tunnel_stats: TunnelStats,
    recv_vpn_outgoing: Receiver<VpnMessage>,
    send_vpn_incoming: Sender<VpnMessage>,
}

/// A tunnel starts and keeps alive the best sosistab session it can under given constraints.
/// A sosistab Session is *a single end-to-end connection between a client and a server.*
/// This can be thought of as analogous to TcpStream, except all reads and writes are datagram-based and unreliable.
pub struct ClientTunnel {
    endpoint: EndpointSource,
    client_ip_addr: Arc<AtomicU32>,

    send_vpn_outgoing: Sender<VpnMessage>,
    recv_vpn_incoming: Receiver<VpnMessage>,

    open_socks5_conn: Sender<(String, Sender<sosistab::RelConn>)>,
    tunnel_stats: TunnelStats,
    _task: Arc<smol::Task<anyhow::Result<()>>>,
}

impl ClientTunnel {
    pub fn new(options: ConnectionOptions, endpoint: EndpointSource) -> Self {
        let (send_socks5, recv_socks5) = smol::channel::unbounded();
        let (send_outgoing, recv_outgoing) = smol::channel::bounded(10000);
        let (send_incoming, recv_incoming) = smol::channel::bounded(10000);
        let current_state = Arc::new(AtomicU32::new(0));

        let stats_gatherer = Arc::new(sosistab::StatsGatherer::new_active());
        let last_ping_ms = Arc::new(AtomicU32::new(0));
        let tunnel_stats = TunnelStats {
            stats_gatherer,
            last_ping_ms,
        };
        let ctx = TunnelCtx {
            options,
            endpoint: endpoint.clone(),
            recv_socks5_conn: recv_socks5,
            vpn_client_ip: current_state.clone(),
            tunnel_stats: tunnel_stats.clone(),
            send_vpn_incoming: send_incoming,
            recv_vpn_outgoing: recv_outgoing,
        };
        let task = Arc::new(smolscale::spawn(tunnel_actor(ctx)));
        // let task = Arc::new(smolscale::spawn(smol::future::pending()));

        ClientTunnel {
            endpoint,
            client_ip_addr: current_state,
            send_vpn_outgoing: send_outgoing,
            recv_vpn_incoming: recv_incoming,
            open_socks5_conn: send_socks5,
            tunnel_stats,
            _task: task,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.client_ip_addr.load(Ordering::Relaxed) > 1
    }

    pub async fn connect(&self, remote: &str) -> anyhow::Result<RelConn> {
        let (send, recv) = smol::channel::bounded(1);
        self.open_socks5_conn
            .send((remote.to_string(), send))
            .await?;
        Ok(recv.recv().await?)
    }

    pub async fn send_vpn(&self, msg: VpnMessage) -> anyhow::Result<()> {
        notify_activity();
        self.send_vpn_outgoing.send(msg).await?;
        Ok(())
    }

    pub async fn recv_vpn(&self) -> anyhow::Result<VpnMessage> {
        let msg = self.recv_vpn_incoming.recv().await?;
        Ok(msg)
    }

    pub async fn get_vpn_client_ip(&self) -> Ipv4Addr {
        loop {
            let current_state = self.client_ip_addr.load(Ordering::Relaxed);
            if current_state == 0 {
                smol::Timer::after(Duration::from_millis(50)).await;
            } else {
                return Ipv4Addr::from(current_state);
            }
        }
    }

    pub fn get_endpoint(&self) -> EndpointSource {
        self.endpoint.clone()
    }

    pub async fn get_stats(&self) -> Stats {
        let gatherer = self.tunnel_stats.stats_gatherer.clone();

        Stats {
            sent_series: gatherer
                .get_timeseries("total_sent_bytes")
                .unwrap_or_default(),
            recv_series: gatherer
                .get_timeseries("total_sent_bytes")
                .unwrap_or_default(),
            loss_series: gatherer.get_timeseries("recv_loss").unwrap_or_default(),
            ping_series: gatherer.get_timeseries("smooth_ping").unwrap_or_default(),

            total_sent_bytes: gatherer.get_last("total_sent_bytes").unwrap_or_default(),
            total_recv_bytes: gatherer.get_last("total_recv_bytes").unwrap_or_default(),
            last_loss: gatherer.get_last("recv_loss").unwrap_or_default(),
            last_ping: self.tunnel_stats.last_ping_ms.load(Ordering::Relaxed) as f32,
        }
    }
}

pub struct Stats {
    pub sent_series: TimeSeries,
    pub recv_series: TimeSeries,
    pub loss_series: TimeSeries,
    pub ping_series: TimeSeries,

    pub total_sent_bytes: f32,
    pub total_recv_bytes: f32,
    pub last_loss: f32,
    pub last_ping: f32, // latency
}
