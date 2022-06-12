use crate::vpn::Vpn;
use parking_lot::RwLock;
use smol::{
    channel::{Receiver, Sender},
    future::FutureExt,
};
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
pub mod reroute;
pub mod tunnel_actor;
use crate::binder::CachedBinderClient;
pub use getsess::ipv4_addr_from_hostname;
use sosistab::Multiplex;
use std::net::Ipv4Addr;

#[derive(Clone)]
pub enum EndpointSource {
    Independent { endpoint: String },
    Binder(BinderTunnelParams),
}

#[derive(Clone)]
pub struct BinderTunnelParams {
    pub ccache: Arc<CachedBinderClient>,
    pub exit_server: String,
    pub use_bridges: bool,
    pub force_bridge: Option<Ipv4Addr>,
    pub sticky_bridges: bool,
}

#[derive(Clone)]
pub enum TunnelState {
    Connecting,
    Connected { mux: Arc<Multiplex> },
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
    pub current_state: Arc<RwLock<TunnelState>>,
    pub tunnel_stats: TunnelStats,
}

/// A tunnel starts and keeps alive the best sosistab session it can under given constraints.
/// A sosistab Session is *a single end-to-end connection between a client and a server.*
/// This can be thought of as analogous to TcpStream, except all reads and writes are datagram-based and unreliable.
pub struct ClientTunnel {
    endpoint: EndpointSource,
    current_state: Arc<RwLock<TunnelState>>,
    open_socks5_conn: Sender<(String, Sender<sosistab::RelConn>)>,
    tunnel_stats: TunnelStats,
    _task: Arc<smol::Task<anyhow::Result<()>>>,
}

impl ClientTunnel {
    pub async fn new(options: ConnectionOptions, endpoint: EndpointSource) -> anyhow::Result<Self> {
        let (send, recv) = smol::channel::unbounded();
        let current_state = Arc::new(RwLock::new(TunnelState::Connecting));

        let stats_gatherer = Arc::new(sosistab::StatsGatherer::new_active());
        let last_ping_ms = Arc::new(AtomicU32::new(0));
        let tunnel_stats = TunnelStats {
            stats_gatherer,
            last_ping_ms,
        };
        let ctx = TunnelCtx {
            options,
            endpoint: endpoint.clone(),
            recv_socks5_conn: recv,
            current_state: current_state.clone(),
            tunnel_stats: tunnel_stats.clone(),
        };
        let task = Arc::new(smolscale::spawn(tunnel_actor(ctx.clone())));
        // let task = Arc::new(smolscale::spawn(smol::future::pending()));

        Ok(ClientTunnel {
            endpoint,
            current_state: current_state.clone(),
            open_socks5_conn: send,
            tunnel_stats: tunnel_stats.clone(),
            _task: task,
        })
    }

    pub async fn connect(&self, remote: &str) -> anyhow::Result<RelConn> {
        let (send, recv) = smol::channel::bounded(1);
        self.open_socks5_conn
            .send((remote.to_string(), send))
            .await?;
        Ok(recv.recv().await?)
    }
    /// Returns a connected tunnel
    pub async fn return_connected(&self) -> anyhow::Result<()> {
        async {
            loop {
                match self.current_state().clone() {
                    TunnelState::Connecting => {
                        smol::Timer::after(Duration::from_secs(1)).await;
                    }
                    TunnelState::Connected { mux: _ } => return Ok(()),
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

    pub async fn start_vpn(&self) -> anyhow::Result<Vpn> {
        loop {
            match self.current_state() {
                TunnelState::Connecting => {
                    smol::Timer::after(Duration::from_secs(1)).await;
                }
                TunnelState::Connected { mux } => return Vpn::new(mux).await,
            }
        }
    }

    pub fn current_state(&self) -> TunnelState {
        self.current_state.read().clone()
    }

    pub fn is_connected(&self) -> bool {
        match self.current_state() {
            TunnelState::Connecting => false,
            TunnelState::Connected { mux: _ } => true,
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
