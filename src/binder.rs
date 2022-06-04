use acidjson::AcidJson;
use anyhow::Context;
use bytes::Bytes;
use futures_util::Future;
use geph4_binder_transport::{
    BinderClient, BinderError, BinderRequestData, BinderResponse, BridgeDescriptor, ExitDescriptor,
    UserInfo,
};
use http_types::{convert::DeserializeOwned, Method, Request, Response};
use rand::Rng;
use rsa_fdh::blind;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use smol::future::FutureExt;
use smol_timeout::TimeoutExt;
use std::{
    collections::BTreeMap,
    fmt::Debug,
    str::from_utf8,
    sync::Arc,
    time::{Duration, SystemTime},
};

static STALE_TIMEOUT: Duration = Duration::from_secs(3);
static NETWORK_TIMEOUT: Duration = Duration::from_secs(120);
const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub user_info: geph4_binder_transport::UserInfo,
    pub level: String,
    pub epoch: u16,
    pub unblinded_digest: Vec<u8>,
    pub unblinded_signature: mizaru::UnblindedSignature,
}

#[derive(Clone)]
pub struct NetworkSummary {
    pub user_info: UserInfo,
    pub exits: Vec<ExitDescriptor>,
    pub exits_free: Vec<ExitDescriptor>,
}

pub trait Cache: Send + Sync {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
    fn insert(&self, key: Vec<u8>, value: Vec<u8>);
    fn remove(&self, key: &[u8]);
    fn clear_all(&self);
}

pub struct CachedBinderClient {
    pub username: String,
    pub password: String,
    pub free_pk: mizaru::PublicKey,
    pub plus_pk: mizaru::PublicKey,
    pub binder_client: Arc<dyn BinderClient>,
    pub ccache: Arc<dyn Cache>,
}

#[derive(Clone)]
pub struct BinderParams {
    pub underlying: Arc<dyn BinderClient + 'static>,
    pub cache: Arc<dyn Cache + 'static>,
    pub binder_mizaru_free_pk: mizaru::PublicKey,
    pub binder_mizaru_plus_pk: mizaru::PublicKey,
    pub username: String,
    pub password: String,
}

// public methods
impl CachedBinderClient {
    pub fn new(params: BinderParams) -> Self {
        CachedBinderClient {
            username: params.username,
            password: params.password,
            free_pk: params.binder_mizaru_free_pk,
            plus_pk: params.binder_mizaru_plus_pk,
            binder_client: params.underlying.clone(),
            ccache: params.cache.clone(),
        }
    }

    pub async fn sync(&self, force: bool) -> anyhow::Result<NetworkSummary> {
        if force {
            self.purge_all()?;
        }
        let exec = smol::Executor::new();
        let atok = self.get_auth_token().await?;
        let exits = exec.spawn(self.get_exits());
        let exits_free = exec.spawn(self.get_free_exits());
        exec.run(async move {
            let ns = NetworkSummary {
                user_info: atok.user_info,
                exits: exits.await?,
                exits_free: exits_free.await?,
            };
            Ok(ns)
        })
        .await
    }

    pub async fn get_closest_exit(
        &self,
        destination_exit: String,
    ) -> anyhow::Result<ExitDescriptor> {
        // find the exit
        let mut exits = self.get_exits().await.context("can't get exits")?;
        if exits.is_empty() {
            anyhow::bail!("no exits found")
        }
        // sort exits by similarity to request and returns most similar
        exits.sort_by(|a, b| {
            strsim::damerau_levenshtein(&a.hostname, &destination_exit)
                .cmp(&strsim::damerau_levenshtein(&b.hostname, &destination_exit))
        });
        Ok(exits[0].clone())
    }

    /// Gets a list of exits.
    pub async fn get_exits(&self) -> anyhow::Result<Vec<ExitDescriptor>> {
        self.get_cached_maybe_stale(
            "cache.exits",
            self.get_exits_fresh(),
            Duration::from_secs(3600),
        )
        .await
    }

    /// Gets a list of free exits.
    pub async fn get_free_exits(&self) -> anyhow::Result<Vec<ExitDescriptor>> {
        self.get_cached_maybe_stale(
            "cache.freeexits",
            self.get_free_exits_fresh(),
            Duration::from_secs(3600),
        )
        .await
    }

    /// Gets a list of bridges.
    pub async fn get_bridges(
        &self,
        exit_hostname: &str,
        sticky_bridges: bool,
    ) -> anyhow::Result<Vec<BridgeDescriptor>> {
        let tok = self.get_auth_token().await?;
        let binder_client = self.binder_client.clone();
        let exit_hostname = exit_hostname.to_string();
        if sticky_bridges {
            let res = self.get_cached_stale(&format!("cache.bridges.{}", exit_hostname));
            match res {
                Some(bridges) => Ok(bridges),
                None => anyhow::bail!("no bridges!!!"),
            }
        } else {
            self.get_cached_maybe_stale(
                &format!("cache.bridges.{}", exit_hostname),
                async {
                    let res = timeout(binder_client.request(BinderRequestData::GetBridges {
                        level: tok.level,
                        unblinded_digest: tok.unblinded_digest,
                        unblinded_signature: tok.unblinded_signature,
                        exit_hostname,
                    }))
                    .await??;
                    if let BinderResponse::GetBridgesResp(bridges) = res {
                        Ok(bridges)
                    } else {
                        anyhow::bail!("invalid response")
                    }
                },
                Duration::from_secs(300),
            )
            .await
        }
    }

    pub async fn get_current_bridges(&self, exit_hostname: &str) -> Option<Vec<BridgeDescriptor>> {
        let exit_hostname = exit_hostname.to_string();
        self.get_cached_stale(&format!("cache.bridges.{}", exit_hostname))
    }

    /// obtains a new token.
    pub async fn get_auth_token(&self) -> anyhow::Result<Token> {
        // this CANNOT be stale!
        self.get_cached(
            "cache.auth_token",
            self.get_token_fresh(),
            Duration::from_secs(86400),
        )
        .await
    }

    /// Clears the bridge list. This should be called when a connection error happens, so that bad bridge lists are purged as fast as possible.
    pub fn purge_bridges(&self, exit_hostname: &str) -> anyhow::Result<()> {
        let key = self.to_key(&format!("cache.bridges.{}", exit_hostname));
        self.ccache.remove(&key);
        Ok(())
    }

    /// clears everything
    pub fn purge_all(&self) -> anyhow::Result<()> {
        self.ccache.clear_all();
        Ok(())
    }
}

// private methods
impl CachedBinderClient {
    async fn get_token_fresh(&self) -> anyhow::Result<Token> {
        let digest: [u8; 32] = rand::thread_rng().gen();
        for level in &["plus", "free"] {
            let mizaru_pk = if level == &"plus" {
                &self.plus_pk
            } else {
                &self.free_pk
            };
            let epoch = mizaru::time_to_epoch(SystemTime::now()) as u16;
            let binder_client = self.binder_client.clone();
            let subkey = timeout(binder_client.request(BinderRequestData::GetEpochKey {
                level: level.to_string(),
                epoch,
            }))
            .await??;
            if let BinderResponse::GetEpochKeyResp(subkey) = subkey {
                // create FDH
                let digest = blind::hash_message::<Sha256, _>(&subkey, &digest).unwrap();
                // blinding
                let (blinded_digest, unblinder) =
                    blind::blind(&mut rand::thread_rng(), &subkey, &digest);
                let binder_client = self.binder_client.clone();
                let username = self.username.clone();
                let password = self.password.clone();
                let resp = timeout(binder_client.request(BinderRequestData::Authenticate {
                    username,
                    password,
                    level: level.to_string(),
                    epoch,
                    blinded_digest,
                }))
                .await?;
                match resp {
                    Ok(BinderResponse::AuthenticateResp {
                        user_info,
                        blind_signature,
                    }) => {
                        let unblinded_signature = blind_signature.unblind(&unblinder);
                        if !mizaru_pk.blind_verify(&digest, &unblinded_signature) {
                            anyhow::bail!("an invalid signature was given by the binder")
                        }
                        return Ok(Token {
                            user_info,
                            level: level.to_string(),
                            epoch,
                            unblinded_digest: digest.to_vec(),
                            unblinded_signature,
                        });
                    }
                    Err(BinderError::WrongLevel) => continue,
                    Err(e) => return Err(e.into()),
                    _ => continue,
                }
            }
        }
        anyhow::bail!("neither plus nor free worked");
    }

    async fn get_exits_fresh(&self) -> anyhow::Result<Vec<ExitDescriptor>> {
        let binder_client = self.binder_client.clone();
        let res = timeout(binder_client.request(BinderRequestData::GetExits)).await??;
        match res {
            geph4_binder_transport::BinderResponse::GetExitsResp(exits) => Ok(exits),
            other => anyhow::bail!("unexpected response {:?}", other),
        }
    }

    async fn get_free_exits_fresh(&self) -> anyhow::Result<Vec<ExitDescriptor>> {
        let binder_client = self.binder_client.clone();
        let res = timeout(binder_client.request(BinderRequestData::GetFreeExits)).await??;
        match res {
            geph4_binder_transport::BinderResponse::GetExitsResp(exits) => Ok(exits),
            other => anyhow::bail!("unexpected response {:?}", other),
        }
    }

    fn get_cached_stale<T: DeserializeOwned + Clone + Debug>(&self, key: &str) -> Option<T> {
        let key = self.to_key(key);
        let existing: Option<(T, u64)> = self
            .ccache
            .get(&key)
            .map(|v| bincode::deserialize(&v).unwrap());
        existing.map(|v| v.0)
    }

    async fn get_cached_maybe_stale<T: Serialize + DeserializeOwned + Clone + std::fmt::Debug>(
        &self,
        key: &str,
        fallback: impl Future<Output = anyhow::Result<T>>,
        ttl: Duration,
    ) -> anyhow::Result<T> {
        self.get_cached(key, fallback, ttl)
            .or(async {
                smol::Timer::after(STALE_TIMEOUT).await;
                if let Some(val) = self.get_cached_stale(key) {
                    log::warn!("falling back to possibly stale value for {}", key);
                    Ok(val)
                } else {
                    log::warn!("no stale value available");
                    smol::future::pending().await
                }
            })
            .await
    }

    async fn get_cached<T: Serialize + DeserializeOwned + Clone + std::fmt::Debug>(
        &self,
        key: &str,
        fallback: impl Future<Output = anyhow::Result<T>>,
        ttl: Duration,
    ) -> anyhow::Result<T> {
        let expanded_key = self.to_key(key);
        let existing: Option<(T, u64)> = self
            .ccache
            .get(&expanded_key)
            .map(|v| bincode::deserialize(v.as_slice()).unwrap());
        if let Some((existing, create_time)) = existing {
            if SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                < create_time + ttl.as_secs()
            {
                return Ok(existing);
            } else {
                log::warn!("ignore stale value for {} created at {}", key, create_time);
            }
        } else {
            log::warn!("absent key {}", key);
        }
        let create_time: SystemTime = SystemTime::now();
        let create_time = create_time
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        log::debug!("refreshing from binder for {}", key);
        let fresh = fallback.await?;
        log::trace!(
            "fallback resolved for {}! ({:?})",
            from_utf8(&expanded_key)?,
            fresh
        );

        // save to disk
        self.ccache.insert(
            expanded_key.to_vec(),
            bincode::serialize(&(fresh.clone(), create_time))
                .unwrap()
                .into(),
        );
        log::trace!("about to return for {}!", from_utf8(&expanded_key)?);
        Ok(fresh)
    }

    fn to_key(&self, key: &str) -> Vec<u8> {
        format!("{}-{}", key, self.username).as_bytes().to_vec()
    }
}

async fn timeout<T, F: Future<Output = T>>(fut: F) -> anyhow::Result<T> {
    fut.timeout(NETWORK_TIMEOUT)
        .await
        .ok_or_else(|| anyhow::anyhow!("timeout"))
}

impl Cache for AcidJson<BTreeMap<String, Bytes>> {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        todo!()
    }

    fn insert(&self, key: Vec<u8>, value: Vec<u8>) {
        todo!()
    }

    fn remove(&self, key: &[u8]) {
        todo!()
    }

    fn clear_all(&self) {
        todo!()
    }
}
