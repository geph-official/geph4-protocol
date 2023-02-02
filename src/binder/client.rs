use std::{
    convert::TryInto,
    time::{Duration, SystemTime},
};

use anyhow::Context;
use async_compat::CompatExt;
use async_trait::async_trait;
use bytes::Bytes;

use nanorpc::{DynRpcTransport, RpcTransport};
use rand::{seq::SliceRandom, Rng};
use reqwest::{
    header::{HeaderMap, HeaderName},
    StatusCode,
};
use smol_str::SmolStr;

use super::protocol::{
    box_decrypt, box_encrypt, AuthError, AuthRequest, AuthResponse, BinderClient, BlindToken,
    BridgeDescriptor, ExitDescriptor, Level, MasterSummary, UserInfo,
};

/// A caching, intelligent binder client, generic over the precise mechanism used for caching.
#[allow(clippy::type_complexity)]
pub struct CachedBinderClient {
    load_cache: Box<dyn Fn(&str) -> Option<Bytes> + Send + Sync + 'static>,
    save_cache: Box<dyn Fn(&str, &[u8], Duration) + Send + Sync + 'static>,

    inner: DynBinderClient,
    username: SmolStr,
    password: SmolStr,
}

impl CachedBinderClient {
    /// Creates a new cached BinderClient, given closures used to load and save from the cache.
    pub fn new(
        load_cache: impl Fn(&str) -> Option<Bytes> + Send + Sync + 'static,
        save_cache: impl Fn(&str, &[u8], Duration) + Send + Sync + 'static,
        inner: DynBinderClient,
        username: &str,
        password: &str,
    ) -> Self {
        Self {
            load_cache: Box::new(load_cache),
            save_cache: Box::new(save_cache),
            inner,
            username: username.into(),
            password: password.into(),
        }
    }

    /// Obtains the overall network summary.
    pub async fn get_summary(&self) -> anyhow::Result<MasterSummary> {
        if let Some(summary) = (self.load_cache)("summary") {
            if let Ok(summary) = serde_json::from_slice(&summary) {
                return Ok(summary);
            }
        }
        // load from the network
        let summary = self.inner.get_summary().await?;
        (self.save_cache)(
            "summary",
            &serde_json::to_vec(&summary)?,
            Duration::from_secs(3600),
        );
        Ok(summary)
    }

    /// A helper function for obtaining the closest exit.
    pub async fn get_closest_exit(&self, destination_exit: &str) -> anyhow::Result<ExitDescriptor> {
        let token = self.get_auth_token().await?.1;
        let summary = self.get_summary().await?;
        let mut exits = summary.exits;
        exits.retain(|e| e.allowed_levels.contains(&token.level));
        // shuffle exits
        exits.shuffle(&mut rand::thread_rng());
        // sort exits by similarity to request and returns most similar
        exits.sort_by(|a, b| {
            strsim::damerau_levenshtein(&a.hostname, destination_exit)
                .cmp(&strsim::damerau_levenshtein(&b.hostname, destination_exit))
        });
        exits.get(0).cloned().context("no exits found at all lol")
    }

    /// A function for obtaining a list of bridges.
    pub async fn get_bridges(
        &self,
        destination_exit: &str,
        force_fresh: bool,
    ) -> anyhow::Result<Vec<BridgeDescriptor>> {
        let bridge_key = format!("bridges {}", destination_exit);
        let auth = self.get_auth_token().await?.1;
        if !force_fresh {
            if let Some(bridges) = (self.load_cache)(&bridge_key) {
                if let Ok(bridges) = serde_json::from_slice(&bridges) {
                    return Ok(bridges);
                }
            }
        }
        let bridges = self
            .inner
            .get_bridges(auth, destination_exit.into())
            .await?;
        (self.save_cache)(
            &bridge_key,
            &serde_json::to_vec(&bridges)?,
            Duration::from_secs(600),
        );
        Ok(bridges)
    }

    /// A function for obtaining a list of v2 bridges.
    pub async fn get_bridges_v2(
        &self,
        destination_exit: &str,
        force_fresh: bool,
    ) -> anyhow::Result<Vec<BridgeDescriptor>> {
        let bridge_key = format!("bridgesv2 {}", destination_exit);
        let auth = self.get_auth_token().await?.1;
        if !force_fresh {
            if let Some(bridges) = (self.load_cache)(&bridge_key) {
                if let Ok(bridges) = serde_json::from_slice(&bridges) {
                    return Ok(bridges);
                }
            }
        }
        let bridges = self
            .inner
            .get_bridges_v2(auth, destination_exit.into())
            .await?;
        (self.save_cache)(
            &bridge_key,
            &serde_json::to_vec(&bridges)?,
            Duration::from_secs(600),
        );
        Ok(bridges)
    }

    /// Obtains an authentication token.
    pub async fn get_auth_token(&self) -> anyhow::Result<(UserInfo, BlindToken)> {
        if let Some(auth_token) = (self.load_cache)("auth_token") {
            if let Ok(auth_token) = serde_json::from_slice(&auth_token) {
                return Ok(auth_token);
            }
        }
        let digest: [u8; 32] = rand::thread_rng().gen();
        for level in [Level::Free, Level::Plus] {
            let mizaru_pk = self.get_mizaru_pk(level).await?;
            let epoch = mizaru::time_to_epoch(SystemTime::now()) as u16;
            let subkey = self.inner.get_mizaru_epoch_key(level, epoch).await?;
            let digest = rsa_fdh::blind::hash_message::<sha2::Sha256, _>(&subkey, &digest).unwrap();
            let (blinded_digest, unblinder) =
                rsa_fdh::blind::blind(&mut rand::thread_rng(), &subkey, &digest);
            let resp: AuthResponse = match self
                .inner
                .authenticate(AuthRequest {
                    username: self.username.clone(),
                    password: self.password.clone(),
                    level,
                    epoch,
                    blinded_digest: blinded_digest.into(),
                })
                .await?
            {
                Err(AuthError::WrongLevel) => continue,
                x => x?,
            };
            let blind_signature: mizaru::BlindedSignature =
                bincode::deserialize(&resp.blind_signature_bincode)?;
            let unblinded_signature = blind_signature.unblind(&unblinder);
            if unblinded_signature.epoch != epoch as usize
                || !mizaru_pk.blind_verify(&digest, &unblinded_signature)
            {
                anyhow::bail!("an invalid signature was given by the binder")
            }
            let tok = BlindToken {
                level,
                unblinded_digest: digest.into(),
                unblinded_signature_bincode: bincode::serialize(&unblinded_signature)?.into(),
                version: std::env::var("GEPH_VERSION").ok().map(|s| s.into()),
            };
            (self.save_cache)(
                "auth_token",
                &serde_json::to_vec(&(&resp.user_info, &tok))?,
                Duration::from_secs(86400),
            );
            return Ok((resp.user_info, tok));
        }
        todo!()
        // Ok(token)
    }

    /// Obtains the long-term Mizaru public key of a level.
    async fn get_mizaru_pk(&self, level: Level) -> anyhow::Result<mizaru::PublicKey> {
        let k = format!("mizaru_pk_{:?}", level);
        if let Some(pk) = (self.load_cache)(&k) {
            if let Ok(pk) = serde_json::from_slice(&pk) {
                return Ok(pk);
            }
        }
        let pk = self.inner.get_mizaru_pk(level).await?;
        (self.save_cache)(
            &k,
            &serde_json::to_vec(&pk)?,
            Duration::from_secs(1_000_000),
        );
        Ok(pk)
    }
}

/// A "dynamically typed" binder client that doesn't expose the exact underlying transport.
pub type DynBinderClient = BinderClient<DynRpcTransport>;

/// An end-to-end encrypted, HTTP-based RpcTransport implementation. This is used as the main backend for communicating over domain fronting and other systems that hit a particular HTTP endpoint with a particular set of headers.
pub struct E2eeHttpTransport {
    binder_lpk: x25519_dalek::PublicKey,
    endpoint: String,
    client: reqwest::Client,
}

#[async_trait]
impl RpcTransport for E2eeHttpTransport {
    type Error = anyhow::Error;

    async fn call_raw(
        &self,
        req: nanorpc::JrpcRequest,
    ) -> Result<nanorpc::JrpcResponse, Self::Error> {
        let eph_sk = x25519_dalek::StaticSecret::new(rand::thread_rng());
        let encrypted_req =
            box_encrypt(&serde_json::to_vec(&req)?, eph_sk.clone(), self.binder_lpk);
        let resp = self
            .client
            .post(&self.endpoint)
            .body(encrypted_req)
            .send()
            .compat()
            .await?;
        if resp.status() != StatusCode::OK {
            anyhow::bail!("non-200 status: {}", resp.status());
        }
        let encrypted_resp = resp.bytes().compat().await?;
        let (resp, _) = box_decrypt(&encrypted_resp, eph_sk)?;
        Ok(serde_json::from_slice(&resp)?)
    }
}

impl E2eeHttpTransport {
    /// Creates a new E2eeHttpTransport instance.
    pub fn new(binder_lpk: [u8; 32], endpoint: String, headers: Vec<(String, String)>) -> Self {
        Self {
            binder_lpk: x25519_dalek::PublicKey::from(binder_lpk),
            endpoint,
            client: reqwest::ClientBuilder::new()
                .default_headers({
                    let mut hh = HeaderMap::new();
                    for (k, v) in headers {
                        hh.insert::<HeaderName>(
                            k.to_ascii_lowercase().try_into().unwrap(),
                            v.to_ascii_lowercase().parse().unwrap(),
                        );
                    }
                    hh
                })
                .build()
                .unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use async_compat::CompatExt;
    use reqwest::header::HeaderMap;

    #[test]
    fn reqwest_domain_front() {
        smolscale::block_on(
            async move {
                let client = reqwest::ClientBuilder::new()
                    .default_headers({
                        let mut hh = HeaderMap::new();
                        hh.insert("host", "loving-bell-981479.netlify.app".parse().unwrap());
                        hh
                    })
                    .build()
                    .unwrap();
                let resp = client
                    .get("https://www.netlify.com/v4")
                    .send()
                    .await
                    .unwrap();
                dbg!(resp);
            }
            .compat(),
        );
    }
}
