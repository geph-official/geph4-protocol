use std::{convert::TryInto, time::Duration};

use async_compat::CompatExt;
use async_trait::async_trait;

use nanorpc::RpcTransport;

use reqwest::{
    header::{HeaderMap, HeaderName},
    StatusCode,
};

use super::protocol::{box_decrypt, box_encrypt};

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
        let eph_sk = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
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
                .no_proxy()
                .http1_only()
                .pool_idle_timeout(Duration::from_secs(1)) // reduce linkability by forcing new connections
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
