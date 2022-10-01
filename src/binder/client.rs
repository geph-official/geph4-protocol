use std::convert::TryInto;

use async_compat::CompatExt;
use async_trait::async_trait;
use nanorpc::{DynRpcTransport, RpcTransport};
use reqwest::header::{HeaderMap, HeaderName};

use super::protocol::BinderClient;

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
        let resp = self
            .client
            .post(&self.endpoint)
            .body(serde_json::to_vec(&req)?)
            .send()
            .compat()
            .await?;
        let resp = resp.bytes().compat().await?;
        Ok(serde_json::from_slice(&resp)?)
    }
}

impl E2eeHttpTransport {
    /// Creates a new E2eeHttpTransport instance.
    pub fn new(
        binder_lpk: x25519_dalek::PublicKey,
        endpoint: String,
        headers: Vec<(String, String)>,
    ) -> Self {
        Self {
            binder_lpk,
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
