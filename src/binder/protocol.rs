use arrayref::array_ref;
use async_trait::async_trait;
use bytes::Bytes;
use chacha20poly1305::{
    aead::{Aead, NewAead},
    ChaCha20Poly1305, Nonce,
};
use nanorpc::{nanorpc_derive, JrpcRequest, JrpcResponse};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smol_str::SmolStr;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};
use stdcode::StdcodeSerializeExt;
use thiserror::Error;
use tmelcrypt::{Ed25519PK, Ed25519SK};

const PUBKEY_AUTH_COOKIE: &[u8; 32] = b"gephauth001---------------------";

/// Verifies a signature for the pubkey authentication method used by the client/binder protocol.
pub fn verify_pk_auth(pk: Ed25519PK, unix_secs: u64, sig: &[u8]) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now.abs_diff(unix_secs) > 600 {
        return false;
    }
    pk.verify(
        blake3::keyed_hash(PUBKEY_AUTH_COOKIE, &unix_secs.to_be_bytes()).as_bytes(),
        sig,
    )
}

/// Encrypts a message, "box-style", to a destination diffie-hellman public key.
pub fn box_encrypt(
    plain: &[u8],
    my_sk: x25519_dalek::StaticSecret,
    their_pk: x25519_dalek::PublicKey,
) -> Bytes {
    let my_pk = x25519_dalek::PublicKey::from(&my_sk);
    let shared_secret = my_sk.diffie_hellman(&their_pk);
    // we key to *their pk* to ensure that our message, reflected back, cannot be misinterpreted as a valid message addressed to us (e.g. as a response)
    let key = blake3::keyed_hash(
        blake3::hash(their_pk.as_bytes()).as_bytes(),
        shared_secret.as_bytes(),
    );
    let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&[0u8; 12]), plain)
        .unwrap();
    let mut pk_and_ctext = Vec::with_capacity(ciphertext.len() + 32);
    pk_and_ctext.extend_from_slice(my_pk.as_bytes());
    pk_and_ctext.extend_from_slice(&ciphertext);
    pk_and_ctext.into()
}

/// Decrypts a message, "box-style", given our diffie-hellman secret key. Returns both the other side's public key and the plaintext.
pub fn box_decrypt(
    ctext: &[u8],
    my_sk: x25519_dalek::StaticSecret,
) -> Result<(Bytes, x25519_dalek::PublicKey), BoxDecryptError> {
    if ctext.len() < 32 {
        return Err(BoxDecryptError::BadFormat);
    }
    let their_pk = x25519_dalek::PublicKey::from(*array_ref![ctext, 0, 32]);
    let shared_secret = my_sk.diffie_hellman(&their_pk);
    // we use *our pk* as the key
    let my_pk = x25519_dalek::PublicKey::from(&my_sk);
    let key = blake3::keyed_hash(
        blake3::hash(my_pk.as_bytes()).as_bytes(),
        shared_secret.as_bytes(),
    );
    let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
    let plain = cipher
        .decrypt(Nonce::from_slice(&[0u8; 12]), &ctext[32..])
        .map_err(|_| BoxDecryptError::DecryptionFailed)?;
    Ok((plain.into(), their_pk))
}

/// Authentication error
#[derive(Error, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BoxDecryptError {
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("badly formatted message")]
    BadFormat,
}

#[derive(Error, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RpcError {
    #[error("error retreiving bootstrap routes")]
    BootstrapFailed,
    #[error("error connecting to melnode")]
    ConnectFailed,
    #[error("error communicating with melnode")]
    CommFailed,
}

#[nanorpc_derive]
#[async_trait]
pub trait BinderProtocol {
    /// Authenticates a 24-hour-long session for a user.
    /// NOTE: This is a legacy method, and will be deprecated later.
    async fn authenticate(&self, auth_req: AuthRequest) -> Result<AuthResponse, AuthError>;

    /// Authenticates a 24-hour-long session for a user.
    async fn authenticate_v2(&self, auth_req: AuthRequestV2) -> Result<AuthResponseV2, AuthError>;

    /// Retrieves a login url
    async fn get_login_url(&self, credentials: Credentials) -> Result<String, AuthError>;

    /// Validates a blind signature token, applying rate-limiting as appropriate
    async fn validate(&self, token: BlindToken) -> bool;

    /// Obtains a unique captcha, for user registry.
    async fn get_captcha(&self) -> Result<Captcha, MiscFatalError>;

    /// Registers a new user.
    /// NOTE: This is a legacy method, and will be deprecated later.
    async fn register_user(
        &self,
        username: SmolStr,
        password: SmolStr,
        captcha_id: SmolStr,
        captcha_soln: SmolStr,
    ) -> Result<(), RegisterError>;

    /// Registers a new user.
    async fn register_user_v2(
        &self,
        credentials: Credentials,
        captcha_id: SmolStr,
        captcha_soln: SmolStr,
    ) -> Result<(), RegisterError>;

    /// Deletes a user.
    /// NOTE: This is a legacy method, and will be deprecated later.
    async fn delete_user(&self, username: SmolStr, password: SmolStr) -> Result<(), AuthError>;

    /// Deletes a user.
    async fn delete_user_v2(&self, credentials: Credentials) -> Result<(), AuthError>;

    /// Adds a bridge route.
    async fn add_bridge_route(&self, descriptor: BridgeDescriptor) -> Result<(), MiscFatalError>;

    /// Obtains the master summary of the network state.
    async fn get_summary(&self) -> MasterSummary;

    /// Obtains a list of bridges.
    async fn get_bridges(&self, token: BlindToken, exit: SmolStr) -> Vec<BridgeDescriptor>;

    /// Obtains a list of bridges, limited to sosistab2.
    async fn get_bridges_v2(&self, token: BlindToken, exit: SmolStr) -> Vec<BridgeDescriptor>;

    /// Obtains the Mizaru long-term key.
    async fn get_mizaru_pk(&self, level: Level) -> mizaru::PublicKey;

    /// Obtains a Mizaru epoch key.
    async fn get_mizaru_epoch_key(&self, level: Level, epoch: u16) -> rsa::RSAPublicKey;

    /// Obtains recent announcements, as a string containing an RSS feed.
    async fn get_announcements(&self) -> String;

    /// Reverse proxies requests to melnode
    async fn reverse_proxy_melnode(&self, req: JrpcRequest) -> Result<JrpcResponse, RpcError>;

    /// Adds a specific metric datapoint to the db
    async fn add_metric(&self, session: i64, data: serde_json::Value)
        -> Result<(), MiscFatalError>;
}

/// Authentication request
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug, Hash, Eq, PartialEq)]
pub struct AuthRequest {
    pub username: SmolStr,
    pub password: SmolStr,
    pub level: Level,
    pub epoch: u16,
    #[serde_as(as = "serde_with::base64::Base64")]
    pub blinded_digest: Bytes,
}

/// Authentication request generic over authentication type
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug, Hash, Eq, PartialEq)]
pub struct AuthRequestV2 {
    pub credentials: Credentials,
    pub level: Level,
    pub epoch: u16,
    #[serde_as(as = "serde_with::base64::Base64")]
    pub blinded_digest: Bytes,
}

/// The different authentications methods available in AuthRequestV2
#[derive(Serialize, Deserialize, Clone, Debug, Hash, Eq, PartialEq)]
pub enum Credentials {
    Password {
        username: SmolStr,
        password: SmolStr,
    },
    Signature {
        pubkey: Ed25519PK,
        unix_secs: u64,
        signature: Vec<u8>,
    },
}

impl Credentials {
    /// Signs a new keypair credential, valid for the next 10 minutes, given a secret key.
    pub fn new_keypair(my_sk: &Ed25519SK) -> Self {
        let unix_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let to_sign = blake3::keyed_hash(PUBKEY_AUTH_COOKIE, &unix_secs.to_be_bytes());
        Credentials::Signature {
            pubkey: my_sk.to_public(),
            unix_secs,
            signature: my_sk.sign(to_sign.as_bytes()),
        }
    }
}

/// Authentication response
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug, Hash, Eq, PartialEq)]
pub struct AuthResponse {
    pub user_info: UserInfo,
    #[serde_as(as = "serde_with::base64::Base64")]
    pub blind_signature_bincode: Bytes,
}

/// Authentication response v2
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug, Hash, Eq, PartialEq)]
pub struct AuthResponseV2 {
    pub user_info: UserInfoV2,
    #[serde_as(as = "serde_with::base64::Base64")]
    pub blind_signature_bincode: Bytes,
}

/// Authentication error
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("too many requests")]
    TooManyRequests,
    #[error("level wrong")]
    WrongLevel,
    #[error("other error: {0}")]
    Other(SmolStr),
}

/// Registration error
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum RegisterError {
    #[error("duplicate credentials")]
    DuplicateCredentials,
    #[error("other error: {0}")]
    Other(SmolStr),
}

/// Information for a particular user
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct UserInfo {
    pub userid: i32,
    pub username: SmolStr,
    pub subscription: Option<SubscriptionInfo>,
}

/// Information for a particular user v2
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct UserInfoV2 {
    pub userid: i32,
    pub subscription: Option<SubscriptionInfo>,
}

/// Information about a user's subscription
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SubscriptionInfo {
    pub level: Level,
    pub expires_unix: i64,
}

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum Level {
    Free,
    Plus,
}

/// A "blind token" that is either valid or not.
#[serde_as]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Hash)]
pub struct BlindToken {
    pub level: Level,
    #[serde_as(as = "serde_with::base64::Base64")]
    pub unblinded_digest: Bytes,
    #[serde_as(as = "serde_with::base64::Base64")]
    pub unblinded_signature_bincode: Bytes,

    #[serde(default)]
    pub version: Option<SmolStr>,
}

/// A captcha.
#[serde_as]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Hash)]
pub struct Captcha {
    pub captcha_id: SmolStr,
    #[serde_as(as = "serde_with::base64::Base64")]
    pub png_data: Bytes,
}

/// A miscellaneous, "dynamically typed" fatal error
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum MiscFatalError {
    #[error("database error: {0}")]
    Database(SmolStr),
    #[error("backend network error: {0}")]
    BadNet(SmolStr),
}

/// Bridge descriptor
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct BridgeDescriptor {
    pub is_direct: bool,
    pub protocol: SmolStr,
    pub endpoint: SocketAddr,
    #[serde(rename = "sosistab_key")]
    pub cookie: Bytes,
    pub exit_hostname: SmolStr,
    pub alloc_group: SmolStr,
    pub update_time: u64,
    pub exit_signature: Bytes,
}

/// Exit descriptor
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExitDescriptor {
    pub hostname: SmolStr,
    pub signing_key: ed25519_dalek::PublicKey,
    pub country_code: SmolStr,
    pub city_code: SmolStr,
    pub direct_routes: Vec<BridgeDescriptor>,
    #[serde(rename = "legacy_direct_sosistab_pk")]
    pub sosistab_e2e_pk: x25519_dalek::PublicKey,
    pub allowed_levels: Vec<Level>,
    pub load: f64,
}

/// Master summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MasterSummary {
    pub exits: Vec<ExitDescriptor>,
    pub bad_countries: Vec<SmolStr>,
}

impl MasterSummary {
    /// Gets a hash of the [`MasterSummary`].
    /// This clears out dynamically changing fields like `load` and `direct_route` in each exit descriptor before hashing.
    pub fn clean_hash(&self) -> blake3::Hash {
        let mut exit_tree: BTreeMap<String, (Vec<u8>, Vec<u8>)> = BTreeMap::new();

        for exit in &self.exits {
            exit_tree.insert(
                exit.hostname.clone().into(),
                (
                    exit.signing_key.as_bytes().to_vec(),
                    exit.sosistab_e2e_pk.as_bytes().to_vec(),
                ),
            );
        }

        blake3::hash(&exit_tree.stdcode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn box_encryption() {
        let test_string = b"hello world";
        let alice_sk = x25519_dalek::StaticSecret::new(rand::thread_rng());
        let alice_pk = x25519_dalek::PublicKey::from(&alice_sk);
        let bob_sk = x25519_dalek::StaticSecret::new(rand::thread_rng());
        let bob_pk = x25519_dalek::PublicKey::from(&bob_sk);
        let encrypted = box_encrypt(test_string, alice_sk, bob_pk);
        let (decrypted, purported_alice_pk) = box_decrypt(&encrypted, bob_sk).unwrap();
        assert_eq!(test_string, &decrypted[..]);
        assert_eq!(purported_alice_pk, alice_pk);
    }

    #[test]
    fn pk_auth() {
        let sk = Ed25519SK::generate();
        let cred = Credentials::new_keypair(&sk);
        match cred {
            Credentials::Password { .. } => todo!(),
            Credentials::Signature {
                pubkey,
                unix_secs,
                signature,
            } => {
                assert!(verify_pk_auth(pubkey, unix_secs, &signature));
            }
        }
    }
}
