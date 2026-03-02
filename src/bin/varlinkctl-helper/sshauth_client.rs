use std::fmt;

use anyhow::{Context, Result, bail};
use log::{debug, warn};
use varlink_http_bridge::SSHAUTH_MAGIC_PREFIX;

// Slightly ugly to build it here dynamically, but when this code is
// built without the sshauth feature this file is not built at all so
// making everything async seems overkill (only this helper needs
// async so far)
static TOKIO_RT: std::sync::LazyLock<tokio::runtime::Runtime> = std::sync::LazyLock::new(|| {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("creating tokio runtime")
});

/// An SSH key that can be used for authentication.
pub(crate) enum SshKey {
    /// A private key read from a file (`VARLINK_SSH_KEY`).
    PrivateKey {
        path: String,
        key: Box<ssh_key::PrivateKey>,
    },
    /// A public key from the SSH agent (`SSH_AUTH_SOCK`).
    AgentKey {
        auth_sock: String,
        key: ssh_key::PublicKey,
    },
}

impl fmt::Display for SshKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SshKey::PrivateKey { path, key } => {
                write!(
                    f,
                    "{} {} ({}) from {}",
                    key.algorithm(),
                    key.fingerprint(ssh_key::HashAlg::Sha256),
                    key.comment(),
                    path,
                )
            }
            SshKey::AgentKey { auth_sock, key } => {
                write!(
                    f,
                    "{} {} ({}) from agent {}",
                    key.algorithm(),
                    key.fingerprint(ssh_key::HashAlg::Sha256),
                    key.comment(),
                    auth_sock,
                )
            }
        }
    }
}

/// Try connecting with each available SSH key, retrying on 401.
///
/// Enumerates keys from the environment (`VARLINK_SSH_KEY` or `SSH_AUTH_SOCK`),
/// then calls `connect` for each key.  On HTTP 401 the next key is tried;
/// any other error is returned immediately.  When no keys are available,
/// `connect` is called once with `None` (unauthenticated).
pub(crate) fn connect_with_ssh_retry<T>(
    connect: impl FnMut(Option<&SshKey>) -> Result<T>,
) -> Result<T> {
    let keys = list_ssh_keys()?;
    try_each_key(&keys, connect)
}

/// Add SSH auth headers to the request, signing with the given key.
pub(crate) fn add_auth_headers(
    request: &mut tungstenite::http::Request<()>,
    uri: &tungstenite::http::Uri,
    key: &SshKey,
) -> Result<()> {
    let path_and_query = uri
        .path_and_query()
        .map_or(uri.path(), tungstenite::http::uri::PathAndQuery::as_str);

    let (bearer, nonce) = sign_with_key(key, "GET", path_and_query)?;

    request.headers_mut().insert(
        "Authorization",
        bearer.parse().context("invalid auth header value")?,
    );
    request.headers_mut().insert(
        varlink_http_bridge::SSHAUTH_NONCE_HEADER,
        nonce.parse().context("invalid nonce header value")?,
    );
    Ok(())
}

// -- internals ---------------------------------------------------------------

/// Generic retry loop: try `connect` for each key, retrying on HTTP 401.
fn try_each_key<K: fmt::Display, T>(
    keys: &[K],
    mut connect: impl FnMut(Option<&K>) -> Result<T>,
) -> Result<T> {
    if keys.is_empty() {
        return connect(None);
    }

    let mut last_err = None;
    for key in keys {
        match connect(Some(key)) {
            Ok(val) => return Ok(val),
            Err(e) if is_http_unauthorized(&e) => {
                warn!("SSH key {key} rejected, trying next");
                last_err = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap())
}

fn is_http_unauthorized(err: &anyhow::Error) -> bool {
    err.downcast_ref::<tungstenite::Error>()
        .is_some_and(|e| matches!(e, tungstenite::Error::Http(r) if r.status() == 401))
}

/// Return all available SSH keys for authentication.
///
/// - If `VARLINK_SSH_KEY` is set: returns a single key from that file.
/// - If `SSH_AUTH_SOCK` is set: returns all non-RSA keys from the agent.
/// - If neither: returns an empty vec (no auth).
fn list_ssh_keys() -> Result<Vec<SshKey>> {
    let key_path = std::env::var("VARLINK_SSH_KEY").ok();
    let auth_sock = std::env::var("SSH_AUTH_SOCK").ok();

    if let Some(key_path) = key_path {
        let key = read_private_key(&key_path)?;
        return Ok(vec![SshKey::PrivateKey {
            path: key_path,
            key: Box::new(key),
        }]);
    }

    if let Some(auth_sock) = auth_sock {
        let all_keys = TOKIO_RT
            .block_on(sshauth::agent::list_keys(&auth_sock))
            .context("listing ssh-agent keys")?;

        let mut keys = Vec::new();
        for k in all_keys {
            if matches!(k.algorithm(), ssh_key::Algorithm::Rsa { .. }) {
                warn!(
                    "skipping RSA key {} ({}): RSA signing is not supported, use Ed25519 or ECDSA",
                    k.fingerprint(ssh_key::HashAlg::Sha256),
                    k.comment(),
                );
            } else {
                keys.push(SshKey::AgentKey {
                    auth_sock: auth_sock.clone(),
                    key: k,
                });
            }
        }
        return Ok(keys);
    }

    Ok(vec![])
}

/// Build a bearer token + nonce by signing with the given key.
fn sign_with_key(key: &SshKey, method: &str, path_and_query: &str) -> Result<(String, String)> {
    let nonce = generate_nonce();

    let bearer = TOKIO_RT.block_on(async {
        let mut signer_builder = match key {
            SshKey::PrivateKey { key, .. } => {
                sshauth::TokenSigner::using_private_key(key.as_ref().clone())?
            }
            SshKey::AgentKey { auth_sock, key } => {
                let mut sb = sshauth::TokenSigner::using_authsock(auth_sock)?;
                sb.key(key.clone());
                sb
            }
        };
        debug!("SSH auth: using {key}");

        signer_builder
            .include_fingerprint(true)
            .magic_prefix(SSHAUTH_MAGIC_PREFIX);
        let signer = signer_builder.build()?;

        let mut tb = signer.sign_for();
        tb.action("method", method)
            .action("path", path_and_query)
            .action("nonce", &nonce);
        let token: sshauth::token::Token = tb.sign().await?;
        Ok::<_, anyhow::Error>(format!("Bearer {}", token.encode()))
    })?;

    Ok((bearer, nonce))
}

fn generate_nonce() -> String {
    let mut buf = [0u8; 16];
    openssl::rand::rand_bytes(&mut buf).expect("openssl PRNG failed");
    openssl::base64::encode_block(&buf)
}

/// Read a private key from `key_path`.
///
/// If the path ends in `.pub`, the corresponding private key path (without the
/// extension) is tried instead.
fn read_private_key(key_path: &str) -> Result<ssh_key::PrivateKey> {
    let privkey_path = key_path.strip_suffix(".pub").unwrap_or(key_path);
    let pem = std::fs::read_to_string(privkey_path)
        .with_context(|| format!("reading private key from {privkey_path}"))?;
    let privkey = ssh_key::PrivateKey::from_openssh(pem.trim())
        .with_context(|| format!("parsing private key from {privkey_path}"))?;

    if matches!(privkey.algorithm(), ssh_key::Algorithm::Rsa { .. }) {
        bail!(
            "VARLINK_SSH_KEY={key_path} is an RSA key, which is not supported; use Ed25519 or ECDSA"
        );
    }
    Ok(privkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_http_error(status: u16) -> anyhow::Error {
        let response = tungstenite::http::Response::builder()
            .status(status)
            .body(None)
            .unwrap();
        tungstenite::Error::Http(Box::new(response)).into()
    }

    #[test]
    fn test_is_http_unauthorized_detects_401() {
        assert!(is_http_unauthorized(&make_http_error(401)));
    }

    #[test]
    fn test_is_http_unauthorized_ignores_other_status() {
        assert!(!is_http_unauthorized(&make_http_error(403)));
        assert!(!is_http_unauthorized(&make_http_error(500)));
    }

    #[test]
    fn test_is_http_unauthorized_ignores_non_http_errors() {
        assert!(!is_http_unauthorized(&anyhow::anyhow!("connection refused")));
    }

    #[test]
    fn test_retry_no_keys_connects_without_auth() {
        let keys: Vec<String> = vec![];
        let result = try_each_key(&keys, |key| {
            assert!(key.is_none());
            Ok("connected")
        });
        assert_eq!(result.unwrap(), "connected");
    }

    #[test]
    fn test_retry_first_key_succeeds() {
        let keys = vec!["key-a".to_string(), "key-b".to_string()];
        let attempts = std::cell::Cell::new(0);
        let result = try_each_key(&keys, |_key| {
            attempts.set(attempts.get() + 1);
            Ok("connected")
        });
        assert_eq!(result.unwrap(), "connected");
        assert_eq!(attempts.get(), 1);
    }

    #[test]
    fn test_retry_skips_401_tries_next_key() {
        let keys = vec![
            "key-a".to_string(),
            "key-b".to_string(),
            "key-c".to_string(),
        ];
        let attempts = std::cell::Cell::new(0);
        let result = try_each_key(&keys, |key| {
            let n = attempts.get();
            attempts.set(n + 1);
            if n < 2 {
                Err(make_http_error(401))
            } else {
                assert_eq!(key.unwrap(), "key-c");
                Ok("connected")
            }
        });
        assert_eq!(result.unwrap(), "connected");
        assert_eq!(attempts.get(), 3);
    }

    #[test]
    fn test_retry_all_keys_rejected() {
        let keys = vec!["key-a".to_string(), "key-b".to_string()];
        let result: Result<()> = try_each_key(&keys, |_key| Err(make_http_error(401)));
        let err = result.unwrap_err();
        assert!(is_http_unauthorized(&err));
    }

    #[test]
    fn test_retry_non_auth_error_stops_immediately() {
        let keys = vec!["key-a".to_string(), "key-b".to_string()];
        let attempts = std::cell::Cell::new(0);
        let result: Result<()> = try_each_key(&keys, |_key| {
            attempts.set(attempts.get() + 1);
            Err(anyhow::anyhow!("connection refused"))
        });
        assert!(result.is_err());
        assert_eq!(attempts.get(), 1);
    }
}
