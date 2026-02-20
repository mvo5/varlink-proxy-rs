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

pub(crate) fn maybe_add_auth_headers(
    request: &mut tungstenite::http::Request<()>,
    uri: &tungstenite::http::Uri,
) -> Result<()> {
    let path_and_query = uri
        .path_and_query()
        .map_or(uri.path(), tungstenite::http::uri::PathAndQuery::as_str);

    let (bearer, nonce) = match build_auth_token("GET", path_and_query) {
        Ok(Some((bearer, nonce))) => (bearer, nonce),
        Ok(None) => return Ok(()),
        Err(e) => {
            warn!("SSH auth token generation failed, proceeding without: {e:#}");
            return Ok(());
        }
    };
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

/// Build an SSH auth token for the given HTTP method and path.
///
/// Returns `Ok(None)` when no SSH credentials are available.
fn build_auth_token(method: &str, path_and_query: &str) -> Result<Option<(String, String)>> {
    let key_path = std::env::var("VARLINK_SSH_KEY").ok();
    let auth_sock = std::env::var("SSH_AUTH_SOCK").ok();
    if key_path.is_none() && auth_sock.is_none() {
        return Ok(None);
    }

    let nonce = generate_nonce();

    // The sshauth crate is async so we need to run this inside an async context
    let bearer = TOKIO_RT.block_on(async {
        // VARLINK_SSH_KEY: sign directly with the private key file (no agent needed).
        // SSH_AUTH_SOCK: fall back to the SSH agent.
        let (mut signer_builder, algo, fingerprint, comment, source) =
            if let Some(key_path) = key_path {
                let privkey = read_private_key(&key_path)?;
                let algo = privkey.algorithm();
                let fp = privkey.fingerprint(ssh_key::HashAlg::Sha256);
                let comment = privkey.comment().to_string();
                let b = sshauth::TokenSigner::using_private_key(privkey)?;
                (b, algo, fp, comment, key_path)
            } else {
                let auth_sock = auth_sock.unwrap();
                let keys = sshauth::agent::list_keys(&auth_sock)
                    .await
                    .context("listing ssh-agent keys")?;
                let key = read_agent_key(keys)?;
                let algo = key.algorithm();
                let fp = key.fingerprint(ssh_key::HashAlg::Sha256);
                let comment = key.comment().to_string();
                let mut sb = sshauth::TokenSigner::using_authsock(&auth_sock)?;
                sb.key(key);
                (sb, algo, fp, comment, auth_sock)
            };
        debug!("SSH auth: using {algo} key {fingerprint} ({comment}) from {source}");

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

    Ok(Some((bearer, nonce)))
}

fn generate_nonce() -> String {
    let mut buf = [0u8; 16];
    openssl::rand::rand_bytes(&mut buf).expect("openssl PRNG failed");
    openssl::base64::encode_block(&buf)
}

/// Read the signing key from the agent.
///
/// Picks the first supported (non-RSA) key, warning about any RSA keys found.
fn read_agent_key(keys: Vec<ssh_key::PublicKey>) -> Result<ssh_key::PublicKey> {
    for k in &keys {
        if matches!(k.algorithm(), ssh_key::Algorithm::Rsa { .. }) {
            warn!(
                "skipping RSA key {} ({}): RSA signing is not supported, use Ed25519 or ECDSA",
                k.fingerprint(ssh_key::HashAlg::Sha256),
                k.comment(),
            );
        }
    }
    keys.into_iter()
        .find(|k| !matches!(k.algorithm(), ssh_key::Algorithm::Rsa { .. }))
        .context("no Ed25519 or ECDSA key in ssh-agent (RSA is not supported)")
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
