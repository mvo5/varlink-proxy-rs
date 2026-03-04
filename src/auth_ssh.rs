// SPDX-License-Identifier: LGPL-2.1-or-later

use anyhow::{Context, bail};
use log::{info, warn};
use ssh_key::{HashAlg, PublicKey};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

use crate::Authenticator;
use varlink_http_bridge::SSHAUTH_MAGIC_PREFIX;

struct KeyCache {
    keys: HashMap<String, PublicKey>,
    mtime: SystemTime,
}

pub(crate) struct SshKeyAuthenticator {
    path: String,
    max_skew: u64,
    authorized_keys: Mutex<KeyCache>,
}

impl SshKeyAuthenticator {
    pub(crate) fn new(path: &str) -> anyhow::Result<Self> {
        let keys = Self::load_keys(path)?;
        // XXX: should we make it a warning only? the file can dynamically
        // get updated so it could be okay to start empty. OTOH ppl might
        // be surprised by it.
        if keys.is_empty() {
            bail!(
                "no supported SSH public keys in {path} (note: RSA is not supported, use Ed25519 or ECDSA)"
            );
        }
        let mtime = std::fs::metadata(path)
            .and_then(|m| m.modified())
            .with_context(|| format!("failed to stat {path}"))?;

        Ok(Self {
            path: path.to_string(),
            max_skew: 60,
            authorized_keys: Mutex::new(KeyCache { keys, mtime }),
        })
    }

    pub(crate) fn key_count(&self) -> usize {
        self.authorized_keys.lock().unwrap().keys.len()
    }

    #[cfg(test)]
    pub(crate) fn with_max_skew(mut self, max_skew: u64) -> Self {
        self.max_skew = max_skew;
        self
    }

    /// Parse an `authorized_keys` file, returning only supported (non-RSA) keys.
    fn load_keys(path: &str) -> anyhow::Result<HashMap<String, PublicKey>> {
        let keys_vec = sshauth::keyfile::parse_authorized_keys(path, true)
            .with_context(|| format!("failed to read authorized keys from {path}"))?;

        let mut keys = HashMap::new();
        for key in keys_vec {
            if matches!(key.algorithm(), ssh_key::Algorithm::Rsa { .. }) {
                warn!(
                    "ignoring RSA key {} ({}): RSA signing is not supported, use Ed25519 or ECDSA",
                    key.fingerprint(HashAlg::Sha256),
                    key.comment(),
                );
                continue;
            }
            let fp = key.fingerprint(HashAlg::Sha256).to_string();
            keys.insert(fp, key);
        }

        Ok(keys)
    }

    /// Reload the `authorized_keys` file if its mtime has changed.
    fn maybe_reload(&self) {
        let current_mtime = match std::fs::metadata(&self.path).and_then(|m| m.modified()) {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    "cannot stat {path}: {e}, keeping cached keys",
                    path = self.path
                );
                return;
            }
        };

        // note that we could use an RWLock here but its probably not worth it
        let mut ak = self.authorized_keys.lock().unwrap();
        if ak.mtime == current_mtime {
            return;
        }

        match Self::load_keys(&self.path) {
            Ok(keys) => {
                info!(
                    "reloaded {count} SSH key(s) from {path} (file changed)",
                    count = keys.len(),
                    path = self.path,
                );
                if keys.is_empty() {
                    warn!(
                        "authorized keys file {path} is empty, SSH auth will reject all requests",
                        path = self.path,
                    );
                }
                ak.keys = keys;
                ak.mtime = current_mtime;
            }
            Err(e) => {
                warn!(
                    "failed to reload {path}: {e:#}, clearing keys (fail closed)",
                    path = self.path,
                );
                ak.keys.clear();
                ak.mtime = current_mtime;
            }
        }
    }
}

impl std::fmt::Debug for SshKeyAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ak = self.authorized_keys.lock().unwrap();
        let fingerprints: Vec<&str> = ak.keys.keys().map(String::as_str).collect();
        f.debug_struct("SshKeyAuthenticator")
            .field("path", &self.path)
            .field("max_skew", &self.max_skew)
            .field("fingerprints", &fingerprints)
            .finish_non_exhaustive()
    }
}

/// Well-known credential name for SSH authorized keys, see
/// systemd.system-credentials(7).
const SSH_AUTHORIZED_KEYS_CREDENTIAL: &str = "ssh.authorized_keys.root";

pub(crate) fn maybe_create_ssh_authenticator(
    cli_authorized_keys: Option<String>,
    creds_dir: Option<&std::path::Path>,
    root: &std::path::Path,
) -> anyhow::Result<Option<SshKeyAuthenticator>> {
    fn exists(p: &std::path::Path) -> Option<String> {
        p.exists().then(|| p.to_string_lossy().to_string())
    }

    // Priority: explicit CLI > /etc config > $CREDENTIALS_DIRECTORY >
    // system-wide /run/credentials/@system/ (see systemd.system-credentials(7))
    let authorized_keys_path = cli_authorized_keys
        .or_else(|| exists(&root.join("etc/varlink-http-bridge/authorized_keys")))
        .or_else(|| creds_dir.and_then(|d| exists(&d.join(SSH_AUTHORIZED_KEYS_CREDENTIAL))))
        .or_else(|| {
            exists(
                &root
                    .join("run/credentials/@system")
                    .join(SSH_AUTHORIZED_KEYS_CREDENTIAL),
            )
        });

    let Some(ak_path) = authorized_keys_path else {
        return Ok(None);
    };
    let ssh_auth = SshKeyAuthenticator::new(&ak_path)?;
    info!(
        "Authenticator: adding SSH authorized keys ({count} keys from {ak_path})",
        count = ssh_auth.key_count()
    );
    Ok(Some(ssh_auth))
}

impl Authenticator for SshKeyAuthenticator {
    fn check_request(
        &self,
        method: &str,
        path: &str,
        auth_header: &str,
        tls_channel_binding: Option<&str>,
    ) -> anyhow::Result<()> {
        self.maybe_reload();

        let token_str = auth_header
            .strip_prefix("Bearer ")
            .context("Authorization header must start with 'Bearer '")?;

        let unverified_token =
            sshauth::UnverifiedToken::try_from(token_str).context("invalid token")?;

        // clone the keys to drop the authorized_keys.lock() ASAP and avoid it being
        // held during the (slow) verify_for()
        let authorized_keys: Vec<ssh_key::PublicKey> = {
            let ak = self.authorized_keys.lock().unwrap();
            ak.keys.values().cloned().collect()
        };

        let verified = unverified_token
            .verify_for()
            .magic_prefix(SSHAUTH_MAGIC_PREFIX)
            .max_skew_seconds(self.max_skew)
            .action("method", method)
            .action("path", path)
            .action(
                "tls-channel-binding",
                tls_channel_binding.unwrap_or_default(),
            )
            .with_keys(&authorized_keys)
            .context("token verification failed")?;

        log::info!(
            "SSH auth OK: {method} {path} key={fp}",
            fp = verified.fingerprint()
        );
        Ok(())
    }
}
