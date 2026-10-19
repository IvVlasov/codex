//! Process-lifetime trust-store cache for standard HTTP and WebSocket clients.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;

use rustls::ClientConfig;
use tracing::info;

use super::BuildCustomCaTransportError;
use super::ConfiguredCaBundle;
use super::EnvSource;
use super::ProcessEnv;
use super::build_rustls_client_config;

struct CachedTlsConfig {
    config: Arc<ClientConfig>,
    bundle: Option<ConfiguredCaBundle>,
}

// Serialize the first fallible initialization as well as publishing the successful result.
// Failed CA loads remain errors and can be retried; never cache `.ok()` and silently fall back.
static TLS_CONFIG: OnceLock<Mutex<Option<Arc<CachedTlsConfig>>>> = OnceLock::new();

fn shared_config() -> Result<Arc<CachedTlsConfig>, BuildCustomCaTransportError> {
    let mut guard = TLS_CONFIG
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(cached) = guard.as_ref() {
        return Ok(Arc::clone(cached));
    }

    let bundle = ProcessEnv.configured_ca_bundle();
    let config = build_rustls_client_config(bundle.as_ref())?;
    let cached = Arc::new(CachedTlsConfig { config, bundle });
    info!("cached TLS trust store; restart the process to reload CA certificates");
    *guard = Some(Arc::clone(&cached));
    Ok(cached)
}

pub(super) fn rustls_config() -> Result<Arc<ClientConfig>, BuildCustomCaTransportError> {
    shared_config().map(|cached| Arc::clone(&cached.config))
}

pub(super) fn build_reqwest_client(
    builder: reqwest::ClientBuilder,
) -> Result<reqwest::Client, BuildCustomCaTransportError> {
    let cached = shared_config()?;
    // Reqwest 0.12 accepts ClientConfig by value. Its verifier, parsed roots, and session
    // storage are shared by the cheap clone. Preconfigured TLS skips reqwest's native-root
    // loader; it also bypasses ALPN setup, so preserve the standard HTTP/2 + HTTP/1.1 policy.
    // WebSocket connectors keep the base configuration without HTTP ALPN.
    let mut config = cached.config.as_ref().clone();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    builder
        .use_preconfigured_tls(config)
        .build()
        .map_err(|source| {
            if let Some(bundle) = &cached.bundle {
                BuildCustomCaTransportError::BuildClientWithCustomCa {
                    source_env: bundle.source_env,
                    path: bundle.path.clone(),
                    source,
                }
            } else {
                BuildCustomCaTransportError::BuildClientWithSystemRoots(source)
            }
        })
}
