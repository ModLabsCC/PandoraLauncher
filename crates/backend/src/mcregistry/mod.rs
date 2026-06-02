use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use bridge::instance::ContentType;
use parking_lot::Mutex;
use reqwest::StatusCode;
use rustc_hash::FxHashMap;
use schema::{
    backend_config::{McRegistryConfig, McRegistryPolicy},
    mcregistry::{
        McRegistryCheckRevokedRequest, McRegistryCheckRevokedResponse, McRegistryNotaryMetadata,
        McRegistryTicket, MCREGISTRY_CHECK_REVOKED_PATH, MCREGISTRY_NOTARY_PATH,
    },
};

mod ticket;

pub use ticket::{read_ticket_with_hash_from_bytes, read_ticket_with_hash_from_path, TicketFromJar};

const NOTARY_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const REVOCATION_CACHE_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, thiserror::Error)]
pub enum McRegistryError {
    #[error("MCRegistry ticket is missing")]
    MissingTicket,
    #[error("Unsupported MCRegistry ticket version {0}")]
    UnsupportedTicketVersion(u32),
    #[error("MCRegistry ticket issuer mismatch: expected {expected}, got {actual}")]
    IssuerMismatch { expected: Arc<str>, actual: Arc<str> },
    #[error("MCRegistry artifact has been revoked (file sha1 {file_sha1}, artifact {artifact_sha256})")]
    RevokedArtifact { file_sha1: String, artifact_sha256: Arc<str> },
    #[error("MCRegistry developer has been revoked ({developer_sub})")]
    RevokedDeveloper { developer_sub: Arc<str> },
    #[error("MCRegistry API request failed: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("MCRegistry API returned status {0}")]
    NotOk(StatusCode),
    #[error("Failed to read mod JAR: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to parse MCRegistry ticket: {0}")]
    InvalidTicket(#[from] serde_json::Error),
    #[error("MCRegistry is unavailable")]
    RegistryUnavailable,
    #[error("Failed to read mod archive")]
    InvalidArchive,
}

#[derive(Debug)]
pub enum McRegistryOutcome {
    Skipped,
    Valid(McRegistryTicket),
    Unsigned,
    Failed(McRegistryError),
}

struct TicketVerification {
    file_sha1: [u8; 20],
    ticket: McRegistryTicket,
}

pub struct McRegistryVerifier {
    http_client: reqwest::Client,
    notary_cache: Mutex<Option<(Instant, Arc<McRegistryNotaryMetadata>)>>,
    revocation_cache: Mutex<FxHashMap<RevocationCacheKey, (Instant, bool)>>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum RevocationCacheKey {
    FileArtifact {
        file_sha1: [u8; 20],
        artifact_sha256: Arc<str>,
    },
    Developer(Arc<str>),
}

impl McRegistryVerifier {
    pub fn new(http_client: reqwest::Client) -> Self {
        Self {
            http_client,
            notary_cache: Mutex::new(None),
            revocation_cache: Mutex::new(FxHashMap::default()),
        }
    }

    pub fn should_verify_content(content_type: &ContentType, path: &Path, in_mods_folder: bool) -> bool {
        if content_type.is_mod() {
            return true;
        }

        in_mods_folder && is_jar_like(path)
    }

    pub async fn verify_jar_path(&self, path: &Path, config: &McRegistryConfig) -> McRegistryOutcome {
        if !config.enabled {
            return McRegistryOutcome::Skipped;
        }

        let path = path.to_path_buf();
        let read_result = tokio::task::spawn_blocking(move || read_ticket_with_hash_from_path(&path)).await;

        let parsed = match read_result {
            Ok(Ok(Some(parsed))) => parsed,
            Ok(Ok(None)) => return McRegistryOutcome::Unsigned,
            Ok(Err(error)) => return McRegistryOutcome::Failed(error),
            Err(_) => return McRegistryOutcome::Failed(McRegistryError::RegistryUnavailable),
        };

        match self.validate_ticket(parsed, config).await {
            Ok(ticket) => McRegistryOutcome::Valid(ticket),
            Err(error) => McRegistryOutcome::Failed(error),
        }
    }

    pub async fn verify_jar_bytes(&self, bytes: &[u8], config: &McRegistryConfig) -> McRegistryOutcome {
        if !config.enabled {
            return McRegistryOutcome::Skipped;
        }

        let parsed = match read_ticket_with_hash_from_bytes(bytes) {
            Ok(Some(parsed)) => parsed,
            Ok(None) => return McRegistryOutcome::Unsigned,
            Err(error) => return McRegistryOutcome::Failed(error),
        };

        match self.validate_ticket(parsed, config).await {
            Ok(ticket) => McRegistryOutcome::Valid(ticket),
            Err(error) => McRegistryOutcome::Failed(error),
        }
    }

    pub fn apply_policy(
        outcome: McRegistryOutcome,
        config: &McRegistryConfig,
        context: &str,
    ) -> Result<Option<McRegistryTicket>, McRegistryError> {
        if !config.enabled {
            return Ok(None);
        }

        match (config.policy, outcome) {
            (_, McRegistryOutcome::Skipped) => Ok(None),
            (_, McRegistryOutcome::Valid(ticket)) => Ok(Some(ticket)),
            (McRegistryPolicy::Warn, McRegistryOutcome::Unsigned) => {
                log::warn!("{context}: mod is not MCRegistry-notarized");
                Ok(None)
            },
            (McRegistryPolicy::Enforce, McRegistryOutcome::Unsigned) => Err(McRegistryError::MissingTicket),
            (McRegistryPolicy::Warn, McRegistryOutcome::Failed(error @ McRegistryError::RegistryUnavailable)) => {
                if config.fail_closed {
                    Err(error)
                } else {
                    log::warn!("{context}: MCRegistry unavailable, allowing mod: {error}");
                    Ok(None)
                }
            },
            (McRegistryPolicy::Warn, McRegistryOutcome::Failed(error)) => {
                log::warn!("{context}: MCRegistry verification failed, allowing mod: {error}");
                Ok(None)
            },
            (McRegistryPolicy::Enforce, McRegistryOutcome::Failed(error @ McRegistryError::RegistryUnavailable)) => {
                if config.fail_closed {
                    Err(error)
                } else {
                    log::warn!("{context}: MCRegistry unavailable, allowing mod: {error}");
                    Ok(None)
                }
            },
            (McRegistryPolicy::Enforce, McRegistryOutcome::Failed(error)) => Err(error),
        }
    }

    pub async fn verify_mod_copies(
        &self,
        entries: &[(std::path::PathBuf, PrelaunchSource)],
        config: &McRegistryConfig,
    ) -> Result<(), McRegistryError> {
        if !config.enabled {
            return Ok(());
        }

        let mut verifications = Vec::new();
        for (display_path, source) in entries {
            if !is_jar_like(display_path) {
                continue;
            }

            let parsed = match source {
                PrelaunchSource::Path(source_path) => read_ticket_with_hash_from_path(source_path)?,
                PrelaunchSource::Bytes(bytes) => read_ticket_with_hash_from_bytes(bytes)?,
            };

            let Some(parsed) = parsed else {
                Self::apply_policy(
                    McRegistryOutcome::Unsigned,
                    config,
                    &format!("Mod {}", display_path.display()),
                )?;
                continue;
            };

            verifications.push((display_path.clone(), parsed));
        }

        if verifications.is_empty() {
            return Ok(());
        }

        let notary = self.fetch_notary_metadata(config).await?;
        for (path, parsed) in &verifications {
            if parsed.ticket.version != notary.ticket_version {
                Self::apply_policy(
                    McRegistryOutcome::Failed(McRegistryError::UnsupportedTicketVersion(parsed.ticket.version)),
                    config,
                    &format!("Mod {}", path.display()),
                )?;
            }

            if parsed.ticket.notary_issuer != notary.notary_issuer {
                Self::apply_policy(
                    McRegistryOutcome::Failed(McRegistryError::IssuerMismatch {
                        expected: Arc::clone(&notary.notary_issuer),
                        actual: Arc::clone(&parsed.ticket.notary_issuer),
                    }),
                    config,
                    &format!("Mod {}", path.display()),
                )?;
            }
        }

        let ticket_values: Vec<TicketVerification> = verifications
            .into_iter()
            .map(|(_, parsed)| TicketVerification {
                file_sha1: parsed.file_sha1,
                ticket: parsed.ticket,
            })
            .collect();

        match self.check_revoked_batch(&ticket_values, config).await {
            Ok(()) => Ok(()),
            Err(error) => Self::apply_policy(
                McRegistryOutcome::Failed(error),
                config,
                "Launch mod verification",
            )
            .map(|_| ()),
        }
    }

    async fn validate_ticket(
        &self,
        parsed: TicketFromJar,
        config: &McRegistryConfig,
    ) -> Result<McRegistryTicket, McRegistryError> {
        let notary = self.fetch_notary_metadata(config).await?;

        if parsed.ticket.version != notary.ticket_version {
            return Err(McRegistryError::UnsupportedTicketVersion(parsed.ticket.version));
        }

        if parsed.ticket.notary_issuer != notary.notary_issuer {
            return Err(McRegistryError::IssuerMismatch {
                expected: Arc::clone(&notary.notary_issuer),
                actual: Arc::clone(&parsed.ticket.notary_issuer),
            });
        }

        self.check_revoked_batch(
            &[TicketVerification {
                file_sha1: parsed.file_sha1,
                ticket: parsed.ticket.clone(),
            }],
            config,
        )
        .await?;
        Ok(parsed.ticket)
    }

    async fn check_revoked_batch(
        &self,
        tickets: &[TicketVerification],
        config: &McRegistryConfig,
    ) -> Result<(), McRegistryError> {
        let now = Instant::now();
        let mut uncached_tickets = Vec::new();

        {
            let cache = self.revocation_cache.lock();
            for ticket in tickets {
                let artifact_key = RevocationCacheKey::FileArtifact {
                    file_sha1: ticket.file_sha1,
                    artifact_sha256: Arc::clone(&ticket.ticket.artifact_sha256),
                };
                let developer_key = RevocationCacheKey::Developer(Arc::clone(&ticket.ticket.developer_sub));

                let artifact_cached = cache
                    .get(&artifact_key)
                    .is_some_and(|(cached_at, _)| now.duration_since(*cached_at) < REVOCATION_CACHE_TTL);
                let developer_cached = cache
                    .get(&developer_key)
                    .is_some_and(|(cached_at, _)| now.duration_since(*cached_at) < REVOCATION_CACHE_TTL);

                if artifact_cached && developer_cached {
                    if let Some((_, true)) = cache.get(&developer_key) {
                        return Err(McRegistryError::RevokedDeveloper {
                            developer_sub: Arc::clone(&ticket.ticket.developer_sub),
                        });
                    }
                    if let Some((_, true)) = cache.get(&artifact_key) {
                        return Err(McRegistryError::RevokedArtifact {
                            file_sha1: hex::encode(ticket.file_sha1),
                            artifact_sha256: Arc::clone(&ticket.ticket.artifact_sha256),
                        });
                    }
                } else {
                    uncached_tickets.push(ticket);
                }
            }
        }

        if uncached_tickets.is_empty() {
            return Ok(());
        }

        let sha256: Vec<Arc<str>> = uncached_tickets
            .iter()
            .map(|ticket| Arc::clone(&ticket.ticket.artifact_sha256))
            .collect();
        let developer_subs: Vec<Arc<str>> = uncached_tickets
            .iter()
            .map(|ticket| Arc::clone(&ticket.ticket.developer_sub))
            .collect();

        let response = self
            .post_check_revoked(
                config,
                McRegistryCheckRevokedRequest {
                    sha256,
                    developer_subs,
                },
            )
            .await?;

        let now = Instant::now();
        let mut cache = self.revocation_cache.lock();

        for ticket in uncached_tickets {
            let artifact_key = RevocationCacheKey::FileArtifact {
                file_sha1: ticket.file_sha1,
                artifact_sha256: Arc::clone(&ticket.ticket.artifact_sha256),
            };
            let developer_key = RevocationCacheKey::Developer(Arc::clone(&ticket.ticket.developer_sub));

            let developer_revoked = response
                .revoked_developer_subs
                .iter()
                .any(|sub| sub.eq_ignore_ascii_case(ticket.ticket.developer_sub.as_ref()));
            let artifact_revoked = response.revoked_sha256.iter().any(|hash| {
                hash.eq_ignore_ascii_case(ticket.ticket.artifact_sha256.as_ref())
            });

            cache.insert(developer_key, (now, developer_revoked));
            cache.insert(artifact_key, (now, artifact_revoked));

            if developer_revoked {
                return Err(McRegistryError::RevokedDeveloper {
                    developer_sub: Arc::clone(&ticket.ticket.developer_sub),
                });
            }
            if artifact_revoked {
                return Err(McRegistryError::RevokedArtifact {
                    file_sha1: hex::encode(ticket.file_sha1),
                    artifact_sha256: Arc::clone(&ticket.ticket.artifact_sha256),
                });
            }
        }

        Ok(())
    }

    async fn fetch_notary_metadata(&self, config: &McRegistryConfig) -> Result<Arc<McRegistryNotaryMetadata>, McRegistryError> {
        let now = Instant::now();
        if let Some((cached_at, metadata)) = self.notary_cache.lock().as_ref() &&
            now.duration_since(*cached_at) < NOTARY_CACHE_TTL
        {
            return Ok(Arc::clone(metadata));
        }

        let url = join_base_url(&config.base_url, MCREGISTRY_NOTARY_PATH);
        let response = self.http_client.get(url).send().await.map_err(|error| {
            log::warn!("Failed to fetch MCRegistry notary metadata: {error}");
            McRegistryError::RegistryUnavailable
        })?;

        if response.status() != StatusCode::OK {
            return Err(McRegistryError::NotOk(response.status()));
        }

        let metadata = Arc::new(response.json::<McRegistryNotaryMetadata>().await?);
        *self.notary_cache.lock() = Some((now, Arc::clone(&metadata)));
        Ok(metadata)
    }

    async fn post_check_revoked(
        &self,
        config: &McRegistryConfig,
        request: McRegistryCheckRevokedRequest,
    ) -> Result<McRegistryCheckRevokedResponse, McRegistryError> {
        let url = join_base_url(&config.base_url, MCREGISTRY_CHECK_REVOKED_PATH);
        let response = self.http_client.post(url).json(&request).send().await.map_err(|error| {
            log::warn!("Failed to call MCRegistry check-revoked: {error}");
            McRegistryError::RegistryUnavailable
        })?;

        if response.status() != StatusCode::OK {
            return Err(McRegistryError::NotOk(response.status()));
        }

        Ok(response.json().await?)
    }
}

pub enum PrelaunchSource {
    Path(PathBuf),
    Bytes(Arc<[u8]>),
}

fn join_base_url(base_url: &str, path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    format!("{base}{path}")
}

fn is_jar_like(path: &Path) -> bool {
    match path.extension().and_then(OsStr::to_str) {
        Some("jar") => true,
        None => true,
        _ => false,
    }
}

trait ContentTypeExt {
    fn is_mod(self: &Self) -> bool;
}

impl ContentTypeExt for ContentType {
    fn is_mod(self: &Self) -> bool {
        matches!(
            self,
            ContentType::Fabric
                | ContentType::LegacyForge
                | ContentType::Forge
                | ContentType::NeoForge
                | ContentType::JavaModule
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_base_url_trims_trailing_slash() {
        assert_eq!(
            join_base_url("https://example.com/", "/api/v1/public/notary"),
            "https://example.com/api/v1/public/notary"
        );
    }
}
