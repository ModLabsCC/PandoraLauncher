use std::sync::Arc;

use serde::{Deserialize, Serialize};

pub const MCREGISTRY_DEFAULT_BASE_URL: &str = "https://mcregistry-api.flwc.cc";
pub const MCREGISTRY_NOTARY_PATH: &str = "/api/v1/public/notary";
pub const MCREGISTRY_CHECK_REVOKED_PATH: &str = "/api/v1/verify/check-revoked";
pub const MCREGISTRY_TICKET_ZIP_PATH: &str = "META-INF/MC-REGISTRY.ticket";

#[derive(Debug, Clone, Deserialize)]
pub struct McRegistryNotaryMetadata {
    pub notary_issuer: Arc<str>,
    pub ticket_version: u32,
    pub ticket_path: Arc<str>,
    pub verify_endpoint: Arc<str>,
    #[serde(default)]
    pub certificate_path: Option<Arc<str>>,
    #[serde(default)]
    pub jar_sig_alg: Option<Arc<str>>,
    #[serde(default)]
    pub jar_digest_alg: Option<Arc<str>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct McRegistryTicket {
    pub version: u32,
    pub ticket_id: Arc<str>,
    pub artifact_sha256: Arc<str>,
    pub developer_sub: Arc<str>,
    #[serde(default)]
    pub entitlements: McRegistryEntitlements,
    pub issued_at: Arc<str>,
    pub notary_issuer: Arc<str>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct McRegistryEntitlements {
    #[serde(default, rename = "cc.flwc.mcr.entitlement.network.external-connect")]
    pub network_external_connect: bool,
    #[serde(default, rename = "cc.flwc.mcr.entitlement.process.execute-os-commands")]
    pub process_execute_os_commands: bool,
    #[serde(default, rename = "cc.flwc.mcr.entitlement.reflection.unsafe-access")]
    pub reflection_unsafe_access: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct McRegistryCheckRevokedRequest {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sha256: Vec<Arc<str>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub developer_subs: Vec<Arc<str>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct McRegistryCheckRevokedResponse {
    #[serde(default, deserialize_with = "deserialize_null_or_vec")]
    pub revoked_sha256: Vec<Arc<str>>,
    #[serde(default, deserialize_with = "deserialize_null_or_vec")]
    pub revoked_developer_subs: Vec<Arc<str>>,
}

fn deserialize_null_or_vec<'de, D>(deserializer: D) -> Result<Vec<Arc<str>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<Vec<Arc<str>>>::deserialize(deserializer).map(|value| value.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_revoked_response_accepts_null_lists() {
        let response: McRegistryCheckRevokedResponse = serde_json::from_str(
            r#"{"revoked_developer_subs":null,"revoked_sha256":null}"#,
        )
        .unwrap();

        assert!(response.revoked_sha256.is_empty());
        assert!(response.revoked_developer_subs.is_empty());
    }

    #[test]
    fn check_revoked_response_accepts_empty_lists() {
        let response: McRegistryCheckRevokedResponse = serde_json::from_str(
            r#"{"revoked_developer_subs":[],"revoked_sha256":[]}"#,
        )
        .unwrap();

        assert!(response.revoked_sha256.is_empty());
        assert!(response.revoked_developer_subs.is_empty());
    }
}
