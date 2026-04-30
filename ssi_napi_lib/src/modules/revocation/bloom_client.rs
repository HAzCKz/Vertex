use crate::modules::revocation::types::ManifestAnchor;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const BLOOM_MANIFEST_CACHE_TTL_MS: u128 = 30_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloomManifestFilterEntry {
    pub filter_id: String,
    #[serde(default)]
    pub status: String,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub closed_at: Option<u64>,
    pub m_bits: usize,
    pub k: usize,
    pub inserted_count: usize,
    #[serde(default)]
    pub capacity_limit: usize,
    pub file_name: String,
    #[serde(default)]
    pub encoding: String,
    #[serde(default)]
    pub sha256_base64: String,
    #[serde(default)]
    pub download_url: Option<String>,
    #[serde(default)]
    pub window_start_min: Option<i64>,
    #[serde(default)]
    pub window_start_max: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloomManifestDocument {
    pub service: String,
    pub version: u32,
    pub updated_at: u64,
    pub active_filter_id: String,
    #[serde(default)]
    pub false_positive_power: u32,
    #[serde(default)]
    pub public_base_url: Option<String>,
    pub filters: Vec<BloomManifestFilterEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloomManifestEnvelope {
    pub ok: bool,
    pub manifest: BloomManifestDocument,
}

#[derive(Clone)]
struct BloomManifestCacheEntry {
    cached_at_ms: u128,
    envelope: BloomManifestEnvelope,
}

static BLOOM_MANIFEST_CACHE: OnceLock<Mutex<HashMap<String, BloomManifestCacheEntry>>> =
    OnceLock::new();

fn bloom_manifest_cache() -> &'static Mutex<HashMap<String, BloomManifestCacheEntry>> {
    BLOOM_MANIFEST_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn manifest_cache_key(anchor: &ManifestAnchor) -> String {
    format!(
        "{}|{}",
        anchor.manifest_url.trim(),
        anchor.manifest_hash.trim()
    )
}

fn get_cached_manifest(anchor: &ManifestAnchor) -> Option<BloomManifestEnvelope> {
    let cache = bloom_manifest_cache().lock().ok()?;
    let entry = cache.get(&manifest_cache_key(anchor))?;
    if now_millis().saturating_sub(entry.cached_at_ms) <= BLOOM_MANIFEST_CACHE_TTL_MS {
        return Some(entry.envelope.clone());
    }
    None
}

fn store_cached_manifest(anchor: &ManifestAnchor, envelope: &BloomManifestEnvelope) {
    if let Ok(mut cache) = bloom_manifest_cache().lock() {
        cache.insert(
            manifest_cache_key(anchor),
            BloomManifestCacheEntry {
                cached_at_ms: now_millis(),
                envelope: envelope.clone(),
            },
        );
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloomCheckResultItem {
    pub key: String,
    pub maybe_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloomCheckResponse {
    pub ok: bool,
    pub filter_id: String,
    pub results: Vec<BloomCheckResultItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloomRevokeResponse {
    pub ok: bool,
    pub filter_id: String,
    #[serde(default)]
    pub filter_ids: Vec<String>,
    pub inserted: usize,
    pub issuer_did: Option<String>,
    pub credential_record_id: Option<String>,
    pub reason: Option<String>,
    pub requested_by: Option<String>,
    #[serde(default)]
    pub window_starts: Vec<i64>,
}

#[derive(Debug, Serialize)]
struct BloomCheckRequest<'a> {
    filter_id: Option<&'a str>,
    revocation_keys: &'a [String],
    encoding: &'a str,
    window_start: Option<i64>,
}

#[derive(Debug, Serialize)]
struct BloomRevokeRequest<'a> {
    issuer_did: Option<&'a str>,
    credential_record_id: Option<&'a str>,
    filter_id: Option<&'a str>,
    revocation_keys: &'a [String],
    window_starts: Option<&'a [i64]>,
    reason: Option<&'a str>,
    requested_by: Option<&'a str>,
}

fn sha256_base64_bytes(bytes: &[u8]) -> String {
    B64.encode(Sha256::digest(bytes))
}

async fn fetch_manifest_body_bytes(manifest_url: &str) -> Result<Vec<u8>, String> {
    let trimmed = manifest_url.trim();
    if trimmed.is_empty() {
        return Err("manifest_url vazio".to_string());
    }

    let client = Client::new();
    let response = client
        .get(trimmed)
        .send()
        .await
        .map_err(|e| format!("Erro HTTP buscando manifesto Bloom: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Serviço Bloom respondeu {} ao buscar manifesto",
            response.status()
        ));
    }

    response
        .bytes()
        .await
        .map(|bytes| bytes.to_vec())
        .map_err(|e| format!("Erro lendo manifesto Bloom: {}", e))
}

pub async fn compute_manifest_body_hash(manifest_url: &str) -> Result<String, String> {
    let body_bytes = fetch_manifest_body_bytes(manifest_url).await?;
    Ok(sha256_base64_bytes(&body_bytes))
}

fn manifest_hash_matches(anchor: &ManifestAnchor, body_bytes: &[u8]) -> bool {
    let expected = anchor.manifest_hash.trim();
    if expected.is_empty() {
        return false;
    }

    expected == sha256_base64_bytes(body_bytes)
}

fn derive_service_base_url(manifest_url: &str) -> Result<String, String> {
    let trimmed = manifest_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err("manifest_url vazio".to_string());
    }

    if let Some(base) = trimmed.strip_suffix("/manifest") {
        return Ok(base.to_string());
    }

    Ok(trimmed.to_string())
}

pub fn validate_manifest_anchor(anchor: &ManifestAnchor) -> Result<(), String> {
    if anchor.manifest_url.trim().is_empty() {
        return Err("manifest_url vazio".to_string());
    }
    if anchor.manifest_hash.trim().is_empty() {
        return Err("manifest_hash vazio".to_string());
    }
    Ok(())
}

pub async fn fetch_manifest(anchor: &ManifestAnchor) -> Result<BloomManifestEnvelope, String> {
    validate_manifest_anchor(anchor)?;

    if let Some(envelope) = get_cached_manifest(anchor) {
        return Ok(envelope);
    }

    let body_bytes = fetch_manifest_body_bytes(anchor.manifest_url.trim()).await?;
    let envelope: BloomManifestEnvelope = serde_json::from_slice(&body_bytes)
        .map_err(|e| format!("Manifesto Bloom inválido: {}", e))?;

    if !manifest_hash_matches(anchor, &body_bytes) {
        return Err(
            "manifest_hash não confere com o manifesto retornado pelo serviço Bloom".to_string(),
        );
    }

    store_cached_manifest(anchor, &envelope);
    Ok(envelope)
}

pub async fn check_revocation_key(
    anchor: &ManifestAnchor,
    revocation_key: &str,
    window_start: i64,
) -> Result<BloomCheckResponse, String> {
    let envelope = fetch_manifest(anchor).await?;
    let base_url = envelope
        .manifest
        .public_base_url
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(derive_service_base_url(&anchor.manifest_url)?);

    let revocation_keys = vec![revocation_key.to_string()];
    let request = BloomCheckRequest {
        filter_id: None,
        revocation_keys: &revocation_keys,
        encoding: "utf8",
        window_start: Some(window_start),
    };

    let client = Client::new();
    let response = client
        .post(format!("{}/check", base_url.trim_end_matches('/')))
        .json(&request)
        .send()
        .await
        .map_err(|e| format!("Erro HTTP consultando Bloom Filter: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Serviço Bloom respondeu {} na consulta pública",
            response.status()
        ));
    }

    response
        .json::<BloomCheckResponse>()
        .await
        .map_err(|e| format!("Resposta inválida da consulta Bloom: {}", e))
}

pub async fn revoke_revocation_keys(
    anchor: &ManifestAnchor,
    admin_token: &str,
    issuer_did: Option<&str>,
    credential_record_id: Option<&str>,
    revocation_keys: &[String],
    window_starts: Option<&[i64]>,
    reason: Option<&str>,
    requested_by: Option<&str>,
) -> Result<BloomRevokeResponse, String> {
    validate_manifest_anchor(anchor)?;
    if admin_token.trim().is_empty() {
        return Err("admin_token vazio".to_string());
    }
    if revocation_keys.is_empty() {
        return Err("revocation_keys vazio".to_string());
    }

    let envelope = fetch_manifest(anchor).await?;
    let base_url = envelope
        .manifest
        .public_base_url
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(derive_service_base_url(&anchor.manifest_url)?);

    let client = Client::new();
    let endpoint = format!("{}/admin/revocations/v2", base_url.trim_end_matches('/'));

    if let Some(window_starts_values) = window_starts {
        if window_starts_values.len() != revocation_keys.len() {
            return Err("window_starts deve ter o mesmo tamanho de revocation_keys".to_string());
        }
    }

    let request = BloomRevokeRequest {
        issuer_did,
        credential_record_id,
        filter_id: None,
        revocation_keys,
        window_starts,
        reason,
        requested_by,
    };

    // O serviço bfilter atual já aceita batches com `window_starts` por chave
    // na mesma chamada ao `/admin/revocations/v2`, preservando o roteamento
    // temporal e reduzindo drasticamente o custo de milhares de round-trips.

    let response = client
        .post(&endpoint)
        .bearer_auth(admin_token.trim())
        .json(&request)
        .send()
        .await
        .map_err(|e| format!("Erro HTTP revogando no serviço Bloom: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Serviço Bloom respondeu {} na escrita administrativa",
            response.status()
        ));
    }

    let mut body = response
        .json::<BloomRevokeResponse>()
        .await
        .map_err(|e| format!("Resposta inválida da revogação no Bloom: {}", e))?;
    if body.filter_ids.is_empty() && !body.filter_id.trim().is_empty() {
        body.filter_ids.push(body.filter_id.clone());
    }
    if body.window_starts.is_empty() {
        body.window_starts = window_starts
            .map(|values| values.to_vec())
            .unwrap_or_default();
    }
    Ok(body)
}
