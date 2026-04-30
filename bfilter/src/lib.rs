pub mod api;

use base64::{Engine as _, engine::general_purpose};
use bitvec::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Representa um Bloom Filter simples usando bit array fixo.
#[derive(Debug, Clone)]
pub struct BloomFilter {
    m_bits: usize,
    k: usize,
    bits: BitVec<u8, Lsb0>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterManifestEntry {
    pub filter_id: String,
    #[serde(default = "default_status_active")]
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
    #[serde(default = "default_encoding")]
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
pub struct BloomManifest {
    pub service: String,
    pub version: u32,
    pub updated_at: u64,
    pub active_filter_id: String,
    #[serde(default = "default_false_positive_power")]
    pub false_positive_power: u32,
    #[serde(default)]
    pub public_base_url: Option<String>,
    pub filters: Vec<FilterManifestEntry>,
}

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub data_dir: PathBuf,
    pub filter_bytes: usize,
    pub false_positive_power: u32,
    pub public_base_url: Option<String>,
    pub rotate_at_percent: u32,
}

impl ServiceConfig {
    pub fn from_env() -> Self {
        let data_dir = std::env::var("BFILTER_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data"));
        let filter_bytes = std::env::var("BFILTER_FILTER_BYTES")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(2 * 1024 * 1024);
        let false_positive_power = std::env::var("BFILTER_FALSE_POSITIVE_POWER")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(32);

        Self {
            data_dir,
            filter_bytes,
            false_positive_power,
            public_base_url: std::env::var("BFILTER_PUBLIC_BASE_URL").ok(),
            rotate_at_percent: std::env::var("BFILTER_ROTATE_AT_PERCENT")
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
                .filter(|v| (1..=100).contains(v))
                .unwrap_or(95),
        }
    }
}

#[derive(Debug)]
pub enum ServiceError {
    Io(String),
    NotFound(String),
    Invalid(String),
    AlreadyExists(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationWriteRequest {
    pub issuer_did: Option<String>,
    pub credential_record_id: Option<String>,
    pub filter_id: Option<String>,
    pub revocation_keys: Vec<String>,
    #[serde(default)]
    pub window_starts: Option<Vec<i64>>,
    pub reason: Option<String>,
    pub requested_by: Option<String>,
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "io: {}", msg),
            Self::NotFound(msg) => write!(f, "not_found: {}", msg),
            Self::Invalid(msg) => write!(f, "invalid: {}", msg),
            Self::AlreadyExists(msg) => write!(f, "already_exists: {}", msg),
        }
    }
}

impl std::error::Error for ServiceError {}

fn now_ts_u64() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn default_encoding() -> String {
    "base64".to_string()
}

fn default_status_active() -> String {
    "active".to_string()
}

fn default_false_positive_power() -> u32 {
    32
}

fn sanitize_filter_id(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect()
}

fn default_filter_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("filter-{}", nanos)
}

fn default_m_bits(config: &ServiceConfig) -> usize {
    config.filter_bytes * 8
}

fn default_k(config: &ServiceConfig) -> usize {
    let m_bits = default_m_bits(config);
    let n = calculate_n_max(m_bits, config.false_positive_power).max(1.0);
    calculate_k_opt(m_bits, n).round().max(1.0) as usize
}

fn rotation_trigger_count(capacity_limit: usize, rotate_at_percent: u32) -> usize {
    if capacity_limit == 0 {
        return 0;
    }
    let numerator = capacity_limit
        .saturating_mul(rotate_at_percent as usize)
        .saturating_add(99);
    numerator / 100
}

fn manifest_path(data_dir: &Path) -> PathBuf {
    data_dir.join("manifest.json")
}

fn filters_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("filters")
}

fn filter_path(data_dir: &Path, file_name: &str) -> PathBuf {
    filters_dir(data_dir).join(file_name)
}

fn sha256_base64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(Sha256::digest(data))
}

fn build_download_url(public_base_url: Option<&str>, filter_id: &str) -> Option<String> {
    Some(
        public_base_url
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|base| format!("{}/filters/{}", base.trim_end_matches('/'), filter_id))
            .unwrap_or_else(|| format!("/filters/{}", filter_id)),
    )
}

#[derive(Debug)]
pub struct BloomService {
    config: ServiceConfig,
    manifest: BloomManifest,
    filters: HashMap<String, BloomFilter>,
}

#[derive(Debug, Clone)]
pub struct NormalizedWriteRequest {
    pub filter_id: Option<String>,
    pub decoded_keys: Vec<Vec<u8>>,
    pub window_starts: Option<Vec<i64>>,
    pub payload: RevocationWriteRequest,
}

#[derive(Debug, Clone)]
pub struct BatchInsertResult {
    pub filter_ids: Vec<String>,
    pub inserted: usize,
}

impl BloomService {
    pub fn load_or_initialize(config: ServiceConfig) -> Result<Self, ServiceError> {
        fs::create_dir_all(filters_dir(&config.data_dir))
            .map_err(|e| ServiceError::Io(e.to_string()))?;

        let manifest_file = manifest_path(&config.data_dir);
        if manifest_file.exists() {
            let manifest_bytes =
                fs::read(&manifest_file).map_err(|e| ServiceError::Io(e.to_string()))?;
            let mut manifest: BloomManifest = serde_json::from_slice(&manifest_bytes)
                .map_err(|e| ServiceError::Invalid(format!("manifest inválido: {}", e)))?;
            manifest.false_positive_power = config.false_positive_power;
            manifest.public_base_url = config.public_base_url.clone();

            let mut filters = HashMap::new();
            let mut legacy_storage_filter_ids = Vec::new();
            for entry in &mut manifest.filters {
                let stored = fs::read(filter_path(&config.data_dir, &entry.file_name))
                    .map_err(|e| ServiceError::Io(e.to_string()))?;
                let (filter, was_legacy_base64) =
                    BloomFilter::from_storage_bytes(&stored).map_err(ServiceError::Invalid)?;
                if was_legacy_base64 {
                    legacy_storage_filter_ids.push(entry.filter_id.clone());
                }
                if entry.capacity_limit == 0 {
                    let (capacity_limit, _) =
                        calculate_n_max_exact(entry.m_bits, config.false_positive_power);
                    entry.capacity_limit = capacity_limit;
                }
                if entry.status.trim().is_empty() {
                    entry.status = if manifest.active_filter_id == entry.filter_id {
                        default_status_active()
                    } else if entry.closed_at.is_some() {
                        "closed".to_string()
                    } else {
                        "active".to_string()
                    };
                }
                entry.download_url =
                    build_download_url(config.public_base_url.as_deref(), &entry.filter_id);
                filters.insert(entry.filter_id.clone(), filter);
            }

            let mut service = Self {
                config,
                manifest,
                filters,
            };
            for filter_id in legacy_storage_filter_ids {
                if let Some(entry) = service.get_filter_entry(&filter_id).cloned() {
                    service.persist_filter(&entry)?;
                }
            }
            service.refresh_manifest_hashes()?;
            service.persist_manifest()?;
            Ok(service)
        } else {
            let mut service = Self {
                config: config.clone(),
                manifest: BloomManifest {
                    service: "bfilter".to_string(),
                    version: 1,
                    updated_at: now_ts_u64(),
                    active_filter_id: String::new(),
                    false_positive_power: config.false_positive_power,
                    public_base_url: config.public_base_url.clone(),
                    filters: Vec::new(),
                },
                filters: HashMap::new(),
            };
            let active_id = default_filter_id();
            service.rotate_filter(Some(active_id), None, None)?;
            Ok(service)
        }
    }

    pub fn manifest(&self) -> BloomManifest {
        self.manifest.clone()
    }

    pub fn active_filter_id(&self) -> &str {
        &self.manifest.active_filter_id
    }

    pub fn get_filter_entry(&self, filter_id: &str) -> Option<&FilterManifestEntry> {
        self.manifest
            .filters
            .iter()
            .find(|entry| entry.filter_id == filter_id)
    }

    pub fn get_filter_base64(&self, filter_id: &str) -> Result<String, ServiceError> {
        let filter = self.filters.get(filter_id).ok_or_else(|| {
            ServiceError::NotFound(format!("filtro não encontrado: {}", filter_id))
        })?;
        Ok(filter.to_base64())
    }

    pub fn normalize_revocation_write_request(
        &self,
        payload: RevocationWriteRequest,
    ) -> Result<NormalizedWriteRequest, ServiceError> {
        if payload.revocation_keys.is_empty() {
            return Err(ServiceError::Invalid(
                "revocation_keys não pode ser vazio".to_string(),
            ));
        }
        if let Some(window_starts) = &payload.window_starts {
            if window_starts.len() != payload.revocation_keys.len() {
                return Err(ServiceError::Invalid(
                    "window_starts deve ter o mesmo tamanho de revocation_keys".to_string(),
                ));
            }
        }
        let decoded = payload
            .revocation_keys
            .iter()
            .map(|key| key.as_bytes().to_vec())
            .collect::<Vec<_>>();
        Ok(NormalizedWriteRequest {
            filter_id: payload.filter_id.clone(),
            decoded_keys: decoded,
            window_starts: payload.window_starts.clone(),
            payload,
        })
    }

    pub fn candidate_filters_for_window(&self, window_start: i64) -> Vec<FilterManifestEntry> {
        let mut matching = self
            .manifest
            .filters
            .iter()
            .filter(
                |entry| match (entry.window_start_min, entry.window_start_max) {
                    (Some(min_ts), Some(max_ts)) => {
                        min_ts <= window_start && window_start <= max_ts
                    }
                    (Some(min_ts), None) => min_ts <= window_start,
                    (None, Some(max_ts)) => window_start <= max_ts,
                    (None, None) => entry.inserted_count > 0,
                },
            )
            .cloned()
            .collect::<Vec<_>>();

        matching.sort_by_key(|entry| {
            (
                if entry.status == "active" { 0 } else { 1 },
                entry.created_at,
                entry.filter_id.clone(),
            )
        });
        matching
    }

    pub fn check_key(
        &self,
        filter_id: Option<&str>,
        key_bytes: &[u8],
    ) -> Result<(String, bool), ServiceError> {
        let resolved_filter_id = filter_id.unwrap_or(self.active_filter_id());
        let filter = self.filters.get(resolved_filter_id).ok_or_else(|| {
            ServiceError::NotFound(format!("filtro não encontrado: {}", resolved_filter_id))
        })?;
        Ok((resolved_filter_id.to_string(), filter.contains(key_bytes)))
    }

    fn resolve_write_filter_id(
        &self,
        filter_id: Option<&str>,
        window_start: Option<i64>,
    ) -> String {
        if let Some(explicit) = filter_id {
            return explicit.to_string();
        }

        if let Some(window_start) = window_start {
            let mut candidates = self.candidate_filters_for_window(window_start);
            candidates.retain(|entry| entry.status == "active");
            if let Some(entry) = candidates.into_iter().next() {
                return entry.filter_id;
            }
        }

        self.active_filter_id().to_string()
    }

    pub fn insert_keys(
        &mut self,
        filter_id: Option<&str>,
        keys: &[Vec<u8>],
        window_starts: Option<&[i64]>,
    ) -> Result<FilterManifestEntry, ServiceError> {
        let resolved_filter_id = filter_id.unwrap_or(self.active_filter_id()).to_string();
        let filter = self.filters.get_mut(&resolved_filter_id).ok_or_else(|| {
            ServiceError::NotFound(format!("filtro não encontrado: {}", resolved_filter_id))
        })?;

        for key in keys {
            filter.insert(key);
        }

        let (entry_clone, should_rotate, rotate_m_bits, rotate_k) = {
            let entry = self
                .manifest
                .filters
                .iter_mut()
                .find(|entry| entry.filter_id == resolved_filter_id)
                .ok_or_else(|| {
                    ServiceError::NotFound(format!(
                        "metadata do filtro não encontrada: {}",
                        resolved_filter_id
                    ))
                })?;
            if entry.status != "active" {
                return Err(ServiceError::Invalid(format!(
                    "filtro não está ativo para escrita: {} ({})",
                    resolved_filter_id, entry.status
                )));
            }
            entry.inserted_count += keys.len();
            entry.updated_at = now_ts_u64();
            if let Some(window_starts) = window_starts {
                if let Some(min_ts) = window_starts.iter().min() {
                    entry.window_start_min = Some(match entry.window_start_min {
                        Some(current) => current.min(*min_ts),
                        None => *min_ts,
                    });
                }
                if let Some(max_ts) = window_starts.iter().max() {
                    entry.window_start_max = Some(match entry.window_start_max {
                        Some(current) => current.max(*max_ts),
                        None => *max_ts,
                    });
                }
            }
            let rotate_threshold =
                rotation_trigger_count(entry.capacity_limit, self.config.rotate_at_percent);
            let should_rotate =
                entry.capacity_limit > 0 && entry.inserted_count >= rotate_threshold;
            if should_rotate {
                entry.status = "closed".to_string();
                entry.closed_at = Some(entry.updated_at);
                if self.manifest.active_filter_id == resolved_filter_id {
                    self.manifest.active_filter_id.clear();
                }
            }
            self.manifest.updated_at = entry.updated_at;
            (entry.clone(), should_rotate, entry.m_bits, entry.k)
        };
        self.persist_filter(&entry_clone)?;
        self.refresh_manifest_hashes()?;
        self.persist_manifest()?;
        if should_rotate {
            self.create_filter(None, Some(rotate_m_bits), Some(rotate_k))?;
        }
        Ok(entry_clone)
    }

    pub fn insert_keys_v2(
        &mut self,
        filter_id: Option<&str>,
        keys: &[Vec<u8>],
        window_starts: Option<&[i64]>,
    ) -> Result<BatchInsertResult, ServiceError> {
        if keys.is_empty() {
            return Err(ServiceError::Invalid("keys não pode ser vazio".to_string()));
        }

        if let Some(window_starts) = window_starts {
            if window_starts.len() != keys.len() {
                return Err(ServiceError::Invalid(
                    "window_starts deve ter o mesmo tamanho de revocation_keys".to_string(),
                ));
            }

            let mut grouped_writes: Vec<(String, Vec<Vec<u8>>, Vec<i64>)> = Vec::new();
            for (key_bytes, window_start) in keys.iter().zip(window_starts.iter()) {
                let target_filter_id = self.resolve_write_filter_id(filter_id, Some(*window_start));
                if let Some((_, grouped_keys, grouped_windows)) = grouped_writes
                    .iter_mut()
                    .find(|(current_filter_id, _, _)| *current_filter_id == target_filter_id)
                {
                    grouped_keys.push(key_bytes.clone());
                    grouped_windows.push(*window_start);
                } else {
                    grouped_writes.push((
                        target_filter_id,
                        vec![key_bytes.clone()],
                        vec![*window_start],
                    ));
                }
            }

            let mut filter_ids = Vec::with_capacity(grouped_writes.len());
            let mut total_inserted = 0usize;
            for (target_filter_id, grouped_keys, grouped_windows) in grouped_writes {
                let entry = self.insert_keys(
                    Some(target_filter_id.as_str()),
                    &grouped_keys,
                    Some(&grouped_windows),
                )?;
                total_inserted += grouped_keys.len();
                if !filter_ids.iter().any(|current| current == &entry.filter_id) {
                    filter_ids.push(entry.filter_id);
                }
            }

            return Ok(BatchInsertResult {
                filter_ids,
                inserted: total_inserted,
            });
        }

        let entry = self.insert_keys(filter_id, keys, None)?;
        Ok(BatchInsertResult {
            filter_ids: vec![entry.filter_id],
            inserted: keys.len(),
        })
    }

    pub fn close_filter(
        &mut self,
        filter_id: Option<&str>,
    ) -> Result<FilterManifestEntry, ServiceError> {
        let resolved_filter_id = filter_id.unwrap_or(self.active_filter_id()).to_string();
        if resolved_filter_id.trim().is_empty() {
            return Err(ServiceError::Invalid(
                "não existe filtro ativo para fechar".to_string(),
            ));
        }

        let entry_clone = {
            let entry = self
                .manifest
                .filters
                .iter_mut()
                .find(|entry| entry.filter_id == resolved_filter_id)
                .ok_or_else(|| {
                    ServiceError::NotFound(format!(
                        "metadata do filtro não encontrada: {}",
                        resolved_filter_id
                    ))
                })?;
            if entry.status != "active" {
                return Err(ServiceError::Invalid(format!(
                    "filtro já não está ativo: {} ({})",
                    resolved_filter_id, entry.status
                )));
            }
            let now = now_ts_u64();
            entry.status = "closed".to_string();
            entry.closed_at = Some(now);
            entry.updated_at = now;
            self.manifest.updated_at = now;
            if self.manifest.active_filter_id == resolved_filter_id {
                self.manifest.active_filter_id.clear();
            }
            entry.clone()
        };
        self.refresh_manifest_hashes()?;
        self.persist_manifest()?;
        Ok(entry_clone)
    }

    pub fn create_filter(
        &mut self,
        filter_id: Option<String>,
        m_bits: Option<usize>,
        k: Option<usize>,
    ) -> Result<FilterManifestEntry, ServiceError> {
        if let Some(active) = self
            .manifest
            .filters
            .iter()
            .find(|entry| entry.status == "active")
        {
            return Err(ServiceError::Invalid(format!(
                "já existe um filtro ativo: {}",
                active.filter_id
            )));
        }

        let raw_id = filter_id.unwrap_or_else(default_filter_id);
        let resolved_id = sanitize_filter_id(&raw_id);
        if resolved_id.is_empty() {
            return Err(ServiceError::Invalid("filter_id inválido".to_string()));
        }
        if self.filters.contains_key(&resolved_id) {
            return Err(ServiceError::AlreadyExists(format!(
                "filter_id já existe: {}",
                resolved_id
            )));
        }

        let resolved_m_bits = m_bits.unwrap_or_else(|| default_m_bits(&self.config));
        let resolved_k = k.unwrap_or_else(|| default_k(&self.config)).max(1);
        let (capacity_limit, _) =
            calculate_n_max_exact(resolved_m_bits, self.config.false_positive_power);
        let filter = BloomFilter::new(resolved_m_bits, resolved_k);
        let now = now_ts_u64();
        let entry = FilterManifestEntry {
            filter_id: resolved_id.clone(),
            status: default_status_active(),
            created_at: now,
            updated_at: now,
            closed_at: None,
            m_bits: resolved_m_bits,
            k: resolved_k,
            inserted_count: 0,
            capacity_limit,
            file_name: format!("{}.bloom", resolved_id),
            encoding: "base64".to_string(),
            sha256_base64: String::new(),
            download_url: build_download_url(self.config.public_base_url.as_deref(), &resolved_id),
            window_start_min: None,
            window_start_max: None,
        };

        self.filters.insert(resolved_id.clone(), filter);
        self.manifest.active_filter_id = resolved_id;
        self.manifest.updated_at = now;
        self.manifest.filters.push(entry.clone());
        self.persist_filter(&entry)?;
        self.refresh_manifest_hashes()?;
        self.persist_manifest()?;
        Ok(entry)
    }

    pub fn rotate_filter(
        &mut self,
        filter_id: Option<String>,
        m_bits: Option<usize>,
        k: Option<usize>,
    ) -> Result<FilterManifestEntry, ServiceError> {
        if self
            .manifest
            .filters
            .iter()
            .any(|entry| entry.status == "active")
        {
            self.close_filter(None)?;
        }
        self.create_filter(filter_id, m_bits, k)
    }

    pub fn reset_all_filters(
        &mut self,
        filter_id: Option<String>,
        m_bits: Option<usize>,
        k: Option<usize>,
    ) -> Result<FilterManifestEntry, ServiceError> {
        let filters_directory = filters_dir(&self.config.data_dir);
        fs::create_dir_all(&filters_directory).map_err(|e| ServiceError::Io(e.to_string()))?;

        for entry in &self.manifest.filters {
            let file_path = filter_path(&self.config.data_dir, &entry.file_name);
            if file_path.exists() {
                fs::remove_file(&file_path).map_err(|e| ServiceError::Io(e.to_string()))?;
            }
        }

        if let Ok(read_dir) = fs::read_dir(&filters_directory) {
            for entry in read_dir {
                let entry = entry.map_err(|e| ServiceError::Io(e.to_string()))?;
                let path = entry.path();
                if path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("bloom"))
                {
                    fs::remove_file(&path).map_err(|e| ServiceError::Io(e.to_string()))?;
                }
            }
        }

        self.filters.clear();
        self.manifest.active_filter_id.clear();
        self.manifest.filters.clear();
        self.manifest.updated_at = now_ts_u64();
        self.manifest.false_positive_power = self.config.false_positive_power;
        self.manifest.public_base_url = self.config.public_base_url.clone();
        self.persist_manifest()?;

        self.create_filter(filter_id, m_bits, k)
    }

    pub fn persist_manifest(&self) -> Result<(), ServiceError> {
        let bytes = serde_json::to_vec_pretty(&self.manifest)
            .map_err(|e| ServiceError::Invalid(format!("manifest serialize: {}", e)))?;
        fs::write(manifest_path(&self.config.data_dir), bytes)
            .map_err(|e| ServiceError::Io(e.to_string()))
    }

    pub fn persist_filter(&self, entry: &FilterManifestEntry) -> Result<(), ServiceError> {
        let filter = self.filters.get(&entry.filter_id).ok_or_else(|| {
            ServiceError::NotFound(format!("filtro não encontrado: {}", entry.filter_id))
        })?;
        let raw = filter.to_bytes();
        fs::write(filter_path(&self.config.data_dir, &entry.file_name), raw)
            .map_err(|e| ServiceError::Io(e.to_string()))
    }

    pub fn refresh_manifest_hashes(&mut self) -> Result<(), ServiceError> {
        let hashes = self
            .manifest
            .filters
            .iter()
            .map(|entry| {
                let encoded = self.get_filter_base64(&entry.filter_id)?;
                Ok::<(String, String), ServiceError>((
                    entry.filter_id.clone(),
                    sha256_base64(encoded.as_bytes()),
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;

        for entry in &mut self.manifest.filters {
            if let Some((_, hash)) = hashes
                .iter()
                .find(|(filter_id, _)| filter_id == &entry.filter_id)
            {
                entry.sha256_base64 = hash.clone();
            }
            entry.download_url =
                build_download_url(self.config.public_base_url.as_deref(), &entry.filter_id);
        }
        self.manifest.updated_at = now_ts_u64();
        Ok(())
    }
}

impl BloomFilter {
    pub fn new(m_bits: usize, k: usize) -> Self {
        Self {
            m_bits,
            k,
            bits: bitvec![u8, Lsb0; 0; m_bits],
        }
    }

    fn hash_indexes(&self, data: &[u8]) -> Vec<usize> {
        let mut hasher = Shake256::default();
        hasher.update(data);
        let mut reader = hasher.finalize_xof();

        let mut idx_list = Vec::with_capacity(self.k);

        for _ in 0..self.k {
            let mut buf = [0u8; 8];
            reader.read(&mut buf);
            let x = u64::from_le_bytes(buf);
            idx_list.push((x % self.m_bits as u64) as usize);
        }

        idx_list
    }

    /// Insere um hash (qualquer dado) no Bloom Filter
    pub fn insert(&mut self, data: &[u8]) {
        for idx in self.hash_indexes(data) {
            self.bits.set(idx, true);
        }
    }

    /// Verifica se possivelmente existe (com falso positivo possível)
    pub fn contains(&self, data: &[u8]) -> bool {
        self.hash_indexes(data).iter().all(|&i| self.bits[i])
    }

    /// Serializa o Bloom Filter no formato cru usado em disco.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(16 + self.bits.as_raw_slice().len());

        // Header
        buffer.extend_from_slice(&(self.m_bits as u64).to_le_bytes());
        buffer.extend_from_slice(&(self.k as u64).to_le_bytes());

        // Payload (bits crus)
        buffer.extend_from_slice(self.bits.as_raw_slice());

        buffer
    }

    /// Serializa o Bloom Filter em Base64 para a API pública.
    pub fn to_base64(&self) -> String {
        general_purpose::STANDARD.encode(self.to_bytes())
    }

    /// Desserializa um Bloom Filter a partir do formato cru usado em disco.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 16 {
            return Err("Dados insuficientes para header".into());
        }

        // Header
        let m_bits = u64::from_le_bytes(data[0..8].try_into().unwrap()) as usize;
        let k = u64::from_le_bytes(data[8..16].try_into().unwrap()) as usize;

        // Payload
        let raw_bits = &data[16..];
        let expected_bytes = m_bits.div_ceil(8);

        if raw_bits.len() != expected_bytes {
            return Err(format!(
                "Tamanho inválido do BitVec: esperado {}, recebido {}",
                expected_bytes,
                raw_bits.len()
            ));
        }

        let bits = BitVec::<u8, Lsb0>::from_slice(raw_bits);

        Ok(Self { m_bits, k, bits })
    }

    /// Desserializa um Bloom Filter a partir de Base64.
    pub fn from_base64(encoded: &str) -> Result<Self, String> {
        let data = general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| format!("Erro Base64: {}", e))?;
        Self::from_bytes(&data)
    }

    /// Carrega bytes de storage aceitando tanto o formato binário atual
    /// quanto o formato legado em Base64.
    pub fn from_storage_bytes(data: &[u8]) -> Result<(Self, bool), String> {
        match Self::from_bytes(data) {
            Ok(filter) => Ok((filter, false)),
            Err(raw_error) => {
                let encoded = std::str::from_utf8(data)
                    .map(str::trim)
                    .map_err(|_| raw_error.clone())?;
                let filter = Self::from_base64(encoded).map_err(|base64_error| {
                    format!(
                        "não foi possível ler filtro binário ({}) nem legado Base64 ({})",
                        raw_error, base64_error
                    )
                })?;
                Ok((filter, true))
            }
        }
    }
}

/// Calcula a quantidade máxima aproximada de elementos N que cabem no Bloom Filter.
///
/// Fórmula aproximada:
///     p ≈ (0.6185)^(m/n)
/// =>  n ≈ m * ln(0.6185) / ln(p)
///
/// m_bits  = quantidade de bits disponível
/// false_positive_power = expoente do 2^-k (ex: 32 para prob = 2^-32)
pub fn calculate_n_max(m_bits: usize, false_positive_power: u32) -> f64 {
    let p = 2f64.powf(-(false_positive_power as f64)); // p = 2^-k
    let ln_p = p.ln();
    let ln_06185 = 0.6185f64.ln();

    // n ≈ (m * ln(0.6185)) / ln(p)
    (m_bits as f64 * ln_06185) / ln_p
}

/// Número ótimo de funções hash k.
///
/// k_opt = (m/n) * ln(2)
pub fn calculate_k_opt(m_bits: usize, n: f64) -> f64 {
    (m_bits as f64 / n) * std::f64::consts::LN_2
}

/// Probabilidade exata de falso positivo para dado m, k, n.
///
/// Fórmula:
/// p = (1 - (1 - 1/m)^(k*n))^k
pub fn false_positive_probability(m_bits: usize, k: usize, n: usize) -> f64 {
    if n == 0 || k == 0 {
        return 0.0;
    }

    let m = m_bits as f64;
    let kf = k as f64;
    let nf = n as f64;

    let one_minus_1_over_m = 1.0 - 1.0 / m;
    let inner = 1.0 - one_minus_1_over_m.powf(kf * nf);
    inner.powf(kf)
}

/// Dado m_bits, k e p_target, encontra o MAIOR n tal que
/// false_positive_probability(m_bits, k, n) <= p_target.
///
/// Usa busca binária em n.
pub fn max_n_for_k(m_bits: usize, k: usize, p_target: f64) -> usize {
    let mut low: usize = 0;
    let mut high: usize = m_bits; // limite bem conservador

    while low < high {
        // mid inclinado para cima (queremos o maior n)
        let mid = (low + high + 1) / 2;
        let p_mid = false_positive_probability(m_bits, k, mid);

        if p_mid <= p_target {
            low = mid; // cabe, tenta mais
        } else {
            high = mid - 1; // estourou, recua
        }
    }

    low
}

/// Cálculo EXATO: dado m_bits e 2^-false_positive_power,
/// varre k em [1..=k_max] e devolve o par (n_max, k_melhor)
/// que suporta o MAIOR número de elementos com p <= alvo.
pub fn calculate_n_max_exact(m_bits: usize, false_positive_power: u32) -> (usize, usize) {
    let p_target = 2f64.powf(-(false_positive_power as f64));

    let k_max = 64.min(m_bits); // limite superior razoável
    let mut best_n: usize = 0;
    let mut best_k: usize = 1;

    for k in 1..=k_max {
        let n_k = max_n_for_k(m_bits, k, p_target);
        if n_k > best_n {
            best_n = n_k;
            best_k = k;
        }
    }

    (best_n, best_k)
}

#[cfg(test)]
mod tests {
    const FILTER_BYTES: usize = 1024 * 1024 * 2;
    const FALSE_POSITIVE_POWER: u32 = 32;

    use super::*;
    use rand::Rng;
    use rand::RngCore;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use rayon::ThreadPoolBuilder;
    use rayon::prelude::*;
    use sha2::{Digest as Sha2Digest, Sha256};
    use std::cmp::{max, min};
    use std::io::{self, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_calculo_n_para_4096_bytes_2_pow_32() {
        let m_bits = 4096 * 8;
        let n = calculate_n_max(m_bits, 32);
        println!("Capacidade aproximada (p=2^-32): n ≈ {}", n);
        assert!(n > 600.0 && n < 900.0); // valor esperado ≈ 710
    }

    #[test]
    fn test_calculo_n_para_4096_bytes_2_pow_10() {
        let m_bits = 4096 * 8;
        let n = calculate_n_max(m_bits, 10);
        println!("Capacidade aproximada (p=2^-10): n ≈ {}", n);
        assert!(n > 2000.0 && n < 2600.0); // valor esperado ≈ 2270
    }

    #[test]
    fn test_matriz_capacidade_exaustao_para_tamanhos_comuns() {
        const SIZES_MB: [usize; 5] = [2, 4, 8, 16, 32];
        const EXPECTED_CAPACITY_LIMITS: [usize; 5] = [363408, 726817, 1453634, 2907269, 5814539];
        const EXPECTED_ROTATE_THRESHOLDS: [usize; 5] = [345238, 690477, 1380953, 2761906, 5523813];
        const EXPECTED_K: usize = 32;

        let p_target = 2f64.powf(-(FALSE_POSITIVE_POWER as f64));
        let mut previous_capacity_limit = 0usize;

        println!("Matriz de capacidade teorica do Bloom Filter");
        println!("Meta de falso positivo: 2^-{}", FALSE_POSITIVE_POWER);
        println!(
            "{:<6} {:>12} {:>14} {:>8} {:>14} {:>14} {:>14}",
            "MB", "m_bits", "n_aprox", "k", "capacity_limit", "rotacao_95%", "p(n_limit)"
        );

        for ((size_mb, expected_capacity_limit), expected_rotate_threshold) in SIZES_MB
            .into_iter()
            .zip(EXPECTED_CAPACITY_LIMITS)
            .zip(EXPECTED_ROTATE_THRESHOLDS)
            .map(|((size_mb, expected_capacity_limit), expected_rotate_threshold)| {
                ((size_mb, expected_capacity_limit), expected_rotate_threshold)
            })
        {
            let filter_bytes = size_mb * 1024 * 1024;
            let m_bits = filter_bytes * 8;
            let n_aprox = calculate_n_max(m_bits, FALSE_POSITIVE_POWER);
            let (capacity_limit, best_k) = calculate_n_max_exact(m_bits, FALSE_POSITIVE_POWER);
            let rotate_threshold = rotation_trigger_count(capacity_limit, 95);
            let p_at_limit = false_positive_probability(m_bits, best_k, capacity_limit);
            let p_after_limit = false_positive_probability(m_bits, best_k, capacity_limit + 1);

            println!(
                "{:<6} {:>12} {:>14.0} {:>8} {:>14} {:>14} {:>14.6e}",
                size_mb,
                m_bits,
                n_aprox,
                best_k,
                capacity_limit,
                rotate_threshold,
                p_at_limit
            );

            assert!(
                capacity_limit > previous_capacity_limit,
                "capacity_limit deveria crescer com o tamanho do filtro"
            );
            assert_eq!(
                best_k, EXPECTED_K,
                "k exato deveria permanecer estavel para os tamanhos testados"
            );
            assert_eq!(
                capacity_limit, expected_capacity_limit,
                "capacity_limit mudou para {} MB",
                size_mb
            );
            assert_eq!(
                rotate_threshold, expected_rotate_threshold,
                "limiar de rotacao mudou para {} MB",
                size_mb
            );
            assert!(
                p_at_limit <= p_target,
                "capacity_limit deve manter a taxa alvo de falso positivo"
            );
            assert!(
                p_after_limit > p_target,
                "capacity_limit deve ser o maior n que ainda respeita a taxa alvo"
            );

            previous_capacity_limit = capacity_limit;
        }
    }

    #[test]
    fn test_insercao_e_consulta_no_bloom_filter() {
        let m_bits = 4096 * 8;
        let n_est = calculate_n_max(m_bits, 10);
        let k_opt = calculate_k_opt(m_bits, n_est).ceil() as usize;

        println!("n estimado = {}", n_est);
        println!("k ótimo ≈ {}", k_opt);

        let mut bf = BloomFilter::new(m_bits, k_opt);

        let hash1 = Sha256::digest(b"credencial_A");
        let hash2 = Sha256::digest(b"credencial_B");

        bf.insert(&hash1);
        assert!(bf.contains(&hash1)); // nunca falso negativo

        // hash2 nunca foi inserido — pode dar false ou true (falso positivo)
        let result = bf.contains(&hash2);
        println!("hash2 presente? {}", result);

        let result = bf.contains(&hash1);
        println!("hash1 presente? {}", result);
    }

    #[test]
    fn test_quantidade_de_bits_ativos_no_filtro_padrao_aos_95_porcento_da_capacidade() {
        let temp_dir = tempfile::tempdir().expect("temp dir should be created");
        let config = ServiceConfig {
            data_dir: temp_dir.path().to_path_buf(),
            filter_bytes: FILTER_BYTES,
            false_positive_power: FALSE_POSITIVE_POWER,
            public_base_url: None,
            rotate_at_percent: 95,
        };

        let service = BloomService::load_or_initialize(config).expect("service should initialize");
        let manifest = service.manifest();
        let active_entry = manifest
            .filters
            .iter()
            .find(|entry| entry.filter_id == manifest.active_filter_id)
            .expect("active filter should exist");

        let target_insert_count = rotation_trigger_count(active_entry.capacity_limit, 95);
        let mut bf = BloomFilter::new(active_entry.m_bits, active_entry.k);

        for index in 0..target_insert_count {
            let hash = Sha256::digest(index.to_le_bytes());
            bf.insert(&hash);
        }

        let bits_ativos = bf.bits.iter().filter(|bit| **bit).count();
        let taxa_bits_ativos = bits_ativos as f64 / active_entry.m_bits as f64;
        let taxa_teorica = 1.0
            - (1.0 - 1.0 / active_entry.m_bits as f64)
                .powf((active_entry.k * target_insert_count) as f64);

        println!("Filtro padrão (bytes): {}", FILTER_BYTES);
        println!("m_bits: {}", active_entry.m_bits);
        println!("k: {}", active_entry.k);
        println!("capacity_limit: {}", active_entry.capacity_limit);
        println!("inserted_count_95_percent: {}", target_insert_count);
        println!("bits_ativos: {}", bits_ativos);
        println!("taxa_bits_ativos: {:.6}", taxa_bits_ativos);
        println!("taxa_teorica: {:.6}", taxa_teorica);

        assert!(bits_ativos > 0);
        assert!(bits_ativos < active_entry.m_bits);
        assert!((taxa_bits_ativos - taxa_teorica).abs() < 0.01);
    }

    // -----------------------------------------------------------------------
    // Teste real de saturação do Bloom Filter
    // -----------------------------------------------------------------------
    fn test_saturacao_bloom_filter() -> usize {
        let m_bits = FILTER_BYTES * 8;

        // Capacidade teórica
        let n_teorico = calculate_n_max(m_bits, FALSE_POSITIVE_POWER);
        let k_opt = calculate_k_opt(m_bits, n_teorico);

        // println!("Tamanho do filtro: {} bytes", FILTER_BYTES);
        // println!("Bits: {}", m_bits);
        // println!("Probabilidade alvo: 2^-{}", FALSE_POSITIVE_POWER);
        // println!("Capacidade teórica ≈ {:.2} elementos", n_teorico);
        // println!("k ótimo ≈ {}", k_opt);

        let mut bf = BloomFilter::new(m_bits, k_opt as usize);
        let mut inseridos: Vec<[u8; 32]> = Vec::new();
        let mut rng = rand::rng();

        let mut count = 0usize;

        let mut lcount = 0;

        loop {
            // Gera hash aleatório (simulando hash de credencial)
            let mut random_data = [0u8; 32];
            rng.fill(&mut random_data);

            // Insere no Bloom
            bf.insert(&random_data);
            inseridos.push(random_data);

            // Testa ausência de falso negativo (NUNCA deve acontecer)
            assert!(bf.contains(&random_data), "FALSO NEGATIVO DETECTADO!");

            count += 1;

            // Testa falso positivo com hash que NÃO foi inserido

            let mut ver = false;
            for _ct in 0..50 {
                let mut random_test = [0u8; 32];
                rng.fill(&mut random_test);

                if bf.contains(&random_test) {
                    // println!(">>> FALSO POSITIVO detectado!");
                    // println!("Elementos inseridos até a saturação real: {}", count);
                    // println!("Capacidade teórica calculada: {:.2}", n_teorico);
                    // println!("Diferença: {:.2}%", (count as f64 / n_teorico) * 100.0);

                    lcount = count;
                    ver = true;
                    break;
                }
            }

            if ver == true {
                break;
            }
            // Evita loop gigante em testes automáticos
            // if count > (n_teorico * 3.0) as usize {
            //     // panic!("Bloom Filter não saturou até 3x o valor teórico — algo está errado.");
            //     println!("Bloom Filter não saturou até 3x o valor teórico — algo está errado.");
            // }
        }

        lcount

        // assert!(count > 10); // sanity check
    }

    #[test]
    fn test_bf() {
        let total = 100000;
        let m_bits = FILTER_BYTES * 8;

        // Capacidade teórica
        let n_teorico = calculate_n_max(m_bits, FALSE_POSITIVE_POWER);
        let k_opt = calculate_k_opt(m_bits, n_teorico);

        println!("Tamanho do filtro: {} bytes", FILTER_BYTES);
        println!("Bits: {}", m_bits);
        println!("Probabilidade alvo: 2^-{}", FALSE_POSITIVE_POWER);
        println!("Capacidade teórica ≈ {:.2} elementos", n_teorico);
        println!("k ótimo ≈ {}", k_opt);

        let mut min_value = 1_000_000_000;
        let mut max_value = 0;

        for ct in 0..total {
            if ct % 500 == 0 {
                println!("{}", ct);
            }
            let v = test_saturacao_bloom_filter();
            max_value = max(v, max_value);
            min_value = min(v, min_value);
        }

        println!("{}", "=".repeat(80));
        println!("Valor Mínimo antes do erro: {}", min_value);
        println!("Valor Máximo antes do erro: {}", max_value);
    }

    fn test_saturacao_bloom_filter_com_k(m_bits: usize, k: usize) -> usize {
        let total_tentativas = 100;
        let mut bf = BloomFilter::new(m_bits, k);
        let mut rng = rand::rng();

        let mut count = 0usize;

        loop {
            // Gera hash aleatório
            let mut random_data = [0u8; 32];
            rng.fill(&mut random_data);

            bf.insert(&random_data);
            assert!(bf.contains(&random_data));

            count += 1;
            if count % 100000 == 0 {
                println!("Inseridos Até o momento: {}", count);
            }

            // Testa falso positivo com valor NÃO inserido
            for _ct in 0..total_tentativas {
                let mut random_test = [0u8; 32];
                rng.fill(&mut random_test);

                if bf.contains(&random_test) {
                    // let encoded = bf.to_base64();
                    // println!("Tamanho do filtro (base64) = {}", encoded.len());

                    return count;
                }
            }
        }
    }

    #[test]
    fn test_b2f() {
        let total = 10_000;
        let m_bits = FILTER_BYTES * 8;

        // Cálculo EXATO
        let (n_exato, k_exato) = calculate_n_max_exact(m_bits, FALSE_POSITIVE_POWER);

        println!("Tamanho do filtro: {} bytes", FILTER_BYTES);
        println!("Bits: {}", m_bits);
        println!("Probabilidade alvo: 2^-{}", FALSE_POSITIVE_POWER);
        println!("Capacidade EXATA ≈ {} elementos", n_exato);
        println!("k ótimo EXATO ≈ {}", k_exato);

        let mut min_value = usize::MAX;
        let mut max_value = 0usize;

        for ct in 0..total {
            if ct % 1000 == 0 {
                println!("{}", ct);
            }
            let v = test_saturacao_bloom_filter_com_k(m_bits, k_exato);
            max_value = max(v, max_value);
            min_value = min(v, min_value);
        }

        println!("{}", "=".repeat(80));
        println!("Valor Mínimo antes do erro: {}", min_value);
        println!("Valor Máximo antes do erro: {}", max_value);

        // Sanidade: a saturação real deve ficar na vizinhança de n_exato
        assert!(min_value > n_exato / 2);
    }

    fn print_progress_bar(done: usize, total: usize) {
        let width = 50; // largura da barra
        let ratio = done as f64 / total as f64;
        let filled = (ratio * width as f64).round() as usize;
        let percent = ratio * 100.0;

        let mut bar = String::with_capacity(width + 32);
        bar.push('[');
        for i in 0..width {
            if i < filled {
                bar.push('=');
            } else if i == filled {
                bar.push('>');
            } else {
                bar.push('.');
            }
        }
        bar.push(']');
        bar.push(' ');
        bar.push_str(&format!("{:6.2}%", percent));

        print!("\r{}", bar);
        io::stdout().flush().unwrap();
    }

    // ============================================================================================
    #[test]
    fn test_bloom_filter_overflow_and_error_rates() {
        use rand::Rng;

        let m_bits = FILTER_BYTES * 8;

        // ------------------------------------------------------------
        // Cálculo EXATO de capacidade e k ótimo
        // ------------------------------------------------------------
        let (n_exato, k_exato) = calculate_n_max_exact(m_bits, FALSE_POSITIVE_POWER);

        println!("Bits           : {}", m_bits);
        println!("Capacidade exata: {}", n_exato);
        println!("k ótimo         : {}", k_exato);
        println!("Prob alvo       : 2^-{}", FALSE_POSITIVE_POWER);

        let mut bf = BloomFilter::new(m_bits, k_exato);
        let mut rng = rand::rng();

        // ------------------------------------------------------------
        // FASE 1 — Inserção até a capacidade máxima (SEM ERRO)
        // ------------------------------------------------------------
        let mut inserted: Vec<[u8; 32]> = Vec::with_capacity(n_exato);

        for _ in 0..n_exato {
            let mut value = [0u8; 32];
            rng.fill(&mut value);

            bf.insert(&value);
            inserted.push(value);

            // Nunca pode haver falso negativo
            assert!(bf.contains(&value), "FALSO NEGATIVO antes da saturação!");
        }

        println!("Fase 1 concluída — filtro saturado sem erros.");

        // ------------------------------------------------------------
        // FASE 3 — Teste de valores NÃO inseridos (falso positivo)
        // (PARALELO + THREADS CONFIGURÁVEIS + PROGRESSO GLOBAL)
        // ------------------------------------------------------------

        // ======================== CONFIGURAÇÃO ======================
        let tests_fp = 100_000_000usize;

        // Número de threads:
        // 0 => todas disponíveis
        // N => força exatamente N threads
        let num_threads: usize = 8;

        // Atualização do progresso a cada X iterações
        let progress_step: usize = 100_000;
        // ============================================================

        // Referências somente leitura
        let bf_ref = &bf;
        let inserted_ref = &inserted;

        // Contador global de progresso
        let progress = AtomicUsize::new(0);

        // Criação do pool dedicado
        let pool = if num_threads == 0 {
            ThreadPoolBuilder::new().build().unwrap()
        } else {
            ThreadPoolBuilder::new()
                .num_threads(num_threads)
                .build()
                .unwrap()
        };

        let false_positives: usize = pool.install(|| {
            (0..tests_fp)
                .into_par_iter()
                .map_init(
                    || StdRng::seed_from_u64(0xDEADBEEF),
                    |rng, _| {
                        // ------------------ PROGRESSO ------------------
                        let current = progress.fetch_add(1, Ordering::Relaxed) + 1;
                        if current % progress_step == 0 {
                            let pct = (current as f64 / tests_fp as f64) * 100.0;
                            println!("Progresso: {:6.2}%", pct);
                        }
                        // ------------------------------------------------

                        let mut random_test = [0u8; 32];
                        rng.fill_bytes(&mut random_test);

                        if inserted_ref.contains(&random_test) {
                            return 0;
                        }

                        if bf_ref.contains(&random_test) { 1 } else { 0 }
                    },
                )
                .sum()
        });

        let fp_rate = false_positives as f64 / tests_fp as f64;

        println!("============================================================");
        println!("Testes de ausência          : {}", tests_fp);
        println!("Falsos positivos detectados: {}", false_positives);
        println!("Taxa real de FP             : {:.8}", fp_rate);
        println!(
            "Prob alvo teórica           : {:.8}",
            2f64.powf(-(FALSE_POSITIVE_POWER as f64))
        );

        assert!(
            fp_rate < 0.01,
            "Bloom Filter totalmente degradado — FP excessivo!"
        );
    }

    // ============================================================================================
    #[test]
    fn test_bloom_filter_base64_roundtrip() {
        use rand::Rng;
        use sha2::{Digest, Sha256};

        let m_bits = 4096 * 8;
        let k = 7;

        let mut bf = BloomFilter::new(m_bits, k);
        let mut rng = rand::rng();

        let mut inserted = Vec::new();

        // Inserções
        for _ in 0..10000 {
            let mut data = [0u8; 32];
            rng.fill(&mut data);

            let hash = Sha256::digest(&data);
            bf.insert(&hash);
            inserted.push(hash.to_vec());
        }

        // println!("bf[1]: {:?}", bf);

        // Serializa
        let encoded = bf.to_base64();
        assert!(!encoded.is_empty());

        println!("BF: {}", encoded);

        // Desserializa
        let bf_restored =
            BloomFilter::from_base64(&encoded).expect("Falha ao restaurar Bloom Filter");

        // Metadados preservados
        assert_eq!(bf_restored.m_bits, bf.m_bits);
        assert_eq!(bf_restored.k, bf.k);
        assert_eq!(bf_restored.bits, bf.bits);

        // println!("bf[2]: {:?}", bf_restored);

        // Nunca pode haver falso negativo
        for value in &inserted {
            assert!(
                bf_restored.contains(value),
                "FALSO NEGATIVO após desserialização!"
            );
        }
    }

    #[test]
    fn test_bloom_filter_raw_roundtrip() {
        use rand::Rng;
        use sha2::{Digest, Sha256};

        let m_bits = 4096 * 8;
        let k = 7;

        let mut bf = BloomFilter::new(m_bits, k);
        let mut rng = rand::rng();

        let mut inserted = Vec::new();

        for _ in 0..10000 {
            let mut data = [0u8; 32];
            rng.fill(&mut data);

            let hash = Sha256::digest(&data);
            bf.insert(&hash);
            inserted.push(hash.to_vec());
        }

        let raw = bf.to_bytes();
        assert_eq!(raw.len(), 16 + m_bits.div_ceil(8));

        let bf_restored =
            BloomFilter::from_bytes(&raw).expect("Falha ao restaurar Bloom Filter bruto");

        assert_eq!(bf_restored.m_bits, bf.m_bits);
        assert_eq!(bf_restored.k, bf.k);
        assert_eq!(bf_restored.bits, bf.bits);

        for value in &inserted {
            assert!(
                bf_restored.contains(value),
                "FALSO NEGATIVO após desserialização bruta!"
            );
        }
    }

    // ================================================================================================
    #[test]
    fn test_b3f() {
        let tentativas = 1;

        let mut v0: usize = 2usize.pow(63);
        let mut v1: usize = 0;

        for ct in 0..tentativas {
            println!("{}", "=".repeat(80));
            println!("Teste {}/{} \n", ct + 1, tentativas);
            let total = 10;
            let m_bits = FILTER_BYTES * 8;

            // 0 = usar todas as threads disponíveis
            let num_threads = 10;

            // Cria thread pool personalizada
            let pool = if num_threads == 0 {
                ThreadPoolBuilder::new().build().unwrap()
            } else {
                ThreadPoolBuilder::new()
                    .num_threads(num_threads)
                    .build()
                    .unwrap()
            };

            pool.install(|| {
                // Cálculo EXATO
                let (n_exato, k_exato) = calculate_n_max_exact(m_bits, FALSE_POSITIVE_POWER);

                // k_exato = 10;

                println!("Tamanho do filtro: {} bytes", FILTER_BYTES);
                println!("Bits: {}", m_bits);
                println!("Probabilidade alvo: 2^-{}", FALSE_POSITIVE_POWER);
                println!("Capacidade EXATA ≈ {} elementos", n_exato);
                println!("k ótimo EXATO ≈ {}", k_exato);

                let progress = AtomicUsize::new(0);

                // Execução paralela
                let results: Vec<usize> = (0..total)
                    .into_par_iter()
                    .map(|_| {
                        let v = test_saturacao_bloom_filter_com_k(m_bits, k_exato);

                        // Atualiza progresso
                        let done = progress.fetch_add(1, Ordering::Relaxed) + 1;
                        if done % 10 == 0 || done == total {
                            print_progress_bar(done, total);
                        }

                        v
                    })
                    .collect();

                // Quebra de linha depois da barra
                println!();

                let min_value = *results.iter().min().unwrap();
                let max_value = *results.iter().max().unwrap();

                println!("{}", "=".repeat(80));
                println!("Valor Mínimo antes do erro: {}", min_value);
                println!("Valor Máximo antes do erro: {}", max_value);
                println!("{}", "=".repeat(80));

                if v0 > min_value {
                    v0 = min_value;
                }
                if v1 < max_value {
                    v1 = max_value;
                }

                // Sanidade: a saturação real deve ficar na vizinhança de n_exato
                assert!(min_value > n_exato / 2);
            });
        }

        println!("Valor Mínimo antes do erro: {}", v0);
        println!("Valor Máximo antes do erro: {}", v1);

        // Cálculo EXATO
        let m_bits = FILTER_BYTES * 8;
        let (n_exato, k_exato) = calculate_n_max_exact(m_bits, FALSE_POSITIVE_POWER);
        println!("Tamanho do filtro: {} bytes", FILTER_BYTES);
        println!("Bits: {}", m_bits);
        println!("Probabilidade alvo: 2^-{}", FALSE_POSITIVE_POWER);
        println!("Capacidade EXATA ≈ {} elementos", n_exato);
        println!("k ótimo EXATO ≈ {}", k_exato);
    }

    #[test]
    fn test_b3f_scientific_option_a() {
        use rand::RngCore;
        use rand::SeedableRng;
        use rand::rngs::StdRng;
        use rayon::ThreadPoolBuilder;
        use rayon::prelude::*;
        use std::collections::HashSet;
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

        // -------------------- Parâmetros do experimento --------------------
        let m_bits = FILTER_BYTES * 8;

        // Dimensiona (n_exato, k_exato) para p_target = 2^-FALSE_POSITIVE_POWER
        let (n_exato, k_exato) = calculate_n_max_exact(m_bits, FALSE_POSITIVE_POWER);
        let p_target = 2f64.powf(-(FALSE_POSITIVE_POWER as f64));

        println!("============================================================");
        println!("Bloom scientific test (Option A) — FP rate @ n_exato");
        println!("FILTER_BYTES   : {}", FILTER_BYTES);
        println!("m_bits         : {}", m_bits);
        println!(
            "p_target       : 2^-{}  (≈ {:.12e})",
            FALSE_POSITIVE_POWER, p_target
        );
        println!("n_exato        : {}", n_exato);
        println!("k_exato        : {}", k_exato);

        // -------------------- 1) Construção do Bloom + Inserção --------------------
        let mut bf = BloomFilter::new(m_bits, k_exato);

        // RNG determinístico para inserção
        let mut rng_ins = StdRng::seed_from_u64(0xB10F_1A53_2026);

        // Amostra de inseridos para sanity-check (não é necessário guardar todos)
        let sample_keep: usize = 100_000.min(n_exato);
        let mut inserted_sample: HashSet<[u8; 32]> = HashSet::with_capacity(sample_keep);

        for i in 0..n_exato {
            let mut value = [0u8; 32];
            rng_ins.fill_bytes(&mut value);

            // Domínio "inserção": força byte[0] = 0xAA para garantir disjunção dos probes
            value[0] = 0xAA;

            bf.insert(&value);

            // Nunca pode haver falso negativo
            assert!(bf.contains(&value), "FALSO NEGATIVO na inserção #{}", i);

            if i < sample_keep {
                inserted_sample.insert(value);
            }
        }

        println!("Inserção concluída: {} elementos.", n_exato);

        // -------------------- 2) Diagnóstico: fill ratio --------------------
        let ones = bf.bits.count_ones();
        let fill_real = ones as f64 / bf.m_bits as f64;

        let expected_fill = 1.0 - (-(bf.k as f64) * (n_exato as f64) / (bf.m_bits as f64)).exp();

        println!("------------------------------------------------------------");
        println!("Fill real     : {:.6}", fill_real);
        println!("Fill esperado : {:.6}", expected_fill);

        // Se isso falhar (ex.: fill_real ~ 0.99), há bug na geração de índices ou k efetivo.
        assert!(
            (fill_real - expected_fill).abs() < 0.08,
            "Fill muito diferente do esperado (real={:.6}, esperado={:.6}). \
         Suspeite de hash_indexes() / k efetivo / distribuição de índices.",
            fill_real,
            expected_fill
        );

        // -------------------- 3) Medição de falso positivo (probes ausentes) --------------------
        // Observação: com p_target=2^-32 é normal obter FP=0 em T=50M.
        let tests_fp: usize = 100_000_000;

        // Paralelismo controlado
        let num_threads: usize = 10;
        let pool = if num_threads == 0 {
            ThreadPoolBuilder::new().build().unwrap()
        } else {
            ThreadPoolBuilder::new()
                .num_threads(num_threads)
                .build()
                .unwrap()
        };

        let fp_count = AtomicUsize::new(0);

        // Seeds únicas por worker (evita cada thread começar com o mesmo RNG)
        let seed_alloc = AtomicU64::new(0xF0A7_3E57_2026);

        // Progresso (opcional)
        let progress = AtomicUsize::new(0);
        let progress_step: usize = 5_000_000;

        pool.install(|| {
            (0..tests_fp).into_par_iter().for_each_init(
                || {
                    let s = seed_alloc.fetch_add(1, Ordering::Relaxed);
                    StdRng::seed_from_u64(s)
                },
                |rng, _| {
                    // Progresso (não essencial; pode remover se quiser mais performance)
                    let done = progress.fetch_add(1, Ordering::Relaxed) + 1;
                    if done % progress_step == 0 {
                        let pct = (done as f64 / tests_fp as f64) * 100.0;
                        println!("Progresso probes: {:6.2}%", pct);
                    }

                    let mut probe = [0u8; 32];
                    rng.fill_bytes(&mut probe);

                    // Domínio "probe": força byte[0] = 0x55 (disjunto dos inseridos)
                    probe[0] = 0x55;

                    // Auditoria: se por algum acaso um probe caiu na amostra de inseridos,
                    // não conte como falso positivo.
                    if inserted_sample.contains(&probe) {
                        return;
                    }

                    if bf.contains(&probe) {
                        fp_count.fetch_add(1, Ordering::Relaxed);
                    }
                },
            );
        });

        let fp = fp_count.load(Ordering::Relaxed);
        let fp_rate = fp as f64 / tests_fp as f64;

        println!("============================================================");
        println!("Testes de ausência          : {}", tests_fp);
        println!("Falsos positivos detectados : {}", fp);
        println!("Taxa real de FP (estimada)  : {:.12e}", fp_rate);
        println!("Taxa alvo teórica           : {:.12e}", p_target);

        // -------------------- 4) Critério de aceitação (estatisticamente defensável) --------------------
        // - Se FP=0: limite superior ~95% ≈ 3/T (aprox Poisson)
        // - Se FP>0: compare fp_rate com p_target com folga (ex.: 50x) para tolerar ruído.
        if fp == 0 {
            let upper_95 = 3.0 / tests_fp as f64;
            println!("FP=0 => limite superior ~95%: p <= {:.12e}", upper_95);

            // Critério: o limite superior deve ser "próximo" do alvo (ordem de grandeza).
            // Para 50M e 2^-32, upper_95/p_target ≈ 258 (aceitável como evidência limitada).
            let factor = upper_95 / p_target;
            println!("upper_95 / p_target ≈ {:.2}", factor);

            assert!(
                factor < 10_000.0,
                "Evidência empírica fraca (upper_95 muito maior que p_target). \
             Aumente tests_fp ou use alvo menos extremo para observar FP."
            );
        } else {
            let tolerance = 50.0; // ajuste conforme rigor desejado
            assert!(
                fp_rate <= tolerance * p_target,
                "FP rate acima do esperado: {:.3e} > {}*p_target ({:.3e})",
                fp_rate,
                tolerance,
                tolerance * p_target
            );
        }
    }
}
