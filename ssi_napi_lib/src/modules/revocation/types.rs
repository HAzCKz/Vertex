use serde::{Deserialize, Serialize};

pub const DEFAULT_EXTRA_WINDOWS_FOR_FP: u32 = 10;
pub const DEFAULT_MAX_WINDOWS_TO_REQUEST: u32 = DEFAULT_EXTRA_WINDOWS_FOR_FP;
pub const DEFAULT_MAX_CONSECUTIVE_HITS_FOR_REVOKE: u32 = DEFAULT_MAX_WINDOWS_TO_REQUEST + 1;

fn default_max_consecutive_hits_for_revoke() -> u32 {
    DEFAULT_MAX_CONSECUTIVE_HITS_FOR_REVOKE
}

fn default_max_windows_to_request() -> u32 {
    DEFAULT_MAX_WINDOWS_TO_REQUEST
}

fn default_holder_must_disprove_with_additional_windows() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KVectorRecord {
    pub issuer_did: String,
    pub k_vector_id: String,
    pub version: u32,
    pub hash_algorithm: String,
    pub vector_hash: String,
    pub values: Vec<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KChunkRecord {
    pub k_vector_id: String,
    pub index: u32,
    pub total: u32,
    pub key: String,
    pub value_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KLedgerAnchor {
    pub issuer_did: String,
    pub k_vector_id: String,
    pub version: u32,
    pub hash_algorithm: String,
    pub vector_hash: String,
    pub value_count: usize,
    pub value_size_bytes: usize,
    pub total_bytes: usize,
    pub chunk_count: u32,
    pub chunk_size_bytes: usize,
    pub index_key: String,
    pub chunk_prefix: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestAnchor {
    pub issuer_did: String,
    pub manifest_url: String,
    pub manifest_hash: String,
    pub manifest_version: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationSetupRecord {
    pub issuer_did: String,
    pub active_k_ledger_anchor: KLedgerAnchor,
    pub active_k_vector: KVectorRecord,
    pub manifest: Option<ManifestAnchor>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RevocationControlValues {
    #[serde(default)]
    pub seed: String,
    #[serde(default)]
    pub start_time: i64,
    #[serde(default)]
    pub validity_end: i64,
    #[serde(default)]
    pub unit_of_time: String,
    #[serde(default)]
    pub time_window: u32,
    #[serde(default)]
    pub extra_windows_for_fp: u32,
    #[serde(default)]
    pub root_merkle_l: String,
    #[serde(default)]
    pub window_count: u32,
    #[serde(default)]
    pub base_window_count: u32,
    #[serde(default)]
    pub confirmation_window_count: u32,
    #[serde(default)]
    pub last_valid_window_index: u32,
    #[serde(default)]
    pub last_confirmation_window_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TEntry {
    pub k_indices: Vec<u16>,
    pub tmp_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SEntry {
    pub k_values_b64: Vec<String>,
    pub tmp_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RevocationVectorsSummary {
    #[serde(default)]
    pub window_count: u32,
    #[serde(default)]
    pub tmp_count: usize,
    #[serde(default)]
    pub l_count: usize,
    #[serde(default)]
    pub t_count: usize,
    #[serde(default)]
    pub s_count: usize,
    #[serde(default)]
    pub l_size_bytes: usize,
    #[serde(default)]
    pub tmp_size_bytes: usize,
    #[serde(default)]
    pub s_size_bytes: usize,
    #[serde(default)]
    pub t_compact_size_bits: usize,
    #[serde(default)]
    pub t_compact_size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HolderRevocationBundle {
    pub credential_id: Option<String>,
    pub cred_def_id: String,
    pub schema_id: String,
    pub issuer_did: String,
    pub control: RevocationControlValues,
    #[serde(default)]
    pub k_ledger_anchor: Option<KLedgerAnchor>,
    #[serde(default)]
    pub tmp_vector_b64: Vec<String>,
    pub t_entries: Vec<TEntry>,
    pub l_values: Vec<String>,
    #[serde(default)]
    pub vectors_summary: RevocationVectorsSummary,
    pub manifest: Option<ManifestAnchor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCredentialRecord {
    pub issuer_local_credential_id: String,
    pub holder_did_hint: Option<String>,
    pub cred_def_id: String,
    pub schema_id: String,
    pub credential_json: String,
    pub control: RevocationControlValues,
    #[serde(default)]
    pub k_ledger_anchor: Option<KLedgerAnchor>,
    pub revocation_keys_by_window: Vec<String>,
    #[serde(default)]
    pub vectors_summary: RevocationVectorsSummary,
    pub manifest: Option<ManifestAnchor>,
    pub status: String,
    pub revoked_at: Option<i64>,
    #[serde(default)]
    pub revoked_from_window: Option<u32>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationProofPayload {
    pub credential_id_local: String,
    pub control: RevocationControlValues,
    #[serde(default)]
    pub k_ledger_anchor: Option<KLedgerAnchor>,
    pub window_index: u32,
    pub window_start: i64,
    pub t_entry: TEntry,
    pub l_value: String,
    pub merkle_path: Vec<String>,
    pub manifest: Option<ManifestAnchor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationDecision {
    InvalidProof,
    ValidNotRevoked,
    FalsePositiveConfirmed,
    NeedsNextWindow,
    RevokedByPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationConfirmationPolicy {
    #[serde(default = "default_max_consecutive_hits_for_revoke")]
    pub max_consecutive_hits_for_revoke: u32,
    #[serde(default = "default_max_windows_to_request")]
    pub max_windows_to_request: u32,
    #[serde(default = "default_true")]
    pub allow_post_expiry_confirmation_windows: bool,
    #[serde(default = "default_holder_must_disprove_with_additional_windows")]
    pub holder_must_disprove_with_additional_windows: bool,
}

impl Default for RevocationConfirmationPolicy {
    fn default() -> Self {
        Self {
            max_consecutive_hits_for_revoke: default_max_consecutive_hits_for_revoke(),
            max_windows_to_request: default_max_windows_to_request(),
            allow_post_expiry_confirmation_windows: true,
            holder_must_disprove_with_additional_windows:
                default_holder_must_disprove_with_additional_windows(),
        }
    }
}

impl RevocationConfirmationPolicy {
    pub fn ensure_protocol_compliance(&self) -> Result<(), String> {
        let expected = Self::default();
        if self.max_consecutive_hits_for_revoke != expected.max_consecutive_hits_for_revoke {
            return Err(format!(
                "max_consecutive_hits_for_revoke={} diverge do protocolo ({})",
                self.max_consecutive_hits_for_revoke, expected.max_consecutive_hits_for_revoke
            ));
        }
        if self.max_windows_to_request != expected.max_windows_to_request {
            return Err(format!(
                "max_windows_to_request={} diverge do protocolo ({})",
                self.max_windows_to_request, expected.max_windows_to_request
            ));
        }
        if self.allow_post_expiry_confirmation_windows
            != expected.allow_post_expiry_confirmation_windows
        {
            return Err(format!(
                "allow_post_expiry_confirmation_windows={} diverge do protocolo ({})",
                self.allow_post_expiry_confirmation_windows,
                expected.allow_post_expiry_confirmation_windows
            ));
        }
        if self.holder_must_disprove_with_additional_windows
            != expected.holder_must_disprove_with_additional_windows
        {
            return Err(format!(
                "holder_must_disprove_with_additional_windows={} diverge do protocolo ({})",
                self.holder_must_disprove_with_additional_windows,
                expected.holder_must_disprove_with_additional_windows
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationCheckTraceItem {
    pub window_index: u32,
    pub window_start: i64,
    pub revocation_key: String,
    #[serde(default)]
    pub proof_verified: bool,
    #[serde(default)]
    pub maybe_present: Option<bool>,
    #[serde(default)]
    pub filter_id: Option<String>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationDecisionResult {
    pub verified: bool,
    pub revoked: bool,
    pub accepted: bool,
    pub decision: RevocationDecision,
    pub requires_more_windows: bool,
    #[serde(default)]
    pub next_required_window_index: Option<u32>,
    pub primary_window_index: u32,
    pub revocation_key_initial: String,
    pub consecutive_hits: u32,
    pub details: String,
    #[serde(default)]
    pub trace: Vec<RevocationCheckTraceItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationProofSequence {
    pub credential_id_local: String,
    #[serde(default)]
    pub cred_def_id: Option<String>,
    pub primary_proof: RevocationProofPayload,
    #[serde(default)]
    pub confirmation_proofs: Vec<RevocationProofPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEventRecord {
    pub event_id: String,
    pub created_at: i64,
    pub event_type: String,
    #[serde(default)]
    pub credential_id_local: Option<String>,
    #[serde(default)]
    pub issuer_did: Option<String>,
    #[serde(default)]
    pub decision: Option<RevocationDecision>,
    #[serde(default)]
    pub trace_len: usize,
    pub payload: serde_json::Value,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationStatus {
    pub verified: bool,
    pub revoked: bool,
    pub window_index: u32,
    pub revocation_key: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocableCredentialArtifacts {
    pub control: RevocationControlValues,
    pub holder_bundle: HolderRevocationBundle,
    pub issuer_record: IssuedCredentialRecord,
}
