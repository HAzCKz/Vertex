use crate::modules::common::now_ts;
use crate::modules::revocation::types::{KChunkRecord, KLedgerAnchor, KVectorRecord};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;

pub const K_VECTOR_LEN: usize = 1024;
pub const K_VALUE_SIZE_BYTES: usize = 32;
pub const ATTRIB_MAX_JSON_SIZE_BYTES: usize = 4096;
pub const REVOCATION_MANIFEST_ATTR_KEY: &str = "REVOCATION_MANIFEST";
pub const REVOCATION_ACTIVE_K_ATTR_KEY: &str = "REVOCATION_K_ACTIVE";

pub fn generate_k_vector(issuer_did: &str, k_vector_id: &str) -> KVectorRecord {
    let mut values = Vec::with_capacity(K_VECTOR_LEN);
    let mut seen = HashSet::with_capacity(K_VECTOR_LEN);

    while values.len() < K_VECTOR_LEN {
        let mut buf = [0u8; K_VALUE_SIZE_BYTES];
        OsRng.fill_bytes(&mut buf);
        let encoded = B64.encode(buf);
        if seen.insert(encoded.clone()) {
            values.push(encoded);
        }
    }

    let vector_hash = hash_k_vector(&values);

    KVectorRecord {
        issuer_did: issuer_did.to_string(),
        k_vector_id: k_vector_id.to_string(),
        version: 1,
        hash_algorithm: "sha3-256".to_string(),
        vector_hash,
        values,
        created_at: now_ts(),
    }
}

pub fn hash_k_vector(values: &[String]) -> String {
    let payload = pack_k_vector_bytes(values).unwrap_or_default();
    let mut hasher = Sha3_256::new();
    hasher.update(payload);
    B64.encode(hasher.finalize())
}

pub fn make_k_attr_prefix(k_vector_id: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(k_vector_id.as_bytes());
    let digest = hasher.finalize();
    let encoded = bs58::encode(&digest[..8]).into_string().to_uppercase();
    format!("REVOC_K_{}", encoded)
}

pub fn make_k_anchor_key(k_vector_id: &str) -> String {
    format!("{}_INDEX", make_k_attr_prefix(k_vector_id))
}

pub fn make_k_chunk_key(prefix: &str, index: u32) -> String {
    format!("{}_PART_{:04}", prefix, index + 1)
}

fn attrib_json_size_for_key_and_chunk(key: &str, raw_chunk_bytes: usize) -> usize {
    let encoded = B64.encode(vec![0u8; raw_chunk_bytes]);
    serde_json::to_string(&serde_json::json!({ key: encoded }))
        .map(|s| s.len())
        .unwrap_or(usize::MAX)
}

pub fn max_chunk_bytes_for_attr_key(key: &str, max_json_size: usize) -> usize {
    let mut low = 1usize;
    let mut high = max_json_size;
    let mut best = 0usize;

    while low <= high {
        let mid = (low + high) / 2;
        if attrib_json_size_for_key_and_chunk(key, mid) <= max_json_size {
            best = mid;
            low = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            high = mid - 1;
        }
    }

    best
}

pub fn recommended_chunk_size_bytes(k_vector_id: &str) -> usize {
    let prefix = make_k_attr_prefix(k_vector_id);
    let first_key = make_k_chunk_key(&prefix, 0);
    max_chunk_bytes_for_attr_key(&first_key, ATTRIB_MAX_JSON_SIZE_BYTES).max(256)
}

pub fn pack_k_vector_bytes(values: &[String]) -> Result<Vec<u8>, String> {
    if values.len() != K_VECTOR_LEN {
        return Err(format!(
            "K vector deve possuir {} valores, recebeu {}",
            K_VECTOR_LEN,
            values.len()
        ));
    }

    let mut bytes = Vec::with_capacity(K_VECTOR_LEN * K_VALUE_SIZE_BYTES);
    for (index, value) in values.iter().enumerate() {
        let decoded = B64
            .decode(value)
            .map_err(|e| format!("Valor K inválido na posição {}: {}", index, e))?;
        if decoded.len() != K_VALUE_SIZE_BYTES {
            return Err(format!(
                "Valor K na posição {} tem {} bytes; esperado {}",
                index,
                decoded.len(),
                K_VALUE_SIZE_BYTES
            ));
        }
        bytes.extend_from_slice(&decoded);
    }

    Ok(bytes)
}

pub fn unpack_k_vector_bytes(
    bytes: &[u8],
    value_count: usize,
    value_size_bytes: usize,
) -> Result<Vec<String>, String> {
    let expected_total = value_count
        .checked_mul(value_size_bytes)
        .ok_or_else(|| "Overflow no cálculo de tamanho esperado do vetor K".to_string())?;

    if bytes.len() != expected_total {
        return Err(format!(
            "Total de bytes do vetor K inconsistente: {} != {}",
            bytes.len(),
            expected_total
        ));
    }

    let mut values = Vec::with_capacity(value_count);
    for chunk in bytes.chunks_exact(value_size_bytes) {
        values.push(B64.encode(chunk));
    }
    Ok(values)
}

pub fn decode_k_vector_values(values: &[String]) -> Result<Vec<[u8; K_VALUE_SIZE_BYTES]>, String> {
    if values.len() != K_VECTOR_LEN {
        return Err(format!(
            "K vector deve possuir {} valores, recebeu {}",
            K_VECTOR_LEN,
            values.len()
        ));
    }

    let mut decoded_values = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let decoded = B64
            .decode(value)
            .map_err(|e| format!("Valor K inválido na posição {}: {}", index, e))?;
        if decoded.len() != K_VALUE_SIZE_BYTES {
            return Err(format!(
                "Valor K na posição {} tem {} bytes; esperado {}",
                index,
                decoded.len(),
                K_VALUE_SIZE_BYTES
            ));
        }
        let mut arr = [0u8; K_VALUE_SIZE_BYTES];
        arr.copy_from_slice(&decoded);
        decoded_values.push(arr);
    }

    Ok(decoded_values)
}

pub fn validate_t_entry_indices(
    k_indices: &[u16],
    expected_len: usize,
    k_len: usize,
) -> Result<(), String> {
    if k_indices.len() != expected_len {
        return Err(format!(
            "Cada entrada T deve possuir {} índices, recebeu {}",
            expected_len,
            k_indices.len()
        ));
    }

    let mut seen = HashSet::with_capacity(k_indices.len());
    for idx in k_indices {
        if (*idx as usize) >= k_len {
            return Err(format!("Índice K fora da faixa: {}", idx));
        }
        if !seen.insert(*idx) {
            return Err(format!("Índice K repetido na mesma janela: {}", idx));
        }
    }

    Ok(())
}

pub fn resolve_k_values_from_indices(
    k_vector: &[[u8; K_VALUE_SIZE_BYTES]],
    k_indices: &[u16],
) -> Result<Vec<[u8; K_VALUE_SIZE_BYTES]>, String> {
    let mut out = Vec::with_capacity(k_indices.len());
    for idx in k_indices {
        let value = k_vector
            .get(*idx as usize)
            .ok_or_else(|| format!("Índice K fora da faixa: {}", idx))?;
        out.push(*value);
    }
    Ok(out)
}

pub fn tmp_not_in_k(
    k_vector: &[[u8; K_VALUE_SIZE_BYTES]],
    tmp: &[u8; K_VALUE_SIZE_BYTES],
) -> Result<(), String> {
    if k_vector.iter().any(|value| value == tmp) {
        return Err("tmp_i pertence ao vetor K, o que viola o algoritmo de revogação".to_string());
    }
    Ok(())
}

pub fn build_k_chunks(record: &KVectorRecord, chunk_size_bytes: usize) -> Vec<KChunkRecord> {
    let packed = pack_k_vector_bytes(&record.values).unwrap_or_default();
    let prefix = make_k_attr_prefix(&record.k_vector_id);
    let max_safe_chunk_size = recommended_chunk_size_bytes(&record.k_vector_id);
    let chunk_size = chunk_size_bytes.min(max_safe_chunk_size).max(256);

    let total = packed.len().div_ceil(chunk_size);
    let mut chunks = Vec::with_capacity(total);

    for (index, chunk) in packed.chunks(chunk_size).enumerate() {
        chunks.push(KChunkRecord {
            k_vector_id: record.k_vector_id.clone(),
            index: index as u32,
            total: total as u32,
            key: make_k_chunk_key(&prefix, index as u32),
            value_b64: B64.encode(chunk),
        });
    }

    chunks
}

pub fn build_k_ledger_anchor(record: &KVectorRecord, chunk_size_bytes: usize) -> KLedgerAnchor {
    let prefix = make_k_attr_prefix(&record.k_vector_id);
    let chunks = build_k_chunks(record, chunk_size_bytes);
    KLedgerAnchor {
        issuer_did: record.issuer_did.clone(),
        k_vector_id: record.k_vector_id.clone(),
        version: record.version,
        hash_algorithm: record.hash_algorithm.clone(),
        vector_hash: record.vector_hash.clone(),
        value_count: K_VECTOR_LEN,
        value_size_bytes: K_VALUE_SIZE_BYTES,
        total_bytes: K_VECTOR_LEN * K_VALUE_SIZE_BYTES,
        chunk_count: chunks.len() as u32,
        chunk_size_bytes: chunks
            .first()
            .and_then(|chunk| B64.decode(&chunk.value_b64).ok().map(|raw| raw.len()))
            .unwrap_or(chunk_size_bytes.max(256)),
        index_key: make_k_anchor_key(&record.k_vector_id),
        chunk_prefix: prefix,
        created_at: record.created_at,
    }
}

pub fn rebuild_k_from_chunks(
    chunks: &[KChunkRecord],
    value_count: usize,
    value_size_bytes: usize,
) -> Result<Vec<String>, String> {
    if chunks.is_empty() {
        return Err("Nenhum chunk fornecido".to_string());
    }

    let mut ordered = chunks.to_vec();
    ordered.sort_by_key(|c| c.index);

    let expected_total = ordered[0].total;
    if expected_total == 0 || expected_total as usize != ordered.len() {
        return Err("Quantidade de chunks inconsistente".to_string());
    }

    let mut bytes = Vec::new();
    for (pos, chunk) in ordered.iter().enumerate() {
        if chunk.index != pos as u32 {
            return Err("Sequência de chunks inconsistente".to_string());
        }
        let decoded = B64
            .decode(&chunk.value_b64)
            .map_err(|e| format!("Chunk base64 inválido: {}", e))?;
        bytes.extend_from_slice(&decoded);
    }

    unpack_k_vector_bytes(&bytes, value_count, value_size_bytes)
}
