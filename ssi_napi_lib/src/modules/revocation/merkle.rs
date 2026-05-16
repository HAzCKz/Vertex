use crate::modules::revocation::types::{RevocationVectorsSummary, SEntry, TEntry};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::RngCore;
use sha3::{Digest, Sha3_256};

pub const K_SUBSET_SIZE: usize = 32;
pub const TMP_SIZE_BYTES: usize = 32;
pub const K_INDEX_BITS: usize = 10;

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(bytes);
    B64.encode(hasher.finalize())
}

pub fn compute_l_value_from_k_values_and_tmp(
    k_values: &[[u8; TMP_SIZE_BYTES]],
    tmp: &[u8; TMP_SIZE_BYTES],
) -> String {
    let mut bytes = Vec::with_capacity((k_values.len() + 1) * TMP_SIZE_BYTES);
    for value in k_values {
        bytes.extend_from_slice(value);
    }
    bytes.extend_from_slice(tmp);
    hash_bytes(&bytes)
}

pub fn compute_revocation_key_from_k_values(
    seed: &str,
    window_start: i64,
    k_values: &[[u8; TMP_SIZE_BYTES]],
) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(seed.as_bytes());
    hasher.update(window_start.to_string().as_bytes());
    for value in k_values {
        hasher.update(value);
    }
    B64.encode(hasher.finalize())
}

fn hash_pair(left_b64: &str, right_b64: &str) -> Result<String, String> {
    let left = B64
        .decode(left_b64)
        .map_err(|e| format!("Hash esquerdo inválido: {}", e))?;
    let right = B64
        .decode(right_b64)
        .map_err(|e| format!("Hash direito inválido: {}", e))?;

    let mut bytes = Vec::with_capacity(left.len() + right.len());
    bytes.extend_from_slice(&left);
    bytes.extend_from_slice(&right);
    Ok(hash_bytes(&bytes))
}

pub fn build_t_entries(window_count: u32, k_len: usize) -> Vec<TEntry> {
    let mut rng = OsRng;
    let mut entries = Vec::with_capacity(window_count as usize);
    let all_indices: Vec<u16> = (0..k_len as u16).collect();

    for _ in 0..window_count {
        let mut indices = all_indices.clone();
        indices.shuffle(&mut rng);
        indices.truncate(K_SUBSET_SIZE);

        let mut tmp = [0u8; TMP_SIZE_BYTES];
        rng.fill_bytes(&mut tmp);

        entries.push(TEntry {
            k_indices: indices,
            tmp_b64: B64.encode(tmp),
        });
    }

    entries
}

pub fn build_t_vector(window_count: u32, k_len: usize) -> Vec<TEntry> {
    build_t_entries(window_count, k_len)
}

pub fn extract_tmp_vector(t_entries: &[TEntry]) -> Vec<String> {
    t_entries
        .iter()
        .map(|entry| entry.tmp_b64.clone())
        .collect()
}

pub fn materialize_s_vector(
    k_values: &[String],
    t_entries: &[TEntry],
) -> Result<Vec<SEntry>, String> {
    let mut s_entries = Vec::with_capacity(t_entries.len());

    for entry in t_entries {
        if entry.k_indices.len() != K_SUBSET_SIZE {
            return Err(format!(
                "Cada entrada T deve possuir {} índices",
                K_SUBSET_SIZE
            ));
        }

        let mut k_values_b64 = Vec::with_capacity(K_SUBSET_SIZE);
        for idx in &entry.k_indices {
            let value = k_values
                .get(*idx as usize)
                .ok_or_else(|| format!("Índice K fora da faixa: {}", idx))?;
            let decoded = B64
                .decode(value)
                .map_err(|e| format!("Valor K inválido: {}", e))?;
            if decoded.len() != TMP_SIZE_BYTES {
                return Err(format!(
                    "Valor K na posição {} tem {} bytes; esperado {}",
                    idx,
                    decoded.len(),
                    TMP_SIZE_BYTES
                ));
            }
            k_values_b64.push(value.clone());
        }

        let tmp = B64
            .decode(&entry.tmp_b64)
            .map_err(|e| format!("tmp inválido: {}", e))?;
        if tmp.len() != TMP_SIZE_BYTES {
            return Err(format!(
                "tmp inválido: tamanho {} bytes, esperado {}",
                tmp.len(),
                TMP_SIZE_BYTES
            ));
        }

        s_entries.push(SEntry {
            k_values_b64,
            tmp_b64: entry.tmp_b64.clone(),
        });
    }

    Ok(s_entries)
}

pub fn summarize_vectors(
    window_count: u32,
    l_values: &[String],
    t_entries: &[TEntry],
    tmp_vector_b64: &[String],
    s_entries: &[SEntry],
) -> RevocationVectorsSummary {
    let l_size_bytes = l_values.len() * 32;
    let tmp_size_bytes = tmp_vector_b64.len() * TMP_SIZE_BYTES;
    let s_size_bytes = s_entries.len() * ((K_SUBSET_SIZE + 1) * TMP_SIZE_BYTES);
    let t_compact_size_bits =
        t_entries.len() * ((K_SUBSET_SIZE * K_INDEX_BITS) + (TMP_SIZE_BYTES * 8));
    let t_compact_size_bytes = t_compact_size_bits.div_ceil(8);

    RevocationVectorsSummary {
        window_count,
        tmp_count: tmp_vector_b64.len(),
        l_count: l_values.len(),
        t_count: t_entries.len(),
        s_count: s_entries.len(),
        l_size_bytes,
        tmp_size_bytes,
        s_size_bytes,
        t_compact_size_bits,
        t_compact_size_bytes,
    }
}

pub fn build_l_vector(k_values: &[String], t_entries: &[TEntry]) -> Result<Vec<String>, String> {
    let mut l_values = Vec::with_capacity(t_entries.len());

    for entry in t_entries {
        if entry.k_indices.len() != K_SUBSET_SIZE {
            return Err(format!(
                "Cada entrada T deve possuir {} índices",
                K_SUBSET_SIZE
            ));
        }

        let mut resolved_values = Vec::with_capacity(K_SUBSET_SIZE);
        for idx in &entry.k_indices {
            let value = k_values
                .get(*idx as usize)
                .ok_or_else(|| format!("Índice K fora da faixa: {}", idx))?;
            let decoded = B64
                .decode(value)
                .map_err(|e| format!("Valor K inválido: {}", e))?;
            if decoded.len() != TMP_SIZE_BYTES {
                return Err(format!(
                    "Valor K na posição {} tem {} bytes; esperado {}",
                    idx,
                    decoded.len(),
                    TMP_SIZE_BYTES
                ));
            }
            let mut arr = [0u8; TMP_SIZE_BYTES];
            arr.copy_from_slice(&decoded);
            resolved_values.push(arr);
        }

        let tmp = B64
            .decode(&entry.tmp_b64)
            .map_err(|e| format!("tmp inválido: {}", e))?;
        if tmp.len() != TMP_SIZE_BYTES {
            return Err(format!(
                "tmp inválido: tamanho {} bytes, esperado {}",
                tmp.len(),
                TMP_SIZE_BYTES
            ));
        }
        let mut tmp_arr = [0u8; TMP_SIZE_BYTES];
        tmp_arr.copy_from_slice(&tmp);
        l_values.push(compute_l_value_from_k_values_and_tmp(
            &resolved_values,
            &tmp_arr,
        ));
    }

    Ok(l_values)
}

pub fn build_merkle_root(leaves: &[String]) -> Result<String, String> {
    if leaves.is_empty() {
        return Err("Árvore de Merkle sem folhas".to_string());
    }

    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0usize;
        while i < level.len() {
            let left = &level[i];
            let right = if i + 1 < level.len() {
                &level[i + 1]
            } else {
                &level[i]
            };
            next.push(hash_pair(left, right)?);
            i += 2;
        }
        level = next;
    }

    Ok(level[0].clone())
}

pub fn build_merkle_levels(leaves: &[String]) -> Result<Vec<Vec<String>>, String> {
    if leaves.is_empty() {
        return Err("Árvore de Merkle sem folhas".to_string());
    }

    let mut levels = Vec::new();
    let mut current = leaves.to_vec();

    loop {
        levels.push(current.clone());
        if current.len() == 1 {
            break;
        }

        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut i = 0usize;
        while i < current.len() {
            let left = &current[i];
            let right = if i + 1 < current.len() {
                &current[i + 1]
            } else {
                &current[i]
            };
            next.push(hash_pair(left, right)?);
            i += 2;
        }

        current = next;
    }

    Ok(levels)
}

pub fn build_merkle_proof_from_levels(
    levels: &[Vec<String>],
    index: usize,
) -> Result<Vec<String>, String> {
    if levels.is_empty() {
        return Err("Árvore de Merkle sem folhas".to_string());
    }
    if index >= levels[0].len() {
        return Err("Índice da prova fora da faixa".to_string());
    }

    let mut proof = Vec::with_capacity(levels.len().saturating_sub(1));
    let mut current_index = index;

    for level in &levels[..levels.len().saturating_sub(1)] {
        let sibling_index = if current_index % 2 == 0 {
            if current_index + 1 < level.len() {
                current_index + 1
            } else {
                current_index
            }
        } else {
            current_index - 1
        };

        proof.push(level[sibling_index].clone());
        current_index /= 2;
    }

    Ok(proof)
}

pub fn build_merkle_proof(leaves: &[String], index: usize) -> Result<Vec<String>, String> {
    let levels = build_merkle_levels(leaves)?;
    build_merkle_proof_from_levels(&levels, index)
}

pub fn verify_merkle_proof(
    leaf: &str,
    proof: &[String],
    index: usize,
    expected_root: &str,
) -> Result<bool, String> {
    let mut current = leaf.to_string();
    let mut current_index = index;

    for sibling in proof {
        current = if current_index % 2 == 0 {
            hash_pair(&current, sibling)?
        } else {
            hash_pair(sibling, &current)?
        };
        current_index /= 2;
    }

    Ok(current == expected_root)
}

#[cfg(test)]
mod tests {
    use super::{
        build_merkle_levels, build_merkle_proof_from_levels, build_merkle_root, hash_bytes,
        verify_merkle_proof,
    };

    #[test]
    fn merkle_levels_produce_valid_proofs_for_all_leaves() {
        let leaves = vec![
            hash_bytes(b"leaf-0"),
            hash_bytes(b"leaf-1"),
            hash_bytes(b"leaf-2"),
            hash_bytes(b"leaf-3"),
            hash_bytes(b"leaf-4"),
        ];

        let levels = build_merkle_levels(&leaves).expect("levels");
        let root = build_merkle_root(&leaves).expect("root");

        for (index, leaf) in leaves.iter().enumerate() {
            let proof = build_merkle_proof_from_levels(&levels, index).expect("proof");
            let valid = verify_merkle_proof(leaf, &proof, index, &root).expect("verify");
            assert!(valid, "proof invalida para leaf {}", index);
        }
    }
}
