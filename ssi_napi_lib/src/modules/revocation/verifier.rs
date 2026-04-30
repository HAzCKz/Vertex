use crate::modules::common::read_attrib_raw_async;
use crate::modules::revocation::bloom_client::check_revocation_key;
use crate::modules::revocation::holder::build_revocation_proof_sequence_for_window;
use crate::modules::revocation::k_vector::{
    decode_k_vector_values, make_k_chunk_key, rebuild_k_from_chunks, resolve_k_values_from_indices,
    tmp_not_in_k, validate_t_entry_indices, K_VALUE_SIZE_BYTES,
};
use crate::modules::revocation::merkle::{
    compute_l_value_from_k_values_and_tmp, compute_revocation_key_from_k_values,
    verify_merkle_proof, K_SUBSET_SIZE, TMP_SIZE_BYTES,
};
use crate::modules::revocation::storage::{
    get_holder_revocation_bundle, make_revocation_event_id, store_revocation_event,
};
use crate::modules::revocation::types::{
    ManifestAnchor, RevocationCheckTraceItem, RevocationConfirmationPolicy, RevocationDecision,
    RevocationDecisionResult, RevocationEventRecord, RevocationProofPayload,
    RevocationProofSequence, RevocationStatus,
};
use crate::modules::revocation::windows::window_layout_from_control;
use crate::IndyAgent;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use napi::{Env, JsObject, Result};
use napi_derive::napi;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

type KVectorDecoded = Vec<[u8; K_VALUE_SIZE_BYTES]>;
const BINARY_SEARCH_SEQUENCE_THRESHOLD: usize = 50;

static K_VECTOR_CACHE: OnceLock<Mutex<HashMap<String, KVectorDecoded>>> = OnceLock::new();

fn k_vector_cache() -> &'static Mutex<HashMap<String, KVectorDecoded>> {
    K_VECTOR_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn k_vector_cache_key(anchor: &crate::modules::revocation::types::KLedgerAnchor) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        anchor.issuer_did,
        anchor.k_vector_id,
        anchor.vector_hash,
        anchor.value_count,
        anchor.value_size_bytes
    )
}

fn get_cached_k_vector(
    anchor: &crate::modules::revocation::types::KLedgerAnchor,
) -> Option<KVectorDecoded> {
    let cache = k_vector_cache().lock().ok()?;
    cache.get(&k_vector_cache_key(anchor)).cloned()
}

fn store_cached_k_vector(
    anchor: &crate::modules::revocation::types::KLedgerAnchor,
    values: &KVectorDecoded,
) {
    if let Ok(mut cache) = k_vector_cache().lock() {
        cache.insert(k_vector_cache_key(anchor), values.clone());
    }
}

fn ensure_single_proof_uses_validity_window(
    proof: &RevocationProofPayload,
) -> std::result::Result<(), String> {
    let layout = window_layout_from_control(&proof.control)?;
    if proof.window_index > layout.last_valid_window_index {
        return Err(format!(
            "window_index {} é janela exclusiva de confirmação; last_valid_window_index={}",
            proof.window_index, layout.last_valid_window_index
        ));
    }
    Ok(())
}

async fn load_k_vector_from_anchor(
    pool: &indy_vdr::pool::PoolRunner,
    anchor: &crate::modules::revocation::types::KLedgerAnchor,
) -> std::result::Result<KVectorDecoded, String> {
    if let Some(values) = get_cached_k_vector(anchor) {
        return Ok(values);
    }

    let mut chunks = Vec::with_capacity(anchor.chunk_count as usize);
    for index in 0..anchor.chunk_count {
        let chunk_key = make_k_chunk_key(&anchor.chunk_prefix, index);
        let value_b64 = read_attrib_raw_async(pool, &anchor.issuer_did, &chunk_key)
            .await
            .map_err(|e| format!("Erro lendo chunk {} do vetor K: {}", chunk_key, e))?;
        chunks.push(crate::modules::revocation::types::KChunkRecord {
            k_vector_id: anchor.k_vector_id.clone(),
            index,
            total: anchor.chunk_count,
            key: chunk_key,
            value_b64,
        });
    }

    let values = rebuild_k_from_chunks(&chunks, anchor.value_count, anchor.value_size_bytes)
        .map_err(|e| format!("Erro reconstruindo K a partir dos ATTRIBs: {}", e))?;

    let rebuilt_hash = crate::modules::revocation::k_vector::hash_k_vector(&values);
    if rebuilt_hash != anchor.vector_hash {
        return Err("vector_hash reconstruído difere do anchor publicado".to_string());
    }

    let decoded = decode_k_vector_values(&values)?;
    store_cached_k_vector(anchor, &decoded);
    Ok(decoded)
}

fn decode_tmp_from_proof(
    proof: &RevocationProofPayload,
) -> std::result::Result<[u8; TMP_SIZE_BYTES], String> {
    let tmp = B64
        .decode(&proof.t_entry.tmp_b64)
        .map_err(|e| format!("tmp inválido na prova: {}", e))?;
    if tmp.len() != TMP_SIZE_BYTES {
        return Err(format!(
            "tmp inválido na prova: tamanho {} bytes, esperado {}",
            tmp.len(),
            TMP_SIZE_BYTES
        ));
    }
    let mut arr = [0u8; TMP_SIZE_BYTES];
    arr.copy_from_slice(&tmp);
    Ok(arr)
}

fn recompute_l_from_proof_and_k(
    proof: &RevocationProofPayload,
    k_vector: &[[u8; K_VALUE_SIZE_BYTES]],
) -> std::result::Result<String, String> {
    validate_t_entry_indices(&proof.t_entry.k_indices, K_SUBSET_SIZE, k_vector.len())?;
    let resolved_values = resolve_k_values_from_indices(k_vector, &proof.t_entry.k_indices)?;
    let tmp = decode_tmp_from_proof(proof)?;
    tmp_not_in_k(k_vector, &tmp)?;
    Ok(compute_l_value_from_k_values_and_tmp(
        &resolved_values,
        &tmp,
    ))
}

fn compute_legacy_revocation_key_from_proof(
    proof: &RevocationProofPayload,
) -> std::result::Result<String, String> {
    validate_t_entry_indices(&proof.t_entry.k_indices, K_SUBSET_SIZE, u16::MAX as usize)?;
    let mut bytes = Vec::with_capacity(proof.t_entry.k_indices.len() * std::mem::size_of::<u16>());
    for idx in &proof.t_entry.k_indices {
        bytes.extend_from_slice(&idx.to_be_bytes());
    }
    Ok(compute_revocation_key_from_k_values(
        &proof.control.seed,
        proof.window_start,
        &bytes
            .chunks_exact(2)
            .map(|chunk| {
                let mut arr = [0u8; K_VALUE_SIZE_BYTES];
                arr[0] = chunk[0];
                arr[1] = chunk[1];
                arr
            })
            .collect::<Vec<_>>(),
    ))
}

fn compute_revocation_key_from_resolved_values(
    proof: &RevocationProofPayload,
    resolved_values: &[[u8; K_VALUE_SIZE_BYTES]],
) -> String {
    compute_revocation_key_from_k_values(&proof.control.seed, proof.window_start, resolved_values)
}

fn decision_accepts_credential(decision: &RevocationDecision) -> bool {
    matches!(
        decision,
        RevocationDecision::ValidNotRevoked | RevocationDecision::FalsePositiveConfirmed
    )
}

fn build_decision_result(
    decision: RevocationDecision,
    verified: bool,
    requires_more_windows: bool,
    next_required_window_index: Option<u32>,
    primary_window_index: u32,
    revocation_key_initial: String,
    consecutive_hits: u32,
    details: String,
    trace: Vec<RevocationCheckTraceItem>,
) -> RevocationDecisionResult {
    RevocationDecisionResult {
        verified,
        revoked: matches!(decision, RevocationDecision::RevokedByPolicy),
        accepted: verified && decision_accepts_credential(&decision),
        decision,
        requires_more_windows,
        next_required_window_index,
        primary_window_index,
        revocation_key_initial,
        consecutive_hits,
        details,
        trace,
    }
}

fn invalid_proof_decision_result(
    proof: &RevocationProofPayload,
    revocation_key_initial: String,
    details: String,
    trace: Vec<RevocationCheckTraceItem>,
) -> RevocationDecisionResult {
    build_decision_result(
        RevocationDecision::InvalidProof,
        false,
        false,
        None,
        proof.window_index,
        revocation_key_initial,
        0,
        details,
        trace,
    )
}

fn validate_proof_sequence(sequence: &RevocationProofSequence) -> std::result::Result<(), String> {
    let primary = &sequence.primary_proof;
    let layout = window_layout_from_control(&primary.control)?;
    if primary.window_index > layout.last_valid_window_index {
        return Err(format!(
            "primary_proof.window_index={} excede last_valid_window_index={}",
            primary.window_index, layout.last_valid_window_index
        ));
    }
    if primary.credential_id_local != sequence.credential_id_local {
        return Err("credential_id_local da sequência difere do primary_proof".to_string());
    }

    let mut expected_window_index = primary
        .window_index
        .checked_add(1)
        .ok_or_else(|| "Overflow no cálculo da próxima janela esperada".to_string())?;
    for proof in &sequence.confirmation_proofs {
        if proof.credential_id_local != sequence.credential_id_local {
            return Err(
                "credential_id_local em confirmation_proofs difere da sequência".to_string(),
            );
        }
        if proof.control.seed != primary.control.seed
            || proof.control.start_time != primary.control.start_time
            || proof.control.time_window != primary.control.time_window
            || proof.control.unit_of_time != primary.control.unit_of_time
            || proof.control.root_merkle_l != primary.control.root_merkle_l
        {
            return Err("confirmation_proof incompatível com o primary_proof".to_string());
        }
        if proof.window_index != expected_window_index {
            return Err(format!(
                "confirmation_proof.window_index={} fora da sequência esperada={}",
                proof.window_index, expected_window_index
            ));
        }
        if proof.window_index > layout.last_confirmation_window_index {
            return Err(format!(
                "confirmation_proof.window_index={} excede last_confirmation_window_index={}",
                proof.window_index, layout.last_confirmation_window_index
            ));
        }
        expected_window_index = expected_window_index
            .checked_add(1)
            .ok_or_else(|| "Overflow no cálculo da sequência de confirmação".to_string())?;
    }

    Ok(())
}

async fn verify_single_window_with_bloom(
    pool: Option<std::sync::Arc<indy_vdr::pool::PoolRunner>>,
    proof: &RevocationProofPayload,
    expected_root_merkle_l: Option<&str>,
) -> std::result::Result<(RevocationStatus, Option<bool>, Option<String>), String> {
    let local_status =
        verify_revocation_proof_with_k_validation(pool, proof, expected_root_merkle_l).await?;

    if !local_status.verified {
        return Ok((local_status, None, None));
    }

    if let Some(manifest) = &proof.manifest {
        let check =
            check_revocation_key(manifest, &local_status.revocation_key, proof.window_start)
                .await
                .map_err(|e| format!("Erro consultando serviço Bloom: {}", e))?;
        let maybe_present = check.results.iter().any(|item| item.maybe_present);
        let status = RevocationStatus {
            verified: true,
            revoked: maybe_present,
            window_index: local_status.window_index,
            revocation_key: local_status.revocation_key,
            details: if maybe_present {
                format!(
                    "Prova local válida{}; chave encontrada no Bloom filter {}",
                    if expected_root_merkle_l.is_some() {
                        " e root coerente"
                    } else {
                        ""
                    },
                    check.filter_id
                )
            } else {
                format!(
                    "Prova local válida{}; chave ausente no Bloom filter {}",
                    if expected_root_merkle_l.is_some() {
                        " e root coerente"
                    } else {
                        ""
                    },
                    check.filter_id
                )
            },
        };

        return Ok((status, Some(maybe_present), Some(check.filter_id)));
    }

    Ok((local_status, None, None))
}

async fn load_or_verify_sequence_window(
    cache: &mut HashMap<usize, (RevocationStatus, Option<bool>, Option<String>)>,
    trace: &mut Vec<RevocationCheckTraceItem>,
    pool: Option<std::sync::Arc<indy_vdr::pool::PoolRunner>>,
    proofs: &[&RevocationProofPayload],
    pos: usize,
    expected_root_merkle_l: Option<&str>,
) -> std::result::Result<(RevocationStatus, Option<bool>, Option<String>), String> {
    if let Some(cached) = cache.get(&pos) {
        return Ok(cached.clone());
    }

    let proof = proofs
        .get(pos)
        .ok_or_else(|| format!("Posição de prova fora do intervalo: {}", pos))?;
    let evaluated = verify_single_window_with_bloom(pool, proof, expected_root_merkle_l).await?;

    trace.push(RevocationCheckTraceItem {
        window_index: proof.window_index,
        window_start: proof.window_start,
        revocation_key: evaluated.0.revocation_key.clone(),
        proof_verified: evaluated.0.verified,
        maybe_present: evaluated.1,
        filter_id: evaluated.2.clone(),
        details: evaluated.0.details.clone(),
    });
    cache.insert(pos, evaluated.clone());
    Ok(evaluated)
}

async fn verify_revocation_proof_sequence_payload_linear(
    pool: Option<std::sync::Arc<indy_vdr::pool::PoolRunner>>,
    sequence: &RevocationProofSequence,
    expected_root_merkle_l: Option<&str>,
    policy: &RevocationConfirmationPolicy,
) -> std::result::Result<RevocationDecisionResult, String> {
    let layout = window_layout_from_control(&sequence.primary_proof.control)?;
    let mut proofs_to_check = Vec::with_capacity(1 + sequence.confirmation_proofs.len());
    proofs_to_check.push(sequence.primary_proof.clone());
    proofs_to_check.extend(sequence.confirmation_proofs.clone());

    let usable_len = proofs_to_check.len();
    let mut trace = Vec::with_capacity(usable_len);
    let mut consecutive_hits = 0u32;
    let mut first_hit_window_index: Option<u32> = None;
    let mut false_positive_sequences = 0u32;
    let revocation_key_initial =
        compute_revocation_key_from_proof(&sequence.primary_proof, None).unwrap_or_default();
    let expected_root =
        expected_root_merkle_l.or(Some(sequence.primary_proof.control.root_merkle_l.as_str()));

    for proof in proofs_to_check.iter().take(usable_len) {
        let (status, maybe_present, filter_id) =
            verify_single_window_with_bloom(pool.clone(), proof, expected_root).await?;

        trace.push(RevocationCheckTraceItem {
            window_index: proof.window_index,
            window_start: proof.window_start,
            revocation_key: status.revocation_key.clone(),
            proof_verified: status.verified,
            maybe_present,
            filter_id: filter_id.clone(),
            details: status.details.clone(),
        });

        if !status.verified {
            return Ok(invalid_proof_decision_result(
                proof,
                revocation_key_initial,
                status.details,
                trace,
            ));
        }

        if maybe_present != Some(true) {
            if consecutive_hits > 0 {
                false_positive_sequences =
                    false_positive_sequences.checked_add(1).ok_or_else(|| {
                        "Overflow na contagem de sequências de falso positivo".to_string()
                    })?;
                consecutive_hits = 0;
                first_hit_window_index = None;
            }
            continue;
        }

        if consecutive_hits == 0 {
            first_hit_window_index = Some(proof.window_index);
        }
        consecutive_hits = consecutive_hits
            .checked_add(1)
            .ok_or_else(|| "Overflow nos hits consecutivos do Bloom".to_string())?;
        if consecutive_hits >= policy.max_consecutive_hits_for_revoke {
            let candidate_window_index =
                first_hit_window_index.unwrap_or(sequence.primary_proof.window_index);
            return Ok(build_decision_result(
                RevocationDecision::RevokedByPolicy,
                true,
                false,
                None,
                candidate_window_index,
                revocation_key_initial,
                consecutive_hits,
                format!(
                    "{} hit(s) consecutivos no Bloom a partir da janela {}; a credencial é confirmada como revogada",
                    consecutive_hits, candidate_window_index
                ),
                trace,
            ));
        }

        if consecutive_hits > policy.max_windows_to_request {
            let candidate_window_index =
                first_hit_window_index.unwrap_or(sequence.primary_proof.window_index);
            return Ok(build_decision_result(
                RevocationDecision::RevokedByPolicy,
                true,
                false,
                None,
                candidate_window_index,
                revocation_key_initial,
                consecutive_hits,
                format!(
                    "{} hit(s) consecutivos no Bloom a partir da janela {} ultrapassaram as {} janelas de confirmação exigidas; a credencial é confirmada como revogada",
                    consecutive_hits,
                    candidate_window_index,
                    policy.max_windows_to_request
                ),
                trace,
            ));
        }
    }

    let next_required_window_index = proofs_to_check
        .get(usable_len.saturating_sub(1))
        .and_then(|proof| proof.window_index.checked_add(1));
    let next_allowed_window_index = next_required_window_index.filter(|index| {
        *index <= layout.last_confirmation_window_index
            && (policy.allow_post_expiry_confirmation_windows
                || *index <= layout.last_valid_window_index)
    });

    if consecutive_hits > 0 {
        let candidate_window_index =
            first_hit_window_index.unwrap_or(sequence.primary_proof.window_index);
        if policy.holder_must_disprove_with_additional_windows
            && next_allowed_window_index.is_some()
        {
            return Ok(build_decision_result(
                RevocationDecision::NeedsNextWindow,
                true,
                true,
                next_allowed_window_index,
                candidate_window_index,
                revocation_key_initial,
                consecutive_hits,
                format!(
                    "{} hit(s) consecutivos no Bloom a partir da janela {}; o holder deve apresentar a próxima janela {} para refutar ou confirmar o resultado",
                    consecutive_hits,
                    candidate_window_index,
                    next_allowed_window_index.unwrap_or_default()
                ),
                trace,
            ));
        }

        return Ok(build_decision_result(
            RevocationDecision::RevokedByPolicy,
            true,
            false,
            None,
            candidate_window_index,
            revocation_key_initial,
            consecutive_hits,
            format!(
                "{} hit(s) consecutivos no Bloom a partir da janela {} sem nenhuma janela adicional elegível restante; a credencial é confirmada como revogada",
                consecutive_hits, candidate_window_index
            ),
            trace,
        ));
    }

    Ok(build_decision_result(
        if false_positive_sequences > 0 {
            RevocationDecision::FalsePositiveConfirmed
        } else {
            RevocationDecision::ValidNotRevoked
        },
        true,
        false,
        None,
        sequence.primary_proof.window_index,
        revocation_key_initial,
        consecutive_hits,
        if false_positive_sequences > 0 {
            format!(
                "Todas as {} janela(s) fornecidas foram verificadas; {} sequência(s) de falso positivo foram descartadas e a credencial é válida",
                usable_len, false_positive_sequences
            )
        } else {
            format!(
                "Todas as {} janela(s) fornecidas foram verificadas; nenhuma chave foi encontrada no Bloom e a credencial é válida",
                usable_len
            )
        },
        trace,
    ))
}

pub async fn verify_revocation_proof_sequence_payload(
    pool: Option<std::sync::Arc<indy_vdr::pool::PoolRunner>>,
    sequence: &RevocationProofSequence,
    expected_root_merkle_l: Option<&str>,
    policy: Option<&RevocationConfirmationPolicy>,
) -> std::result::Result<RevocationDecisionResult, String> {
    validate_proof_sequence(sequence)?;
    let policy = policy.cloned().unwrap_or_default();
    policy.ensure_protocol_compliance()?;
    let layout = window_layout_from_control(&sequence.primary_proof.control)?;

    if 1 + sequence.confirmation_proofs.len() < BINARY_SEARCH_SEQUENCE_THRESHOLD {
        return verify_revocation_proof_sequence_payload_linear(
            pool,
            sequence,
            expected_root_merkle_l,
            &policy,
        )
        .await;
    }

    let mut proofs_to_check = Vec::with_capacity(1 + sequence.confirmation_proofs.len());
    proofs_to_check.push(&sequence.primary_proof);
    proofs_to_check.extend(sequence.confirmation_proofs.iter());

    let searchable_last_pos = proofs_to_check
        .iter()
        .rposition(|proof| proof.window_index <= layout.last_valid_window_index)
        .ok_or_else(|| "Nenhuma janela válida disponível para busca binária".to_string())?;

    let required_hits = policy.max_consecutive_hits_for_revoke as usize;
    let revocation_key_initial =
        compute_revocation_key_from_proof(&sequence.primary_proof, None).unwrap_or_default();
    let expected_root =
        expected_root_merkle_l.or(Some(sequence.primary_proof.control.root_merkle_l.as_str()));
    let mut trace = Vec::new();
    let mut cache: HashMap<usize, (RevocationStatus, Option<bool>, Option<String>)> =
        HashMap::new();
    let mut low = 0usize;
    let mut high = searchable_last_pos;
    let mut first_confirmed_pos: Option<usize> = None;
    let mut saw_false_positive = false;

    while low <= high {
        let mid = low + ((high - low) / 2);
        let (status, maybe_present, _) = load_or_verify_sequence_window(
            &mut cache,
            &mut trace,
            pool.clone(),
            &proofs_to_check,
            mid,
            expected_root,
        )
        .await?;

        if !status.verified {
            return Ok(invalid_proof_decision_result(
                proofs_to_check[mid],
                revocation_key_initial,
                status.details,
                trace,
            ));
        }

        if maybe_present != Some(true) {
            low = mid.saturating_add(1);
            continue;
        }

        let confirmation_end = mid
            .checked_add(required_hits.saturating_sub(1))
            .ok_or_else(|| "Overflow no cálculo da confirmação binária".to_string())?;

        if confirmation_end >= proofs_to_check.len() {
            return verify_revocation_proof_sequence_payload_linear(
                pool,
                sequence,
                expected_root_merkle_l,
                &policy,
            )
            .await;
        }

        let mut confirmed_hits = 1usize;
        let mut broken_at: Option<usize> = None;

        for pos in (mid + 1)..=confirmation_end {
            let (confirm_status, confirm_present, _) = load_or_verify_sequence_window(
                &mut cache,
                &mut trace,
                pool.clone(),
                &proofs_to_check,
                pos,
                expected_root,
            )
            .await?;

            if !confirm_status.verified {
                return Ok(invalid_proof_decision_result(
                    proofs_to_check[pos],
                    revocation_key_initial,
                    confirm_status.details,
                    trace,
                ));
            }

            if confirm_present == Some(true) {
                confirmed_hits = confirmed_hits
                    .checked_add(1)
                    .ok_or_else(|| "Overflow na contagem de hits da busca binária".to_string())?;
            } else {
                broken_at = Some(pos);
                saw_false_positive = true;
                break;
            }
        }

        if confirmed_hits >= required_hits {
            first_confirmed_pos = Some(mid);
            if mid == 0 {
                break;
            }
            high = mid - 1;
            continue;
        }

        if let Some(broken_pos) = broken_at {
            low = broken_pos.saturating_add(1);
            continue;
        }

        return verify_revocation_proof_sequence_payload_linear(
            pool,
            sequence,
            expected_root_merkle_l,
            &policy,
        )
        .await;
    }

    if let Some(found_pos) = first_confirmed_pos {
        let proof = proofs_to_check[found_pos];
        return Ok(build_decision_result(
            RevocationDecision::RevokedByPolicy,
            true,
            false,
            None,
            proof.window_index,
            revocation_key_initial,
            policy.max_consecutive_hits_for_revoke,
            format!(
                "{} hit(s) consecutivos confirmaram a revogação a partir da janela {}; a busca binária validou o ponto mínimo de revogação",
                policy.max_consecutive_hits_for_revoke,
                proof.window_index
            ),
            trace,
        ));
    }

    Ok(build_decision_result(
        if saw_false_positive {
            RevocationDecision::FalsePositiveConfirmed
        } else {
            RevocationDecision::ValidNotRevoked
        },
        true,
        false,
        None,
        sequence.primary_proof.window_index,
        revocation_key_initial,
        0,
        if saw_false_positive {
            format!(
                "A busca binária confirmada consultou {} janela(s) estratégica(s), descartou falso(s) positivo(s) e não encontrou revogação real",
                trace.len()
            )
        } else {
            format!(
                "A busca binária confirmada consultou {} janela(s) estratégica(s) sem encontrar um ponto real de revogação",
                trace.len()
            )
        },
        trace,
    ))
}

pub fn compute_revocation_key_from_proof(
    proof: &RevocationProofPayload,
    k_vector: Option<&[[u8; K_VALUE_SIZE_BYTES]]>,
) -> std::result::Result<String, String> {
    if let Some(k_vector) = k_vector {
        validate_t_entry_indices(&proof.t_entry.k_indices, K_SUBSET_SIZE, k_vector.len())?;
        let resolved_values = resolve_k_values_from_indices(k_vector, &proof.t_entry.k_indices)?;
        return Ok(compute_revocation_key_from_resolved_values(
            proof,
            &resolved_values,
        ));
    }

    compute_legacy_revocation_key_from_proof(proof)
}

pub fn verify_revocation_proof_locally(
    proof: &RevocationProofPayload,
) -> std::result::Result<RevocationStatus, String> {
    validate_t_entry_indices(&proof.t_entry.k_indices, K_SUBSET_SIZE, u16::MAX as usize)?;
    let _ = decode_tmp_from_proof(proof)?;

    let merkle_ok = verify_merkle_proof(
        &proof.l_value,
        &proof.merkle_path,
        proof.window_index as usize,
        &proof.control.root_merkle_l,
    )?;

    let revocation_key = compute_revocation_key_from_proof(proof, None)?;

    Ok(RevocationStatus {
        verified: merkle_ok,
        revoked: false,
        window_index: proof.window_index,
        revocation_key,
        details: if merkle_ok {
            "Prova local válida; consulta Bloom ainda não executada".to_string()
        } else {
            "Falha na validação local da prova de revogação".to_string()
        },
    })
}

pub fn verify_revocation_proof_against_expected_root(
    proof: &RevocationProofPayload,
    expected_root_merkle_l: &str,
) -> std::result::Result<RevocationStatus, String> {
    let expected_root = expected_root_merkle_l.trim();
    if expected_root.is_empty() {
        return Err("expected_root_merkle_l vazio".to_string());
    }

    if proof.control.root_merkle_l != expected_root {
        let revocation_key = compute_revocation_key_from_proof(proof, None)?;
        return Ok(RevocationStatus {
            verified: false,
            revoked: false,
            window_index: proof.window_index,
            revocation_key,
            details: "root_merkle_l da prova difere do root_merkle_L revelado na apresentação"
                .to_string(),
        });
    }

    verify_revocation_proof_locally(proof)
}

async fn verify_revocation_proof_with_k_validation(
    pool: Option<std::sync::Arc<indy_vdr::pool::PoolRunner>>,
    proof: &RevocationProofPayload,
    expected_root_merkle_l: Option<&str>,
) -> std::result::Result<RevocationStatus, String> {
    if let Some(expected_root) = expected_root_merkle_l {
        let expected_root = expected_root.trim();
        if expected_root.is_empty() {
            return Err("expected_root_merkle_l vazio".to_string());
        }
        if proof.control.root_merkle_l != expected_root {
            let revocation_key = compute_revocation_key_from_proof(proof, None)?;
            return Ok(RevocationStatus {
                verified: false,
                revoked: false,
                window_index: proof.window_index,
                revocation_key,
                details: "root_merkle_l da prova difere do root_merkle_L revelado na apresentação"
                    .to_string(),
            });
        }
    }

    let mut loaded_k_vector: Option<Vec<[u8; K_VALUE_SIZE_BYTES]>> = None;
    if let Some(anchor) = &proof.k_ledger_anchor {
        let pool = pool.ok_or_else(|| {
            "Prova contém k_ledger_anchor, mas o agente não está conectado à rede".to_string()
        })?;
        let k_vector = load_k_vector_from_anchor(&pool, anchor).await?;
        loaded_k_vector = Some(k_vector.clone());
        let recomputed_l = recompute_l_from_proof_and_k(proof, &k_vector)?;
        if recomputed_l != proof.l_value {
            let revocation_key = compute_revocation_key_from_proof(proof, Some(&k_vector))?;
            return Ok(RevocationStatus {
                verified: false,
                revoked: false,
                window_index: proof.window_index,
                revocation_key,
                details: "l_value da prova não confere com o valor recomposto a partir de K e tmp"
                    .to_string(),
            });
        }
    }

    let mut local_status = verify_revocation_proof_locally(proof)?;
    local_status.revocation_key =
        compute_revocation_key_from_proof(proof, loaded_k_vector.as_deref())?;
    Ok(local_status)
}

pub async fn verify_revocation_proof_payload(
    pool: Option<std::sync::Arc<indy_vdr::pool::PoolRunner>>,
    proof: &RevocationProofPayload,
    expected_root_merkle_l: Option<&str>,
) -> std::result::Result<RevocationStatus, String> {
    let (status, _, _) =
        verify_single_window_with_bloom(pool, proof, expected_root_merkle_l).await?;
    Ok(status)
}

#[napi]
impl IndyAgent {
    #[napi]
    pub fn verify_presentation_revocation_proof(
        &self,
        env: Env,
        proof_json: String,
    ) -> Result<JsObject> {
        let pool = self.pool.clone();
        env.execute_tokio_future(
            async move {
                let proof: RevocationProofPayload = serde_json::from_str(&proof_json)
                    .map_err(|e| napi::Error::from_reason(format!("proof_json inválido: {}", e)))?;
                ensure_single_proof_uses_validity_window(&proof).map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Prova legada inválida para verificação de revogação: {}",
                        e
                    ))
                })?;

                let status = verify_revocation_proof_payload(pool, &proof, None)
                    .await
                    .map_err(|e| {
                        napi::Error::from_reason(format!(
                            "Erro validando prova local de revogação: {}",
                            e
                        ))
                    })?;

                let response = serde_json::json!({
                    "ok": true,
                    "proof": proof,
                    "status": status,
                });

                serde_json::to_string(&response).map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando resultado da verificação de revogação: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn verify_presentation_revocation_proof_with_expected_root(
        &self,
        env: Env,
        proof_json: String,
        expected_root_merkle_l: String,
    ) -> Result<JsObject> {
        let pool = self.pool.clone();
        env.execute_tokio_future(
            async move {
                let proof: RevocationProofPayload =
                    serde_json::from_str(&proof_json).map_err(|e| {
                        napi::Error::from_reason(format!("proof_json inválido: {}", e))
                    })?;
                ensure_single_proof_uses_validity_window(&proof).map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Prova legada inválida para verificação de revogação: {}",
                        e
                    ))
                })?;

                let status = verify_revocation_proof_payload(
                    pool,
                    &proof,
                    Some(&expected_root_merkle_l),
                )
                .await
                .map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro validando prova local de revogação com root esperado: {}",
                        e
                    ))
                })?;

                let response = serde_json::json!({
                    "ok": true,
                    "expected_root_merkle_l": expected_root_merkle_l,
                    "proof": proof,
                    "status": status,
                });

                serde_json::to_string(&response).map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando resultado da verificação de revogação com root esperado: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn verify_presentation_revocation_proof_v2(
        &self,
        env: Env,
        proof_sequence_json: String,
        expected_root_merkle_l: Option<String>,
        policy_json: Option<String>,
        store_event: Option<bool>,
    ) -> Result<JsObject> {
        let pool = self.pool.clone();
        let store = self.store.clone();
        env.execute_tokio_future(
            async move {
                let should_store_event = store_event.unwrap_or(true);
                let proof_sequence: RevocationProofSequence =
                    serde_json::from_str(&proof_sequence_json).map_err(|e| {
                        napi::Error::from_reason(format!("proof_sequence_json inválido: {}", e))
                    })?;
                let policy: Option<RevocationConfirmationPolicy> = match policy_json {
                    Some(raw) if !raw.trim().is_empty() => {
                        Some(serde_json::from_str(&raw).map_err(|e| {
                            napi::Error::from_reason(format!("policy_json inválido: {}", e))
                        })?)
                    }
                    _ => None,
                };

                let status = verify_revocation_proof_sequence_payload(
                    pool,
                    &proof_sequence,
                    expected_root_merkle_l.as_deref(),
                    policy.as_ref(),
                )
                .await
                .map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro validando sequência de prova de revogação: {}",
                        e
                    ))
                })?;

                if should_store_event {
                    if let Some(store) = &store {
                        let issuer_did = proof_sequence
                            .primary_proof
                            .manifest
                            .as_ref()
                            .map(|manifest| manifest.issuer_did.clone());
                        let event = RevocationEventRecord {
                            event_id: make_revocation_event_id("revocation-proof-v2"),
                            created_at: crate::modules::common::now_ts(),
                            event_type: "verify_presentation_revocation_proof_v2".to_string(),
                            credential_id_local: Some(proof_sequence.credential_id_local.clone()),
                            issuer_did,
                            decision: Some(status.decision.clone()),
                            trace_len: status.trace.len(),
                            payload: serde_json::json!({
                                "status": &status,
                                "policy": policy.clone().unwrap_or_default(),
                            }),
                        };
                        store_revocation_event(store, &event).await?;
                    }
                }

                let response = serde_json::json!({
                    "ok": true,
                    "proof_sequence": proof_sequence,
                    "policy": policy.unwrap_or_default(),
                    "status": status,
                });

                serde_json::to_string(&response).map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando resultado da verificação v2 de revogação: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn verify_holder_revocation_status_full_scan(
        &self,
        env: Env,
        bundle_id_local: String,
        credential_id_local: Option<String>,
        expected_root_merkle_l: Option<String>,
        policy_json: Option<String>,
        manifest_anchor_json: Option<String>,
    ) -> Result<JsObject> {
        let pool = self.pool.clone();
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(napi::Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let mut bundle = get_holder_revocation_bundle(&store, &bundle_id_local)
                    .await?
                    .ok_or_else(|| {
                        napi::Error::from_reason(format!(
                            "Holder revocation bundle não encontrado: {}",
                            bundle_id_local
                        ))
                    })?;

                if let Some(raw_manifest) =
                    manifest_anchor_json.filter(|raw| !raw.trim().is_empty())
                {
                    let manifest: ManifestAnchor =
                        serde_json::from_str(&raw_manifest).map_err(|e| {
                            napi::Error::from_reason(format!(
                                "manifest_anchor_json inválido: {}",
                                e
                            ))
                        })?;
                    bundle.manifest = Some(manifest);
                }

                let proof_credential_id = credential_id_local
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty())
                    .or_else(|| bundle.credential_id.clone())
                    .ok_or_else(|| {
                        napi::Error::from_reason(
                            "credential_id_local é obrigatório quando o bundle salvo não possui credential_id"
                                .to_string(),
                        )
                    })?;

                let policy: Option<RevocationConfirmationPolicy> = match policy_json {
                    Some(raw) if !raw.trim().is_empty() => {
                        Some(serde_json::from_str(&raw).map_err(|e| {
                            napi::Error::from_reason(format!("policy_json inválido: {}", e))
                        })?)
                    }
                    _ => None,
                };
                let policy_for_scan = policy.clone().unwrap_or_default();
                policy_for_scan.ensure_protocol_compliance().map_err(|e| {
                    napi::Error::from_reason(format!("Política de revogação inválida: {}", e))
                })?;
                let layout = window_layout_from_control(&bundle.control).map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Controle de janelas da credencial inválido: {}",
                        e
                    ))
                })?;

                let total_steps = layout
                    .last_valid_window_index
                    .checked_add(1)
                    .unwrap_or(layout.last_valid_window_index);
                let mut scan_runs = Vec::with_capacity(total_steps as usize);
                let mut global_status = None;
                let mut revoked_detected = false;
                let mut verified_steps = 0usize;

                for primary_window_index in 0..=layout.last_valid_window_index {
                    let additional_window_count = std::cmp::min(
                        policy_for_scan.max_windows_to_request,
                        layout
                            .last_confirmation_window_index
                            .saturating_sub(primary_window_index),
                    );
                    let proof_sequence = build_revocation_proof_sequence_for_window(
                        &proof_credential_id,
                        &bundle,
                        primary_window_index,
                        additional_window_count,
                    )
                    .map_err(|e| {
                        napi::Error::from_reason(format!(
                            "Erro montando sequência de prova de revogação: {}",
                            e
                        ))
                    })?;
                    let status = verify_revocation_proof_sequence_payload(
                        pool.clone(),
                        &proof_sequence,
                        expected_root_merkle_l.as_deref(),
                        policy.as_ref(),
                    )
                    .await
                    .map_err(|e| {
                        napi::Error::from_reason(format!(
                            "Erro validando sequência de prova de revogação: {}",
                            e
                        ))
                    })?;

                    if status.verified {
                        verified_steps += 1;
                    }
                    scan_runs.push(serde_json::json!({
                        "primaryWindowIndex": primary_window_index,
                        "additionalWindowCount": additional_window_count,
                        "status": {
                            "verified": status.verified,
                            "accepted": status.accepted,
                            "revoked": status.revoked,
                            "decision": status.decision,
                            "requires_more_windows": status.requires_more_windows,
                            "next_required_window_index": status.next_required_window_index,
                            "consecutive_hits": status.consecutive_hits,
                        },
                    }));

                    if status.revoked {
                        revoked_detected = true;
                        global_status = Some(serde_json::json!({
                            "verified": true,
                            "accepted": false,
                            "revoked": true,
                            "decision": "globally_revoked",
                            "requires_more_windows": false,
                            "next_required_window_index": null,
                            "consecutive_hits": status.consecutive_hits,
                            "decisive_window_index": primary_window_index,
                            "decisive_window_start": proof_sequence.primary_proof.window_start,
                            "scanned_windows": scan_runs.len(),
                            "details": format!(
                                "Revogação confirmada ao verificar a janela {}.",
                                primary_window_index
                            ),
                        }));
                        break;
                    }

                    if !status.verified {
                        global_status = Some(serde_json::json!({
                            "verified": false,
                            "accepted": false,
                            "revoked": false,
                            "decision": "global_inconclusive",
                            "requires_more_windows": false,
                            "next_required_window_index": null,
                            "consecutive_hits": "",
                            "decisive_window_index": null,
                            "decisive_window_start": null,
                            "scanned_windows": scan_runs.len(),
                            "details": "Não foi possível concluir a verificação completa em todas as janelas da credencial.",
                        }));
                        break;
                    }
                }

                let global_status = global_status.unwrap_or_else(|| {
                    serde_json::json!({
                        "verified": true,
                        "accepted": true,
                        "revoked": false,
                        "decision": "globally_not_revoked",
                        "requires_more_windows": false,
                        "next_required_window_index": null,
                        "consecutive_hits": 0,
                        "decisive_window_index": null,
                        "decisive_window_start": null,
                        "scanned_windows": scan_runs.len(),
                        "details": format!(
                            "Nenhuma janela válida da credencial indicou revogação após a verificação completa de {} janela(s).",
                            scan_runs.len()
                        ),
                    })
                });

                let response = serde_json::json!({
                    "ok": true,
                    "mode": "native_full_window_scan",
                    "bundle_id_local": bundle_id_local,
                    "credential_id_local": proof_credential_id,
                    "globalStatus": global_status,
                    "progress": {
                        "total_steps": total_steps,
                        "completed_steps": scan_runs.len(),
                        "revoked_detected": revoked_detected,
                        "verified_steps": verified_steps,
                    },
                    "scanRuns": scan_runs,
                });

                serde_json::to_string(&response).map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando varredura completa de revogação: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }
}
