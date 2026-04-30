use crate::modules::common::{now_ts, read_attrib_raw_async, write_attrib_raw_async};
use crate::modules::revocation::bloom_client::{
    compute_manifest_body_hash, revoke_revocation_keys,
};
use crate::modules::revocation::k_vector::{
    build_k_chunks, build_k_ledger_anchor, generate_k_vector, hash_k_vector, make_k_anchor_key,
    make_k_chunk_key, recommended_chunk_size_bytes, K_VECTOR_LEN, REVOCATION_ACTIVE_K_ATTR_KEY,
    REVOCATION_MANIFEST_ATTR_KEY,
};
use crate::modules::revocation::k_vector::{
    decode_k_vector_values, resolve_k_values_from_indices, validate_t_entry_indices,
};
use crate::modules::revocation::merkle::{
    build_l_vector, build_merkle_root, build_t_vector, compute_revocation_key_from_k_values,
    extract_tmp_vector, materialize_s_vector, summarize_vectors,
};
use crate::modules::revocation::storage::{
    delete_issued_credential_record, get_issued_credential_record, get_revocation_setup_record,
    list_issued_credential_records, store_issued_credential_record, store_revocation_setup_record,
};
use crate::modules::revocation::types::{
    HolderRevocationBundle, IssuedCredentialRecord, KChunkRecord, KLedgerAnchor, KVectorRecord,
    ManifestAnchor, RevocableCredentialArtifacts, RevocationControlValues, RevocationSetupRecord,
    RevocationVectorsSummary, DEFAULT_EXTRA_WINDOWS_FOR_FP,
};
use crate::modules::revocation::windows::{compute_window_layout, window_start_for_index};
use crate::IndyAgent;
use aries_askar::Store;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use napi::{Env, Error, JsObject, Result};
use napi_derive::napi;
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{Map, Value};

pub fn create_k_vector_record(issuer_did: &str, k_vector_id: &str) -> KVectorRecord {
    generate_k_vector(issuer_did, k_vector_id)
}

pub fn build_manifest_anchor(
    issuer_did: &str,
    manifest_url: &str,
    manifest_hash: &str,
    manifest_version: &str,
) -> ManifestAnchor {
    ManifestAnchor {
        issuer_did: issuer_did.to_string(),
        manifest_url: manifest_url.to_string(),
        manifest_hash: manifest_hash.to_string(),
        manifest_version: manifest_version.to_string(),
        updated_at: now_ts(),
    }
}

async fn refresh_manifest_anchor_live(manifest: &ManifestAnchor) -> napi::Result<ManifestAnchor> {
    let manifest_url = manifest.manifest_url.trim();
    if manifest_url.is_empty() {
        return Ok(manifest.clone());
    }

    let live_hash = compute_manifest_body_hash(manifest_url)
        .await
        .map_err(|e| {
            napi::Error::from_reason(format!("Erro sincronizando manifesto Bloom ativo: {}", e))
        })?;

    let mut refreshed = manifest.clone();
    refreshed.manifest_hash = live_hash;
    refreshed.updated_at = now_ts();
    Ok(refreshed)
}

fn is_missing_attrib_error_message(message: &str) -> bool {
    message.contains("não encontrado")
        || message.contains("nao encontrado")
        || message.contains("data null/invalido")
        || message.contains("Chave '")
}

async fn read_attrib_raw_optional_async(
    pool: &indy_vdr::pool::PoolRunner,
    target_did: &str,
    key: &str,
) -> napi::Result<Option<String>> {
    match read_attrib_raw_async(pool, target_did, key).await {
        Ok(value) => Ok(Some(value)),
        Err(err) => {
            let message = err.to_string();
            if is_missing_attrib_error_message(&message) {
                Ok(None)
            } else {
                Err(err)
            }
        }
    }
}

fn default_k_vector_id_for_issuer(issuer_did: &str) -> String {
    format!("k-vector-active-{}", issuer_did)
}

async fn write_k_vector_record_to_ledger(
    store: &Store,
    pool: &indy_vdr::pool::PoolRunner,
    issuer_did: &str,
    record: &KVectorRecord,
    chunk_size_bytes: usize,
) -> napi::Result<(KLedgerAnchor, bool)> {
    if let Some(active_anchor_json) =
        read_attrib_raw_optional_async(pool, issuer_did, REVOCATION_ACTIVE_K_ATTR_KEY).await?
    {
        let active_anchor: KLedgerAnchor =
            serde_json::from_str(&active_anchor_json).map_err(|e| {
                napi::Error::from_reason(format!("REVOCATION_K_ACTIVE inválido: {}", e))
            })?;
        let active_record = read_k_vector_record_from_anchor(pool, &active_anchor).await?;

        if active_record.k_vector_id == record.k_vector_id
            && active_record.vector_hash == record.vector_hash
        {
            return Ok((active_anchor, true));
        }

        return Err(napi::Error::from_reason(format!(
            "O emissor '{}' já possui um vetor K ativo no ledger (k_vector_id='{}'). \
Somente um único vetor K por DID é permitido para não invalidar credenciais emitidas anteriormente.",
            issuer_did, active_anchor.k_vector_id
        )));
    }

    let chunks = build_k_chunks(record, chunk_size_bytes);
    let anchor = build_k_ledger_anchor(record, chunk_size_bytes);

    for chunk in &chunks {
        write_attrib_raw_async(store, pool, issuer_did, &chunk.key, &chunk.value_b64).await?;
    }

    let anchor_json = serde_json::to_string(&anchor).map_err(|e| {
        napi::Error::from_reason(format!("Erro serializando K ledger anchor: {}", e))
    })?;
    write_attrib_raw_async(store, pool, issuer_did, &anchor.index_key, &anchor_json).await?;
    write_attrib_raw_async(
        store,
        pool,
        issuer_did,
        REVOCATION_ACTIVE_K_ATTR_KEY,
        &anchor_json,
    )
    .await?;

    Ok((anchor, false))
}

async fn read_k_vector_record_from_anchor(
    pool: &indy_vdr::pool::PoolRunner,
    anchor: &KLedgerAnchor,
) -> napi::Result<KVectorRecord> {
    let mut chunks = Vec::with_capacity(anchor.chunk_count as usize);
    for index in 0..anchor.chunk_count {
        let chunk_key = make_k_chunk_key(&anchor.chunk_prefix, index);
        let value_b64 = read_attrib_raw_async(pool, &anchor.issuer_did, &chunk_key).await?;
        chunks.push(KChunkRecord {
            k_vector_id: anchor.k_vector_id.clone(),
            index,
            total: anchor.chunk_count,
            key: chunk_key,
            value_b64,
        });
    }

    let values = crate::modules::revocation::k_vector::rebuild_k_from_chunks(
        &chunks,
        anchor.value_count,
        anchor.value_size_bytes,
    )
    .map_err(|e| {
        napi::Error::from_reason(format!("Erro reconstruindo K a partir dos ATTRIBs: {}", e))
    })?;

    let rebuilt_hash = hash_k_vector(&values);
    if rebuilt_hash != anchor.vector_hash {
        return Err(napi::Error::from_reason(
            "vector_hash reconstruído difere do anchor publicado".to_string(),
        ));
    }

    Ok(KVectorRecord {
        issuer_did: anchor.issuer_did.clone(),
        k_vector_id: anchor.k_vector_id.clone(),
        version: anchor.version,
        hash_algorithm: anchor.hash_algorithm.clone(),
        vector_hash: anchor.vector_hash.clone(),
        values,
        created_at: anchor.created_at,
    })
}

async fn resolve_manifest_anchor(
    pool: &indy_vdr::pool::PoolRunner,
    issuer_did: &str,
    manifest_json: Option<String>,
) -> napi::Result<Option<ManifestAnchor>> {
    if let Some(raw) = manifest_json {
        if raw.trim().is_empty() {
            return Ok(None);
        }
        let manifest: ManifestAnchor = serde_json::from_str(&raw)
            .map_err(|e| napi::Error::from_reason(format!("manifest_json inválido: {}", e)))?;
        if manifest.issuer_did != issuer_did {
            return Err(napi::Error::from_reason(
                "issuer_did do manifesto difere do issuer_did da emissão".to_string(),
            ));
        }
        return Ok(Some(manifest));
    }

    let manifest_json =
        read_attrib_raw_optional_async(pool, issuer_did, REVOCATION_MANIFEST_ATTR_KEY).await?;
    match manifest_json {
        Some(raw) => {
            let manifest: ManifestAnchor = serde_json::from_str(&raw).map_err(|e| {
                napi::Error::from_reason(format!("Manifest anchor inválido no ledger: {}", e))
            })?;
            Ok(Some(manifest))
        }
        None => Ok(None),
    }
}

async fn resolve_or_create_k_for_issuer(
    store: &Store,
    pool: &indy_vdr::pool::PoolRunner,
    issuer_did: &str,
    k_vector_id: Option<String>,
    chunk_size_bytes: Option<u32>,
    manifest: Option<ManifestAnchor>,
) -> napi::Result<(String, KVectorRecord, KLedgerAnchor)> {
    let normalized_k_vector_id = k_vector_id
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    if let Some(setup) = get_revocation_setup_record(store, issuer_did).await? {
        let matches_requested = normalized_k_vector_id
            .as_ref()
            .map(|requested| requested == &setup.active_k_ledger_anchor.k_vector_id)
            .unwrap_or(true);
        if matches_requested {
            return Ok((
                "cache_local".to_string(),
                setup.active_k_vector,
                setup.active_k_ledger_anchor,
            ));
        }
    }

    if let Some(explicit_k_vector_id) = normalized_k_vector_id.clone() {
        let anchor_json =
            read_attrib_raw_async(pool, issuer_did, &make_k_anchor_key(&explicit_k_vector_id))
                .await?;
        let anchor: KLedgerAnchor = serde_json::from_str(&anchor_json)
            .map_err(|e| napi::Error::from_reason(format!("K ledger anchor inválido: {}", e)))?;
        let record = read_k_vector_record_from_anchor(pool, &anchor).await?;
        let now = now_ts();
        store_revocation_setup_record(
            store,
            &RevocationSetupRecord {
                issuer_did: issuer_did.to_string(),
                active_k_ledger_anchor: anchor.clone(),
                active_k_vector: record.clone(),
                manifest,
                created_at: now,
                updated_at: now,
            },
        )
        .await?;
        return Ok(("ledger_explicit".to_string(), record, anchor));
    }

    if let Some(active_anchor_json) =
        read_attrib_raw_optional_async(pool, issuer_did, REVOCATION_ACTIVE_K_ATTR_KEY).await?
    {
        let anchor: KLedgerAnchor = serde_json::from_str(&active_anchor_json).map_err(|e| {
            napi::Error::from_reason(format!("REVOCATION_K_ACTIVE inválido: {}", e))
        })?;
        let record = read_k_vector_record_from_anchor(pool, &anchor).await?;
        let now = now_ts();
        store_revocation_setup_record(
            store,
            &RevocationSetupRecord {
                issuer_did: issuer_did.to_string(),
                active_k_ledger_anchor: anchor.clone(),
                active_k_vector: record.clone(),
                manifest,
                created_at: now,
                updated_at: now,
            },
        )
        .await?;
        return Ok(("ledger_active".to_string(), record, anchor));
    }

    let resolved_k_vector_id = default_k_vector_id_for_issuer(issuer_did);
    let recommended_chunk_size = recommended_chunk_size_bytes(&resolved_k_vector_id);
    let chunk_size = chunk_size_bytes
        .map(|value| value as usize)
        .unwrap_or(recommended_chunk_size)
        .min(recommended_chunk_size)
        .max(256);
    let record = create_k_vector_record(issuer_did, &resolved_k_vector_id);
    let (anchor, _) =
        write_k_vector_record_to_ledger(store, pool, issuer_did, &record, chunk_size).await?;
    let now = now_ts();
    store_revocation_setup_record(
        store,
        &RevocationSetupRecord {
            issuer_did: issuer_did.to_string(),
            active_k_ledger_anchor: anchor.clone(),
            active_k_vector: record.clone(),
            manifest,
            created_at: now,
            updated_at: now,
        },
    )
    .await?;

    Ok(("created_and_written".to_string(), record, anchor))
}

fn merge_credential_values_with_control_attributes(
    values_json: &str,
    control_attributes: &Map<String, Value>,
) -> std::result::Result<String, String> {
    let mut values_map: Map<String, Value> =
        serde_json::from_str(values_json).map_err(|e| format!("values_json inválido: {}", e))?;
    for (key, value) in control_attributes {
        values_map.insert(key.clone(), value.clone());
    }
    serde_json::to_string(&Value::Object(values_map))
        .map_err(|e| format!("Erro serializando values_json combinado: {}", e))
}

async fn issue_credential_json_async(
    store: &Store,
    cred_def_id: &str,
    offer_json: &str,
    request_json: &str,
    values_json: &str,
) -> napi::Result<String> {
    use anoncreds::data_types::cred_def::CredentialDefinitionId;
    use anoncreds::types::{AttributeValues, CredentialOffer, CredentialRequest, CredentialValues};

    fn hash_string_to_int_str(s: &str) -> String {
        use num_bigint::BigUint;
        use sha2::{Digest, Sha256};

        let digest = Sha256::digest(s.as_bytes());
        let n = BigUint::from_bytes_be(&digest);
        n.to_str_radix(10)
    }

    let mut session = store
        .session(None)
        .await
        .map_err(|e| napi::Error::from_reason(format!("Erro sessão: {}", e)))?;

    let _cred_def_id_obj = CredentialDefinitionId::new(cred_def_id.to_string())
        .map_err(|_| napi::Error::from_reason("CredDefID invalido"))?;

    let offer: CredentialOffer = serde_json::from_str(offer_json)
        .map_err(|e| napi::Error::from_reason(format!("Erro Offer JSON: {}", e)))?;

    let request: CredentialRequest = serde_json::from_str(request_json)
        .map_err(|e| napi::Error::from_reason(format!("Erro Request JSON: {}", e)))?;

    let values_map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(values_json)
        .map_err(|e| napi::Error::from_reason(format!("Erro Values JSON: {}", e)))?;

    let mut cred_values = CredentialValues::default();
    for (key, val) in values_map {
        let raw_val = val.as_str().unwrap_or("").to_string();
        let encoded_val = if raw_val.chars().all(|c| c.is_ascii_digit()) && !raw_val.is_empty() {
            raw_val.clone()
        } else {
            hash_string_to_int_str(&raw_val)
        };
        cred_values.0.insert(
            key,
            AttributeValues {
                raw: raw_val,
                encoded: encoded_val,
            },
        );
    }

    let priv_entry = session
        .fetch("cred_def_private", cred_def_id, false)
        .await
        .map_err(|e| napi::Error::from_reason(format!("Erro DB Priv: {}", e)))?
        .ok_or_else(|| napi::Error::from_reason("CredDef Private não achada"))?;

    let cred_def_priv_str = String::from_utf8(priv_entry.value.to_vec()).unwrap_or_default();
    let cred_def_priv: anoncreds::data_types::cred_def::CredentialDefinitionPrivate =
        serde_json::from_str(&cred_def_priv_str)
            .map_err(|e| napi::Error::from_reason(format!("Erro Parse Priv: {}", e)))?;

    let pub_entry = session
        .fetch("cred_def", cred_def_id, false)
        .await
        .map_err(|_e| napi::Error::from_reason("Erro DB Pub"))?
        .ok_or_else(|| napi::Error::from_reason("CredDef Public não achada"))?;

    let cred_def_pub_str = String::from_utf8(pub_entry.value.to_vec()).unwrap_or_default();
    let cred_def_pub: anoncreds::data_types::cred_def::CredentialDefinition =
        serde_json::from_str(&cred_def_pub_str)
            .map_err(|e| napi::Error::from_reason(format!("Erro Parse Pub: {}", e)))?;

    let credential = anoncreds::issuer::create_credential(
        &cred_def_pub,
        &cred_def_priv,
        &offer,
        &request,
        cred_values,
        None,
    )
    .map_err(|e| napi::Error::from_reason(format!("Erro anoncreds create_credential: {}", e)))?;

    serde_json::to_string(&credential)
        .map_err(|e| napi::Error::from_reason(format!("Erro serializando credencial: {}", e)))
}

pub fn build_control_attributes_map(control: &RevocationControlValues) -> Map<String, Value> {
    let mut out = Map::new();
    out.insert("seed".to_string(), Value::String(control.seed.clone()));
    out.insert(
        "start_time".to_string(),
        Value::String(control.start_time.to_string()),
    );
    out.insert(
        "unit_of_time".to_string(),
        Value::String(control.unit_of_time.clone()),
    );
    out.insert(
        "time_window".to_string(),
        Value::String(control.time_window.to_string()),
    );
    out.insert(
        "root_merkle_L".to_string(),
        Value::String(control.root_merkle_l.clone()),
    );
    out
}

pub fn build_revocable_delivery_payload(
    credential_json: &str,
    issuer_did: &str,
    cred_def_id: &str,
    schema_id: &str,
    control: &RevocationControlValues,
    k_ledger_anchor: Option<&KLedgerAnchor>,
    manifest: Option<&ManifestAnchor>,
) -> std::result::Result<Value, String> {
    let credential_value: Value = serde_json::from_str(credential_json)
        .map_err(|e| format!("credential_json inválido para delivery_payload: {}", e))?;

    Ok(serde_json::json!({
        "credential": credential_value,
        "credential_json": credential_json,
        "control_attributes": build_control_attributes_map(control),
        "control_values": control,
        "revocation_binding": {
            "issuer_did": issuer_did,
            "cred_def_id": cred_def_id,
            "schema_id": schema_id,
            "k_vector_id": k_ledger_anchor.map(|anchor| anchor.k_vector_id.clone()),
            "k_ledger_anchor": k_ledger_anchor,
            "manifest_attr_key": REVOCATION_MANIFEST_ATTR_KEY,
            "manifest": manifest,
        }
    }))
}

pub fn build_revocation_keys(
    seed: &str,
    start_time: i64,
    unit_of_time: &str,
    time_window: u32,
    k_values: &[String],
    t_entries: &[crate::modules::revocation::types::TEntry],
) -> std::result::Result<Vec<String>, String> {
    let mut out = Vec::with_capacity(t_entries.len());
    let decoded_k_values = decode_k_vector_values(k_values)?;

    for (i, entry) in t_entries.iter().enumerate() {
        validate_t_entry_indices(
            &entry.k_indices,
            crate::modules::revocation::merkle::K_SUBSET_SIZE,
            decoded_k_values.len(),
        )?;
        let resolved_values = resolve_k_values_from_indices(&decoded_k_values, &entry.k_indices)?;
        let window_start = window_start_for_index(
            start_time,
            unit_of_time,
            time_window,
            u32::try_from(i).map_err(|_| "window_index fora da faixa".to_string())?,
        )?;
        out.push(compute_revocation_key_from_k_values(
            seed,
            window_start,
            &resolved_values,
        ));
    }

    Ok(out)
}

pub fn build_window_starts(
    start_time: i64,
    unit_of_time: &str,
    time_window: u32,
    count: usize,
    start_index: usize,
) -> std::result::Result<Vec<i64>, String> {
    let mut out = Vec::with_capacity(count);
    for offset in 0..count {
        let index = u32::try_from(start_index + offset)
            .map_err(|_| "window_index fora da faixa".to_string())?;
        out.push(window_start_for_index(
            start_time,
            unit_of_time,
            time_window,
            index,
        )?);
    }
    Ok(out)
}

fn build_issued_revocable_summary_value(
    record: &IssuedCredentialRecord,
    requested_window_index: Option<u32>,
) -> Value {
    let requested_window_index = requested_window_index.unwrap_or(0);
    let total_windows = record.control.window_count as usize;
    let valid_window_index = (requested_window_index as usize) < total_windows;
    let issuer_did = record
        .cred_def_id
        .split(':')
        .next()
        .unwrap_or_default()
        .to_string();

    serde_json::json!({
        "issuer_local_credential_id": record.issuer_local_credential_id,
        "issuer_did": issuer_did,
        "holder_did_hint": record.holder_did_hint,
        "cred_def_id": record.cred_def_id,
        "schema_id": record.schema_id,
        "status": record.status,
        "revoked_at": record.revoked_at,
        "revoked_from_window": record.revoked_from_window,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "window_count": record.control.window_count,
        "unit_of_time": record.control.unit_of_time,
        "time_window": record.control.time_window,
        "validity_end": record.control.validity_end,
        "extra_windows_for_fp": record.control.extra_windows_for_fp,
        "k_vector_id": record.k_ledger_anchor.as_ref().map(|anchor| anchor.k_vector_id.clone()),
        "manifest_url": record.manifest.as_ref().map(|manifest| manifest.manifest_url.clone()),
        "manifest_version": record.manifest.as_ref().map(|manifest| manifest.manifest_version.clone()),
        "requested_window_index": requested_window_index,
        "requested_window_index_valid": valid_window_index,
        "revocation_keys_total": record.revocation_keys_by_window.len(),
    })
}

fn preflight_revoke_issued_record(
    record: &IssuedCredentialRecord,
    revoke_from_window: u32,
) -> Value {
    let mut errors: Vec<String> = Vec::new();

    if record.status == "revoked" {
        errors.push("Credencial emitida já está com status revoked".to_string());
    }

    if record.manifest.is_none() {
        errors.push("A credencial emitida não possui manifesto Bloom associado".to_string());
    }

    if record.k_ledger_anchor.is_none() {
        errors.push("A credencial emitida não possui k_ledger_anchor associado".to_string());
    }

    if record.revocation_keys_by_window.is_empty() {
        errors.push("A credencial emitida não possui revocation_keys_by_window".to_string());
    }

    let start_index = revoke_from_window as usize;
    if start_index >= record.revocation_keys_by_window.len() {
        errors.push(format!(
            "revoke_from_window={} fora do intervalo (total={})",
            start_index,
            record.revocation_keys_by_window.len()
        ));
    }

    let window_starts_preview = if errors.is_empty() {
        build_window_starts(
            record.control.start_time,
            &record.control.unit_of_time,
            record.control.time_window,
            record.revocation_keys_by_window.len() - start_index,
            start_index,
        )
        .unwrap_or_default()
    } else {
        Vec::new()
    };

    serde_json::json!({
        "ok": true,
        "can_revoke": errors.is_empty(),
        "errors": errors,
        "summary": build_issued_revocable_summary_value(record, Some(revoke_from_window)),
        "preflight": {
            "revoke_from_window": revoke_from_window,
            "revocation_keys_to_write": if start_index < record.revocation_keys_by_window.len() {
                record.revocation_keys_by_window.len() - start_index
            } else {
                0
            },
            "window_starts_to_write_preview": window_starts_preview,
        }
    })
}

#[allow(clippy::too_many_arguments)]
pub fn create_revocable_credential_artifacts(
    issuer_local_credential_id: &str,
    holder_did_hint: Option<String>,
    cred_def_id: &str,
    schema_id: &str,
    credential_json: &str,
    issuer_did: &str,
    k_values: &[String],
    start_time: i64,
    validity_end: i64,
    unit_of_time: &str,
    time_window: u32,
    _extra_windows_for_fp: u32,
    k_ledger_anchor: Option<KLedgerAnchor>,
    manifest: Option<ManifestAnchor>,
) -> std::result::Result<RevocableCredentialArtifacts, String> {
    // The current protocol fixes the false-positive confirmation budget at 10
    // extra windows for every revocable credential, regardless of caller input.
    let extra_windows_for_fp = DEFAULT_EXTRA_WINDOWS_FOR_FP;

    let layout = compute_window_layout(
        start_time,
        validity_end,
        unit_of_time,
        time_window,
        extra_windows_for_fp,
    )?;
    let window_count = layout.total_window_count;

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let seed_b64 = B64.encode(seed);

    let t_entries = build_t_vector(window_count, k_values.len());
    let tmp_vector_b64 = extract_tmp_vector(&t_entries);
    let s_entries = materialize_s_vector(k_values, &t_entries)?;
    let l_values = build_l_vector(k_values, &t_entries)?;
    let root_merkle_l = build_merkle_root(&l_values)?;
    let vectors_summary: RevocationVectorsSummary = summarize_vectors(
        window_count,
        &l_values,
        &t_entries,
        &tmp_vector_b64,
        &s_entries,
    );
    let revocation_keys_by_window = build_revocation_keys(
        &seed_b64,
        start_time,
        unit_of_time,
        time_window,
        k_values,
        &t_entries,
    )?;

    let control = RevocationControlValues {
        seed: seed_b64,
        start_time,
        validity_end,
        unit_of_time: unit_of_time.to_string(),
        time_window,
        extra_windows_for_fp,
        root_merkle_l,
        window_count,
        base_window_count: layout.base_window_count,
        confirmation_window_count: layout.confirmation_window_count,
        last_valid_window_index: layout.last_valid_window_index,
        last_confirmation_window_index: layout.last_confirmation_window_index,
    };

    let holder_bundle = HolderRevocationBundle {
        credential_id: None,
        cred_def_id: cred_def_id.to_string(),
        schema_id: schema_id.to_string(),
        issuer_did: issuer_did.to_string(),
        control: control.clone(),
        k_ledger_anchor: k_ledger_anchor.clone(),
        tmp_vector_b64,
        t_entries: t_entries.clone(),
        l_values,
        vectors_summary: vectors_summary.clone(),
        manifest: manifest.clone(),
    };

    let now = now_ts();
    let issuer_record = IssuedCredentialRecord {
        issuer_local_credential_id: issuer_local_credential_id.to_string(),
        holder_did_hint,
        cred_def_id: cred_def_id.to_string(),
        schema_id: schema_id.to_string(),
        credential_json: credential_json.to_string(),
        control: control.clone(),
        k_ledger_anchor,
        revocation_keys_by_window,
        vectors_summary,
        manifest,
        status: "active".to_string(),
        revoked_at: None,
        revoked_from_window: None,
        created_at: now,
        updated_at: now,
    };

    Ok(RevocableCredentialArtifacts {
        control,
        holder_bundle,
        issuer_record,
    })
}

fn normalize_extra_windows_for_fp(extra_windows_for_fp: Option<u32>) -> Result<u32> {
    match extra_windows_for_fp {
        Some(value) if value != DEFAULT_EXTRA_WINDOWS_FOR_FP => {
            Err(napi::Error::from_reason(format!(
                "extra_windows_for_fp deve ser exatamente {}. Valor recebido: {}",
                DEFAULT_EXTRA_WINDOWS_FOR_FP, value
            )))
        }
        _ => Ok(DEFAULT_EXTRA_WINDOWS_FOR_FP),
    }
}

#[napi]
impl IndyAgent {
    #[napi]
    pub fn revocation_setup_create_k(
        &self,
        issuer_did: String,
        k_vector_id: Option<String>,
        chunk_size_bytes: Option<u32>,
    ) -> Result<String> {
        if issuer_did.trim().is_empty() {
            return Err(Error::from_reason("issuer_did vazio"));
        }

        let resolved_k_vector_id = k_vector_id
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| format!("k-vector-{}", now_ts()));

        let recommended_chunk_size = recommended_chunk_size_bytes(&resolved_k_vector_id);
        let chunk_size = chunk_size_bytes
            .map(|value| value as usize)
            .unwrap_or(recommended_chunk_size)
            .min(recommended_chunk_size)
            .max(256);
        let record = create_k_vector_record(&issuer_did, &resolved_k_vector_id);
        let anchor = build_k_ledger_anchor(&record, chunk_size);
        let chunks = build_k_chunks(&record, chunk_size);

        serde_json::to_string(&serde_json::json!({
            "ok": true,
            "recommended_chunk_size_bytes": recommended_chunk_size,
            "k_vector": record,
            "ledger_anchor": anchor,
            "chunks": chunks,
        }))
        .map_err(|e| Error::from_reason(format!("Erro serializando setup K: {}", e)))
    }

    #[napi]
    pub fn revocation_write_k_vector_on_ledger(
        &self,
        env: Env,
        _genesis_path: String,
        issuer_did: String,
        k_vector_json: String,
        chunk_size_bytes: Option<u32>,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        let pool = match &self.pool {
            Some(p) => p.clone(),
            None => {
                return Err(Error::from_reason(
                    "Não conectado à rede. Execute connect_network antes.",
                ))
            }
        };

        env.execute_tokio_future(
            async move {
                let record: KVectorRecord =
                    serde_json::from_str(&k_vector_json).map_err(|e| {
                        napi::Error::from_reason(format!("k_vector_json inválido: {}", e))
                    })?;

                if record.issuer_did != issuer_did {
                    return Err(napi::Error::from_reason(
                        "issuer_did informado difere do issuer_did do K vector".to_string(),
                    ));
                }
                if record.values.len() != K_VECTOR_LEN {
                    return Err(napi::Error::from_reason(format!(
                        "K vector deve conter {} valores, mas recebeu {}",
                        K_VECTOR_LEN,
                        record.values.len()
                    )));
                }

                let computed_hash = hash_k_vector(&record.values);
                if computed_hash != record.vector_hash {
                    return Err(napi::Error::from_reason(
                        "vector_hash do K vector não confere com os valores".to_string(),
                    ));
                }

                let recommended_chunk_size = recommended_chunk_size_bytes(&record.k_vector_id);
                let chunk_size = chunk_size_bytes
                    .map(|value| value as usize)
                    .unwrap_or(recommended_chunk_size)
                    .min(recommended_chunk_size)
                    .max(256);
                let chunks = build_k_chunks(&record, chunk_size);
                let (anchor, reused_existing) =
                    write_k_vector_record_to_ledger(&store, &pool, &issuer_did, &record, chunk_size)
                        .await?;

                let now = now_ts();
                store_revocation_setup_record(
                    &store,
                    &RevocationSetupRecord {
                        issuer_did: issuer_did.clone(),
                        active_k_ledger_anchor: anchor.clone(),
                        active_k_vector: record.clone(),
                        manifest: None,
                        created_at: now,
                        updated_at: now,
                    },
                )
                .await?;

                serde_json::to_string(&serde_json::json!({
                    "ok": true,
                    "issuer_did": issuer_did,
                    "k_vector_id": record.k_vector_id,
                    "ledger_anchor": anchor,
                    "active_key": REVOCATION_ACTIVE_K_ATTR_KEY,
                    "reused_existing": reused_existing,
                    "recommended_chunk_size_bytes": recommended_chunk_size,
                    "written_chunk_keys": chunks.iter().map(|chunk| chunk.key.clone()).collect::<Vec<_>>(),
                }))
                .map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando resposta de escrita do K: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn revocation_read_k_vector_from_ledger(
        &self,
        env: Env,
        _genesis_path: String,
        issuer_did: String,
        k_vector_id: String,
    ) -> Result<JsObject> {
        let pool = match &self.pool {
            Some(p) => p.clone(),
            None => {
                return Err(Error::from_reason(
                    "Não conectado à rede. Execute connect_network antes.",
                ))
            }
        };

        env.execute_tokio_future(
            async move {
                let index_key = make_k_anchor_key(&k_vector_id);
                let anchor_json = read_attrib_raw_async(&pool, &issuer_did, &index_key).await?;
                let anchor: KLedgerAnchor = serde_json::from_str(&anchor_json).map_err(|e| {
                    napi::Error::from_reason(format!("K ledger anchor inválido: {}", e))
                })?;

                let mut chunks = Vec::with_capacity(anchor.chunk_count as usize);
                for index in 0..anchor.chunk_count {
                    let chunk_key = make_k_chunk_key(&anchor.chunk_prefix, index);
                    let value_b64 = read_attrib_raw_async(&pool, &issuer_did, &chunk_key).await?;
                    chunks.push(KChunkRecord {
                        k_vector_id: anchor.k_vector_id.clone(),
                        index,
                        total: anchor.chunk_count,
                        key: chunk_key,
                        value_b64,
                    });
                }

                let values = crate::modules::revocation::k_vector::rebuild_k_from_chunks(
                    &chunks,
                    anchor.value_count,
                    anchor.value_size_bytes,
                )
                .map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro reconstruindo K a partir dos ATTRIBs: {}",
                        e
                    ))
                })?;

                let rebuilt_hash = hash_k_vector(&values);
                if rebuilt_hash != anchor.vector_hash {
                    return Err(napi::Error::from_reason(
                        "vector_hash reconstruído difere do anchor publicado".to_string(),
                    ));
                }

                let record = KVectorRecord {
                    issuer_did: anchor.issuer_did.clone(),
                    k_vector_id: anchor.k_vector_id.clone(),
                    version: anchor.version,
                    hash_algorithm: anchor.hash_algorithm.clone(),
                    vector_hash: anchor.vector_hash.clone(),
                    values,
                    created_at: anchor.created_at,
                };

                serde_json::to_string(&serde_json::json!({
                    "ok": true,
                    "ledger_anchor": anchor,
                    "chunks": chunks,
                    "k_vector": record,
                }))
                .map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando resposta de leitura do K: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn revocation_build_manifest_anchor(
        &self,
        issuer_did: String,
        manifest_url: String,
        manifest_hash: String,
        manifest_version: Option<String>,
    ) -> Result<String> {
        if issuer_did.trim().is_empty() {
            return Err(Error::from_reason("issuer_did vazio"));
        }
        if manifest_url.trim().is_empty() {
            return Err(Error::from_reason("manifest_url vazio"));
        }
        if manifest_hash.trim().is_empty() {
            return Err(Error::from_reason("manifest_hash vazio"));
        }

        let manifest = build_manifest_anchor(
            &issuer_did,
            &manifest_url,
            &manifest_hash,
            manifest_version
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or("1"),
        );

        serde_json::to_string(&manifest)
            .map_err(|e| Error::from_reason(format!("Erro serializando manifesto: {}", e)))
    }

    #[napi]
    pub fn revocation_write_manifest_anchor_on_ledger(
        &self,
        env: Env,
        _genesis_path: String,
        issuer_did: String,
        manifest_json: String,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        let pool = match &self.pool {
            Some(p) => p.clone(),
            None => {
                return Err(Error::from_reason(
                    "Não conectado à rede. Execute connect_network antes.",
                ))
            }
        };

        env.execute_tokio_future(
            async move {
                let mut manifest: ManifestAnchor =
                    serde_json::from_str(&manifest_json).map_err(|e| {
                        napi::Error::from_reason(format!("manifest_json inválido: {}", e))
                    })?;

                if manifest.issuer_did != issuer_did {
                    return Err(napi::Error::from_reason(
                        "issuer_did informado difere do issuer_did do manifesto".to_string(),
                    ));
                }

                manifest.manifest_hash = compute_manifest_body_hash(&manifest.manifest_url)
                    .await
                    .map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro calculando hash do arquivo manifesto antes da ancoragem: {}",
                        e
                    ))
                })?;
                manifest.updated_at = now_ts();
                let normalized_manifest_json = serde_json::to_string(&manifest).map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando manifesto normalizado: {}",
                        e
                    ))
                })?;

                write_attrib_raw_async(
                    &store,
                    &pool,
                    &issuer_did,
                    REVOCATION_MANIFEST_ATTR_KEY,
                    &normalized_manifest_json,
                )
                .await?;

                serde_json::to_string(&serde_json::json!({
                    "ok": true,
                    "issuer_did": issuer_did,
                    "key": REVOCATION_MANIFEST_ATTR_KEY,
                    "manifest": manifest,
                }))
                .map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando resposta da escrita do manifesto: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn revocation_read_manifest_anchor_from_ledger(
        &self,
        env: Env,
        _genesis_path: String,
        issuer_did: String,
    ) -> Result<JsObject> {
        let pool = match &self.pool {
            Some(p) => p.clone(),
            None => {
                return Err(Error::from_reason(
                    "Não conectado à rede. Execute connect_network antes.",
                ))
            }
        };

        env.execute_tokio_future(
            async move {
                let manifest_json =
                    read_attrib_raw_async(&pool, &issuer_did, REVOCATION_MANIFEST_ATTR_KEY).await?;
                let manifest: ManifestAnchor =
                    serde_json::from_str(&manifest_json).map_err(|e| {
                        napi::Error::from_reason(format!("Manifest anchor inválido: {}", e))
                    })?;

                serde_json::to_string(&serde_json::json!({
                    "ok": true,
                    "key": REVOCATION_MANIFEST_ATTR_KEY,
                    "manifest": manifest,
                }))
                .map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando resposta da leitura do manifesto: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn create_revocable_credential_package(
        &self,
        env: Env,
        issuer_local_credential_id: String,
        holder_did_hint: Option<String>,
        cred_def_id: String,
        schema_id: String,
        credential_json: String,
        issuer_did: String,
        k_values_json: String,
        start_time: i64,
        validity_end: i64,
        unit_of_time: String,
        time_window: u32,
        extra_windows_for_fp: Option<u32>,
        manifest_json: Option<String>,
        k_ledger_anchor_json: Option<String>,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let extra_windows_for_fp = normalize_extra_windows_for_fp(extra_windows_for_fp)?;

                let k_values: Vec<String> = serde_json::from_str(&k_values_json).map_err(|e| {
                    napi::Error::from_reason(format!("k_values_json inválido: {}", e))
                })?;

                if k_values.is_empty() {
                    return Err(napi::Error::from_reason("k_values_json vazio"));
                }

                let manifest = match manifest_json {
                    Some(raw) if !raw.trim().is_empty() => {
                        Some(serde_json::from_str::<ManifestAnchor>(&raw).map_err(|e| {
                            napi::Error::from_reason(format!("manifest_json inválido: {}", e))
                        })?)
                    }
                    _ => None,
                };
                let k_ledger_anchor = match k_ledger_anchor_json {
                    Some(raw) if !raw.trim().is_empty() => {
                        Some(serde_json::from_str::<KLedgerAnchor>(&raw).map_err(|e| {
                            napi::Error::from_reason(format!(
                                "k_ledger_anchor_json inválido: {}",
                                e
                            ))
                        })?)
                    }
                    _ => None,
                };

                let artifacts = create_revocable_credential_artifacts(
                    &issuer_local_credential_id,
                    holder_did_hint,
                    &cred_def_id,
                    &schema_id,
                    &credential_json,
                    &issuer_did,
                    &k_values,
                    start_time,
                    validity_end,
                    &unit_of_time,
                    time_window,
                    extra_windows_for_fp,
                    k_ledger_anchor.clone(),
                    manifest,
                )
                .map_err(|e| napi::Error::from_reason(e.to_string()))?;

                store_issued_credential_record(&store, &artifacts.issuer_record).await?;

                let delivery_payload = build_revocable_delivery_payload(
                    &credential_json,
                    &issuer_did,
                    &cred_def_id,
                    &schema_id,
                    &artifacts.control,
                    k_ledger_anchor.as_ref(),
                    artifacts.holder_bundle.manifest.as_ref(),
                )
                .map_err(|e| napi::Error::from_reason(e))?;

                let package = serde_json::json!({
                    "type": "ssi.revocable_credential.package",
                    "version": 1,
                    "credential_json": credential_json,
                    "control_attributes": build_control_attributes_map(&artifacts.control),
                    "control_values": artifacts.control,
                    "k_ledger_anchor": k_ledger_anchor,
                    "manifest": artifacts.holder_bundle.manifest,
                    "delivery_payload": delivery_payload,
                    "holder_bundle": artifacts.holder_bundle,
                    "issuer_record": artifacts.issuer_record,
                });

                serde_json::to_string(&package).map_err(|e| {
                    napi::Error::from_reason(format!("Erro serializando pacote revogável: {}", e))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    #[allow(clippy::too_many_arguments)]
    pub fn issue_revocable_credential(
        &self,
        env: Env,
        _genesis_path: String,
        issuer_local_credential_id: String,
        holder_did_hint: Option<String>,
        cred_def_id: String,
        schema_id: String,
        offer_json: String,
        request_json: String,
        values_json: String,
        start_time: i64,
        validity_end: i64,
        unit_of_time: String,
        time_window: u32,
        extra_windows_for_fp: Option<u32>,
        manifest_json: Option<String>,
        k_vector_id: Option<String>,
        chunk_size_bytes: Option<u32>,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        let pool = match &self.pool {
            Some(p) => p.clone(),
            None => {
                return Err(Error::from_reason(
                    "Não conectado à rede. Execute connect_network antes.",
                ))
            }
        };

        env.execute_tokio_future(
            async move {
                let extra_windows_for_fp = normalize_extra_windows_for_fp(extra_windows_for_fp)?;

                let issuer_did = cred_def_id
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if issuer_did.is_empty() {
                    return Err(napi::Error::from_reason(
                        "Issuer DID não derivado do CredDefID".to_string(),
                    ));
                }

                let manifest = resolve_manifest_anchor(&pool, &issuer_did, manifest_json).await?;
                let (k_resolution_source, k_vector, k_ledger_anchor) =
                    resolve_or_create_k_for_issuer(
                        &store,
                        &pool,
                        &issuer_did,
                        k_vector_id,
                        chunk_size_bytes,
                        manifest.clone(),
                    )
                    .await?;

                let placeholder_credential_json = serde_json::json!({
                    "schema_id": schema_id,
                    "cred_def_id": cred_def_id,
                    "values": {}
                })
                .to_string();

                let mut artifacts = create_revocable_credential_artifacts(
                    &issuer_local_credential_id,
                    holder_did_hint,
                    &cred_def_id,
                    &schema_id,
                    &placeholder_credential_json,
                    &issuer_did,
                    &k_vector.values,
                    start_time,
                    validity_end,
                    &unit_of_time,
                    time_window,
                    extra_windows_for_fp,
                    Some(k_ledger_anchor.clone()),
                    manifest.clone(),
                )
                .map_err(|e| napi::Error::from_reason(e.to_string()))?;

                let control_attributes = build_control_attributes_map(&artifacts.control);
                let issued_values_json = merge_credential_values_with_control_attributes(
                    &values_json,
                    &control_attributes,
                )
                .map_err(napi::Error::from_reason)?;

                let credential_json = issue_credential_json_async(
                    &store,
                    &cred_def_id,
                    &offer_json,
                    &request_json,
                    &issued_values_json,
                )
                .await?;

                artifacts.issuer_record.credential_json = credential_json.clone();
                store_issued_credential_record(&store, &artifacts.issuer_record).await?;

                let delivery_payload = build_revocable_delivery_payload(
                    &credential_json,
                    &issuer_did,
                    &cred_def_id,
                    &schema_id,
                    &artifacts.control,
                    Some(&k_ledger_anchor),
                    manifest.as_ref(),
                )
                .map_err(napi::Error::from_reason)?;

                let package = serde_json::json!({
                    "type": "ssi.revocable_credential.package",
                    "version": 2,
                    "credential_json": credential_json,
                    "issued_values_json": issued_values_json,
                    "control_attributes": control_attributes,
                    "control_values": artifacts.control,
                    "k_ledger_anchor": k_ledger_anchor,
                    "manifest": manifest,
                    "k_resolution_source": k_resolution_source,
                    "delivery_payload": delivery_payload,
                    "holder_bundle": artifacts.holder_bundle,
                    "issuer_record": artifacts.issuer_record,
                });

                serde_json::to_string(&package).map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando pacote revogável emitido: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn list_issued_credentials(
        &self,
        env: Env,
        status_filter: Option<String>,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let records =
                    list_issued_credential_records(&store, status_filter.as_deref()).await?;
                serde_json::to_string(&records).map_err(|e| {
                    napi::Error::from_reason(format!("Erro serializando issued credentials: {}", e))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn get_issued_credential(&self, env: Env, id_local: String) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let record = get_issued_credential_record(&store, &id_local)
                    .await?
                    .ok_or_else(|| {
                        napi::Error::from_reason(format!(
                            "Issued credential não encontrada: {}",
                            id_local
                        ))
                    })?;

                serde_json::to_string(&record).map_err(|e| {
                    napi::Error::from_reason(format!("Erro serializando issued credential: {}", e))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn revoke_issued_credential(
        &self,
        env: Env,
        id_local: String,
        bloom_admin_token: String,
        revoke_from_window: Option<u32>,
        reason: Option<String>,
        requested_by: Option<String>,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                if bloom_admin_token.trim().is_empty() {
                    return Err(napi::Error::from_reason("bloom_admin_token vazio"));
                }

                let mut record = get_issued_credential_record(&store, &id_local)
                    .await?
                    .ok_or_else(|| {
                        napi::Error::from_reason(format!(
                            "Issued credential não encontrada: {}",
                            id_local
                        ))
                    })?;

                let manifest = record.manifest.clone().ok_or_else(|| {
                    napi::Error::from_reason(
                        "A credencial emitida não possui manifesto Bloom associado".to_string(),
                    )
                })?;
                let refreshed_manifest = refresh_manifest_anchor_live(&manifest).await?;
                record.manifest = Some(refreshed_manifest.clone());

                let start_index = revoke_from_window.unwrap_or(0) as usize;
                if start_index >= record.revocation_keys_by_window.len() {
                    return Err(napi::Error::from_reason(format!(
                        "revoke_from_window={} fora do intervalo (total={})",
                        start_index,
                        record.revocation_keys_by_window.len()
                    )));
                }

                let keys_to_revoke = record.revocation_keys_by_window[start_index..].to_vec();
                let window_starts_to_revoke = build_window_starts(
                    record.control.start_time,
                    &record.control.unit_of_time,
                    record.control.time_window,
                    keys_to_revoke.len(),
                    start_index,
                )
                .map_err(napi::Error::from_reason)?;
                let issuer_did = record
                    .cred_def_id
                    .split(':')
                    .next()
                    .unwrap_or_default()
                    .to_string();

                let bloom_response = revoke_revocation_keys(
                    &refreshed_manifest,
                    &bloom_admin_token,
                    Some(issuer_did.as_str()),
                    Some(record.issuer_local_credential_id.as_str()),
                    &keys_to_revoke,
                    Some(&window_starts_to_revoke),
                    reason.as_deref(),
                    requested_by.as_deref(),
                )
                .await
                .map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro escrevendo revogação no serviço Bloom: {}",
                        e
                    ))
                })?;

                let now = now_ts();
                if let Ok(updated_manifest) =
                    refresh_manifest_anchor_live(&refreshed_manifest).await
                {
                    record.manifest = Some(updated_manifest);
                }
                record.status = "revoked".to_string();
                record.revoked_at = Some(now);
                record.revoked_from_window = Some(start_index as u32);
                record.updated_at = now;
                store_issued_credential_record(&store, &record).await?;

                let response = serde_json::json!({
                    "ok": true,
                    "issuer_local_credential_id": id_local,
                    "revoke_from_window": start_index,
                    "revocation_keys_written": keys_to_revoke.len(),
                    "window_starts_written": window_starts_to_revoke,
                    "bloom": bloom_response,
                    "issuer_record": record,
                });

                serde_json::to_string(&response).map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando resposta de revogação: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn list_issued_revocable_credentials(
        &self,
        env: Env,
        status_filter: Option<String>,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let records =
                    list_issued_credential_records(&store, status_filter.as_deref()).await?;
                let summaries: Vec<Value> = records
                    .iter()
                    .map(|record| build_issued_revocable_summary_value(record, None))
                    .collect();

                serde_json::to_string(&serde_json::json!({
                    "ok": true,
                    "count": summaries.len(),
                    "items": summaries,
                }))
                .map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando issued revocable credentials: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn get_issued_revocable_credential_summary(
        &self,
        env: Env,
        id_local: String,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let record = get_issued_credential_record(&store, &id_local)
                    .await?
                    .ok_or_else(|| {
                        napi::Error::from_reason(format!(
                            "Issued credential não encontrada: {}",
                            id_local
                        ))
                    })?;

                serde_json::to_string(&serde_json::json!({
                    "ok": true,
                    "issuer_record": record,
                    "revocation_summary": build_issued_revocable_summary_value(&record, None),
                }))
                .map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando summary da issued revocable credential: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn delete_issued_revocable_credential(
        &self,
        env: Env,
        id_local: String,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let deleted = delete_issued_credential_record(&store, &id_local).await?;
                serde_json::to_string(&serde_json::json!({
                    "ok": true,
                    "issuer_local_credential_id": id_local,
                    "deleted": deleted,
                }))
                .map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando remoção da issued revocable credential: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn preflight_revoke_issued_credential(
        &self,
        env: Env,
        id_local: String,
        revoke_from_window: Option<u32>,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let record = get_issued_credential_record(&store, &id_local)
                    .await?
                    .ok_or_else(|| {
                        napi::Error::from_reason(format!(
                            "Issued credential não encontrada: {}",
                            id_local
                        ))
                    })?;

                let response =
                    preflight_revoke_issued_record(&record, revoke_from_window.unwrap_or(0));
                serde_json::to_string(&response).map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando preflight de revogação: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn revoke_issued_credential_from_window(
        &self,
        env: Env,
        id_local: String,
        bloom_admin_token: String,
        revoke_from_window: u32,
        reason: Option<String>,
        requested_by: Option<String>,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                if bloom_admin_token.trim().is_empty() {
                    return Err(napi::Error::from_reason("bloom_admin_token vazio"));
                }

                let preflight_record = get_issued_credential_record(&store, &id_local)
                    .await?
                    .ok_or_else(|| {
                        napi::Error::from_reason(format!(
                            "Issued credential não encontrada: {}",
                            id_local
                        ))
                    })?;

                let preflight =
                    preflight_revoke_issued_record(&preflight_record, revoke_from_window);
                let can_revoke = preflight
                    .get("can_revoke")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if !can_revoke {
                    return Err(napi::Error::from_reason(format!(
                        "Preflight de revogação falhou: {}",
                        preflight
                            .get("errors")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!(["erro-desconhecido"]))
                    )));
                }

                let mut record = preflight_record;
                let manifest = record.manifest.clone().ok_or_else(|| {
                    napi::Error::from_reason(
                        "A credencial emitida não possui manifesto Bloom associado".to_string(),
                    )
                })?;
                let refreshed_manifest = refresh_manifest_anchor_live(&manifest).await?;
                record.manifest = Some(refreshed_manifest.clone());

                let start_index = revoke_from_window as usize;
                let keys_to_revoke = record.revocation_keys_by_window[start_index..].to_vec();
                let window_starts_to_revoke = build_window_starts(
                    record.control.start_time,
                    &record.control.unit_of_time,
                    record.control.time_window,
                    keys_to_revoke.len(),
                    start_index,
                )
                .map_err(napi::Error::from_reason)?;
                let issuer_did = record
                    .cred_def_id
                    .split(':')
                    .next()
                    .unwrap_or_default()
                    .to_string();

                let bloom_response = revoke_revocation_keys(
                    &refreshed_manifest,
                    &bloom_admin_token,
                    Some(issuer_did.as_str()),
                    Some(record.issuer_local_credential_id.as_str()),
                    &keys_to_revoke,
                    Some(&window_starts_to_revoke),
                    reason.as_deref(),
                    requested_by.as_deref(),
                )
                .await
                .map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro escrevendo revogação no serviço Bloom: {}",
                        e
                    ))
                })?;

                let now = now_ts();
                if let Ok(updated_manifest) =
                    refresh_manifest_anchor_live(&refreshed_manifest).await
                {
                    record.manifest = Some(updated_manifest);
                }
                record.status = "revoked".to_string();
                record.revoked_at = Some(now);
                record.revoked_from_window = Some(start_index as u32);
                record.updated_at = now;
                store_issued_credential_record(&store, &record).await?;

                let response = serde_json::json!({
                    "ok": true,
                    "issuer_local_credential_id": id_local,
                    "revoke_from_window": start_index,
                    "revocation_keys_written": keys_to_revoke.len(),
                    "window_starts_written": window_starts_to_revoke,
                    "bloom": bloom_response,
                    "issuer_record": record,
                    "preflight": preflight,
                });

                serde_json::to_string(&response).map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando resposta de revogação por janela: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }
}
