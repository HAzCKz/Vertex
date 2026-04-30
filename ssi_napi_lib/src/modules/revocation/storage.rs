use crate::modules::common::{napi_err, now_ts};
use crate::modules::revocation::types::{
    HolderRevocationBundle, IssuedCredentialRecord, RevocationEventRecord, RevocationSetupRecord,
};
use aries_askar::entry::{EntryTag, TagFilter};
use aries_askar::Store;
use std::sync::atomic::{AtomicU64, Ordering};

pub const REVOCATION_SETUP_CATEGORY: &str = "revocation_setup";
pub const ISSUED_CREDENTIAL_CATEGORY: &str = "issued_credential";
pub const HOLDER_REVOCATION_BUNDLE_CATEGORY: &str = "holder_revocation_bundle";
pub const REVOCATION_MANIFEST_CACHE_CATEGORY: &str = "revocation_manifest_cache";
pub const REVOCATION_EVENT_CATEGORY: &str = "revocation_event";
static REVOCATION_EVENT_COUNTER: AtomicU64 = AtomicU64::new(0);

fn revocation_setup_tags(record: &RevocationSetupRecord) -> Vec<EntryTag> {
    let mut tags = vec![
        EntryTag::Encrypted("issuer_did".to_string(), record.issuer_did.clone()),
        EntryTag::Encrypted(
            "k_vector_id".to_string(),
            record.active_k_ledger_anchor.k_vector_id.clone(),
        ),
        EntryTag::Encrypted(
            "vector_hash".to_string(),
            record.active_k_ledger_anchor.vector_hash.clone(),
        ),
        EntryTag::Encrypted("updated_at".to_string(), record.updated_at.to_string()),
    ];

    if let Some(manifest) = &record.manifest {
        if !manifest.manifest_url.trim().is_empty() {
            tags.push(EntryTag::Encrypted(
                "manifest_url".to_string(),
                manifest.manifest_url.clone(),
            ));
        }
    }

    tags
}

fn issued_record_tags(record: &IssuedCredentialRecord) -> Vec<EntryTag> {
    let mut tags = vec![
        EntryTag::Encrypted(
            "issuer_did".to_string(),
            record
                .cred_def_id
                .split(':')
                .next()
                .unwrap_or_default()
                .to_string(),
        ),
        EntryTag::Encrypted("cred_def_id".to_string(), record.cred_def_id.clone()),
        EntryTag::Encrypted("schema_id".to_string(), record.schema_id.clone()),
        EntryTag::Encrypted("status".to_string(), record.status.clone()),
        EntryTag::Encrypted("created_at".to_string(), record.created_at.to_string()),
        EntryTag::Encrypted("updated_at".to_string(), record.updated_at.to_string()),
    ];

    if let Some(holder_did_hint) = &record.holder_did_hint {
        if !holder_did_hint.trim().is_empty() {
            tags.push(EntryTag::Encrypted(
                "holder_did_hint".to_string(),
                holder_did_hint.clone(),
            ));
        }
    }

    if let Some(k_ledger_anchor) = &record.k_ledger_anchor {
        if !k_ledger_anchor.k_vector_id.trim().is_empty() {
            tags.push(EntryTag::Encrypted(
                "k_vector_id".to_string(),
                k_ledger_anchor.k_vector_id.clone(),
            ));
        }
    }

    if let Some(revoked_at) = record.revoked_at {
        tags.push(EntryTag::Encrypted(
            "revoked_at".to_string(),
            revoked_at.to_string(),
        ));
    }
    if let Some(revoked_from_window) = record.revoked_from_window {
        tags.push(EntryTag::Encrypted(
            "revoked_from_window".to_string(),
            revoked_from_window.to_string(),
        ));
    }

    tags
}

fn holder_bundle_tags(bundle: &HolderRevocationBundle) -> Vec<EntryTag> {
    let mut tags = vec![
        EntryTag::Encrypted("issuer_did".to_string(), bundle.issuer_did.clone()),
        EntryTag::Encrypted("cred_def_id".to_string(), bundle.cred_def_id.clone()),
        EntryTag::Encrypted("schema_id".to_string(), bundle.schema_id.clone()),
        EntryTag::Encrypted(
            "root_merkle_l".to_string(),
            bundle.control.root_merkle_l.clone(),
        ),
        EntryTag::Encrypted(
            "window_count".to_string(),
            bundle.control.window_count.to_string(),
        ),
        EntryTag::Encrypted("stored_at".to_string(), now_ts().to_string()),
    ];

    if let Some(credential_id) = &bundle.credential_id {
        if !credential_id.trim().is_empty() {
            tags.push(EntryTag::Encrypted(
                "credential_id".to_string(),
                credential_id.clone(),
            ));
        }
    }

    if let Some(k_ledger_anchor) = &bundle.k_ledger_anchor {
        if !k_ledger_anchor.k_vector_id.trim().is_empty() {
            tags.push(EntryTag::Encrypted(
                "k_vector_id".to_string(),
                k_ledger_anchor.k_vector_id.clone(),
            ));
        }
    }

    tags
}

pub async fn store_issued_credential_record(
    store: &Store,
    record: &IssuedCredentialRecord,
) -> napi::Result<String> {
    let mut session = store
        .session(None)
        .await
        .map_err(|e| napi_err("RevocationSessionOpenFailed", e.to_string()))?;

    let id_local = record.issuer_local_credential_id.clone();
    if session
        .fetch(ISSUED_CREDENTIAL_CATEGORY, &id_local, false)
        .await
        .map_err(|e| napi_err("RevocationFetchIssuedFailed", e.to_string()))?
        .is_some()
    {
        session
            .remove(ISSUED_CREDENTIAL_CATEGORY, &id_local)
            .await
            .map_err(|e| napi_err("RevocationRemoveIssuedFailed", e.to_string()))?;
    }

    let value = serde_json::to_vec_pretty(record)
        .map_err(|e| napi_err("RevocationSerializeIssuedFailed", e.to_string()))?;

    session
        .insert(
            ISSUED_CREDENTIAL_CATEGORY,
            &id_local,
            &value,
            Some(&issued_record_tags(record)),
            None,
        )
        .await
        .map_err(|e| napi_err("RevocationInsertIssuedFailed", e.to_string()))?;

    session
        .commit()
        .await
        .map_err(|e| napi_err("RevocationCommitIssuedFailed", e.to_string()))?;

    Ok(id_local)
}

pub async fn get_issued_credential_record(
    store: &Store,
    id_local: &str,
) -> napi::Result<Option<IssuedCredentialRecord>> {
    let mut session = store
        .session(None)
        .await
        .map_err(|e| napi_err("RevocationSessionOpenFailed", e.to_string()))?;

    let entry = session
        .fetch(ISSUED_CREDENTIAL_CATEGORY, id_local, false)
        .await
        .map_err(|e| napi_err("RevocationFetchIssuedFailed", e.to_string()))?;

    let Some(entry) = entry else {
        return Ok(None);
    };

    let parsed = serde_json::from_slice::<IssuedCredentialRecord>(&entry.value)
        .map_err(|e| napi_err("RevocationParseIssuedFailed", e.to_string()))?;
    Ok(Some(parsed))
}

pub async fn list_issued_credential_records(
    store: &Store,
    status_filter: Option<&str>,
) -> napi::Result<Vec<IssuedCredentialRecord>> {
    let mut session = store
        .session(None)
        .await
        .map_err(|e| napi_err("RevocationSessionOpenFailed", e.to_string()))?;

    let filter = status_filter.map(|status| TagFilter::is_eq("status", status));
    let entries = session
        .fetch_all(
            Some(ISSUED_CREDENTIAL_CATEGORY),
            filter,
            None,
            None,
            false,
            false,
        )
        .await
        .map_err(|e| napi_err("RevocationListIssuedFailed", e.to_string()))?;

    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let parsed = serde_json::from_slice::<IssuedCredentialRecord>(&entry.value)
            .map_err(|e| napi_err("RevocationParseIssuedFailed", e.to_string()))?;
        out.push(parsed);
    }

    Ok(out)
}

pub async fn delete_issued_credential_record(store: &Store, id_local: &str) -> napi::Result<bool> {
    let mut session = store
        .session(None)
        .await
        .map_err(|e| napi_err("RevocationSessionOpenFailed", e.to_string()))?;

    let exists = session
        .fetch(ISSUED_CREDENTIAL_CATEGORY, id_local, false)
        .await
        .map_err(|e| napi_err("RevocationFetchIssuedFailed", e.to_string()))?
        .is_some();

    if !exists {
        return Ok(false);
    }

    session
        .remove(ISSUED_CREDENTIAL_CATEGORY, id_local)
        .await
        .map_err(|e| napi_err("RevocationRemoveIssuedFailed", e.to_string()))?;

    session
        .commit()
        .await
        .map_err(|e| napi_err("RevocationCommitIssuedFailed", e.to_string()))?;

    Ok(true)
}

pub async fn store_holder_revocation_bundle(
    store: &Store,
    id_local: &str,
    bundle: &HolderRevocationBundle,
) -> napi::Result<String> {
    let mut session = store
        .session(None)
        .await
        .map_err(|e| napi_err("RevocationSessionOpenFailed", e.to_string()))?;

    if session
        .fetch(HOLDER_REVOCATION_BUNDLE_CATEGORY, id_local, false)
        .await
        .map_err(|e| napi_err("RevocationFetchBundleFailed", e.to_string()))?
        .is_some()
    {
        session
            .remove(HOLDER_REVOCATION_BUNDLE_CATEGORY, id_local)
            .await
            .map_err(|e| napi_err("RevocationRemoveBundleFailed", e.to_string()))?;
    }

    let value = serde_json::to_vec_pretty(bundle)
        .map_err(|e| napi_err("RevocationSerializeBundleFailed", e.to_string()))?;

    session
        .insert(
            HOLDER_REVOCATION_BUNDLE_CATEGORY,
            id_local,
            &value,
            Some(&holder_bundle_tags(bundle)),
            None,
        )
        .await
        .map_err(|e| napi_err("RevocationInsertBundleFailed", e.to_string()))?;

    session
        .commit()
        .await
        .map_err(|e| napi_err("RevocationCommitBundleFailed", e.to_string()))?;

    Ok(id_local.to_string())
}

pub async fn get_holder_revocation_bundle(
    store: &Store,
    id_local: &str,
) -> napi::Result<Option<HolderRevocationBundle>> {
    let mut session = store
        .session(None)
        .await
        .map_err(|e| napi_err("RevocationSessionOpenFailed", e.to_string()))?;

    let entry = session
        .fetch(HOLDER_REVOCATION_BUNDLE_CATEGORY, id_local, false)
        .await
        .map_err(|e| napi_err("RevocationFetchBundleFailed", e.to_string()))?;

    let Some(entry) = entry else {
        return Ok(None);
    };

    let parsed = serde_json::from_slice::<HolderRevocationBundle>(&entry.value)
        .map_err(|e| napi_err("RevocationParseBundleFailed", e.to_string()))?;
    Ok(Some(parsed))
}

pub async fn find_holder_revocation_bundle_by_credential_id(
    store: &Store,
    credential_id: &str,
) -> napi::Result<Option<(String, HolderRevocationBundle)>> {
    let mut session = store
        .session(None)
        .await
        .map_err(|e| napi_err("RevocationSessionOpenFailed", e.to_string()))?;

    let entries = session
        .fetch_all(
            Some(HOLDER_REVOCATION_BUNDLE_CATEGORY),
            Some(TagFilter::is_eq("credential_id", credential_id)),
            None,
            None,
            false,
            false,
        )
        .await
        .map_err(|e| napi_err("RevocationFindBundleByCredentialFailed", e.to_string()))?;

    if entries.is_empty() {
        return Ok(None);
    }

    if entries.len() > 1 {
        return Err(napi_err(
            "RevocationDuplicateBundleByCredential",
            format!(
                "Mais de um holder bundle encontrado para credential_id {}",
                credential_id
            ),
        ));
    }

    let entry = entries.into_iter().next().unwrap();
    let parsed = serde_json::from_slice::<HolderRevocationBundle>(&entry.value)
        .map_err(|e| napi_err("RevocationParseBundleFailed", e.to_string()))?;
    Ok(Some((entry.name, parsed)))
}

pub async fn store_revocation_setup_record(
    store: &Store,
    record: &RevocationSetupRecord,
) -> napi::Result<String> {
    let mut session = store
        .session(None)
        .await
        .map_err(|e| napi_err("RevocationSessionOpenFailed", e.to_string()))?;

    if session
        .fetch(REVOCATION_SETUP_CATEGORY, &record.issuer_did, false)
        .await
        .map_err(|e| napi_err("RevocationFetchSetupFailed", e.to_string()))?
        .is_some()
    {
        session
            .remove(REVOCATION_SETUP_CATEGORY, &record.issuer_did)
            .await
            .map_err(|e| napi_err("RevocationRemoveSetupFailed", e.to_string()))?;
    }

    let value = serde_json::to_vec_pretty(record)
        .map_err(|e| napi_err("RevocationSerializeSetupFailed", e.to_string()))?;

    session
        .insert(
            REVOCATION_SETUP_CATEGORY,
            &record.issuer_did,
            &value,
            Some(&revocation_setup_tags(record)),
            None,
        )
        .await
        .map_err(|e| napi_err("RevocationInsertSetupFailed", e.to_string()))?;

    session
        .commit()
        .await
        .map_err(|e| napi_err("RevocationCommitSetupFailed", e.to_string()))?;

    Ok(record.issuer_did.clone())
}

pub async fn get_revocation_setup_record(
    store: &Store,
    issuer_did: &str,
) -> napi::Result<Option<RevocationSetupRecord>> {
    let mut session = store
        .session(None)
        .await
        .map_err(|e| napi_err("RevocationSessionOpenFailed", e.to_string()))?;

    let entry = session
        .fetch(REVOCATION_SETUP_CATEGORY, issuer_did, false)
        .await
        .map_err(|e| napi_err("RevocationFetchSetupFailed", e.to_string()))?;

    let Some(entry) = entry else {
        return Ok(None);
    };

    let parsed = serde_json::from_slice::<RevocationSetupRecord>(&entry.value)
        .map_err(|e| napi_err("RevocationParseSetupFailed", e.to_string()))?;
    Ok(Some(parsed))
}

pub async fn store_revocation_event(
    store: &Store,
    record: &RevocationEventRecord,
) -> napi::Result<String> {
    let mut session = store
        .session(None)
        .await
        .map_err(|e| napi_err("RevocationSessionOpenFailed", e.to_string()))?;

    let value = serde_json::to_vec_pretty(record)
        .map_err(|e| napi_err("RevocationSerializeEventFailed", e.to_string()))?;

    let mut tags = vec![
        EntryTag::Encrypted("event_type".to_string(), record.event_type.clone()),
        EntryTag::Encrypted("created_at".to_string(), record.created_at.to_string()),
        EntryTag::Encrypted("trace_len".to_string(), record.trace_len.to_string()),
    ];
    if let Some(credential_id_local) = &record.credential_id_local {
        if !credential_id_local.trim().is_empty() {
            tags.push(EntryTag::Encrypted(
                "credential_id_local".to_string(),
                credential_id_local.clone(),
            ));
        }
    }
    if let Some(issuer_did) = &record.issuer_did {
        if !issuer_did.trim().is_empty() {
            tags.push(EntryTag::Encrypted(
                "issuer_did".to_string(),
                issuer_did.clone(),
            ));
        }
    }
    if let Some(decision) = &record.decision {
        tags.push(EntryTag::Encrypted(
            "decision".to_string(),
            serde_json::to_string(decision).unwrap_or_else(|_| "null".to_string()),
        ));
    }

    session
        .insert(
            REVOCATION_EVENT_CATEGORY,
            &record.event_id,
            &value,
            Some(&tags),
            None,
        )
        .await
        .map_err(|e| napi_err("RevocationInsertEventFailed", e.to_string()))?;

    session
        .commit()
        .await
        .map_err(|e| napi_err("RevocationCommitEventFailed", e.to_string()))?;

    Ok(record.event_id.clone())
}

pub fn make_revocation_event_id(prefix: &str) -> String {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_else(|_| now_ts() as u128);
    let counter = REVOCATION_EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{}-{}", prefix, millis, counter)
}
