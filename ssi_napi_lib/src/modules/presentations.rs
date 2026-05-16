// src/modules/presentations.rs
// use crate::modules::common::napi_err;
use crate::IndyAgent;
// Importamos o cache compartilhado do módulo de credenciais
use crate::modules::credentials::LINK_SECRET_CACHE;
use crate::modules::revocation::holder::{
    build_primary_revocation_proof_for_window, build_revocation_proof_sequence_for_window,
};
use crate::modules::revocation::storage::{
    find_holder_revocation_bundle_by_credential_id, make_revocation_event_id,
    store_revocation_event,
};
use crate::modules::revocation::types::{
    RevocationConfirmationPolicy, RevocationDecisionResult, RevocationEventRecord,
    RevocationProofPayload, RevocationProofSequence, RevocationStatus,
};
use crate::modules::revocation::verifier::{
    verify_revocation_proof_payload, verify_revocation_proof_sequence_payload,
};

use napi::{Env, Error, JsObject, Result};
use napi_derive::napi;
use std::collections::HashMap;
use std::convert::TryFrom;
// use std::sync::Arc;

// Imports Anoncreds
use anoncreds::data_types::cred_def::CredentialDefinitionId as AnonCredDefId;
// use anoncreds::data_types::cred_def::{CredentialDefinition, CredentialDefinitionId};
use anoncreds::data_types::cred_def::CredentialDefinition;
// use anoncreds::data_types::credential::Credential;
use anoncreds::data_types::schema::SchemaId as AnonSchemaId;
// use anoncreds::data_types::schema::{Schema, SchemaId};
// use anoncreds::types::{LinkSecret, PresentCredentials, Presentation, PresentationRequest};

use anoncreds::data_types::schema::Schema;
use anoncreds::types::{Presentation, PresentationRequest};

use anoncreds::verifier::verify_presentation;

use aries_askar::entry::EntryTag;
use std::time::{SystemTime, UNIX_EPOCH};

// Funções auxiliares:
// -------------------------------
// Helpers: Spec de UI -> RequestedCredentials (AnonCreds)
// -------------------------------

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

const PRESENTATION_REVOCATION_CATEGORY: &str = "presentation_revocation";
const REVOCATION_CONTROL_ATTRS: [&str; 5] = [
    "seed",
    "start_time",
    "unit_of_time",
    "time_window",
    "root_merkle_L",
];

#[derive(Debug, Serialize)]
struct ExtractedRevocationControlsOut {
    seed: String,
    start_time: String,
    unit_of_time: String,
    time_window: String,
    #[serde(rename = "root_merkle_L")]
    root_merkle_l: String,
}

#[derive(Debug, Serialize)]
struct ExtractedCredentialHintOut {
    #[serde(skip_serializing_if = "Option::is_none")]
    schema_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cred_def_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct ExtractedRevocableCredentialOut {
    slot: String,
    sub_proof_index: usize,
    credential_hint: ExtractedCredentialHintOut,
    controls: ExtractedRevocationControlsOut,
    revealed_attr_refs: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct MixedRevocationProofIn {
    #[serde(default)]
    credential_id_local: Option<String>,
    #[serde(default)]
    cred_def_id: Option<String>,
    proof: RevocationProofPayload,
}

#[derive(Debug, Deserialize)]
struct MixedRevocationProofSequenceIn {
    #[serde(default)]
    credential_id_local: Option<String>,
    #[serde(default)]
    cred_def_id: Option<String>,
    proof_sequence: RevocationProofSequence,
}

#[derive(Debug, Deserialize)]
struct MixedExpectedRootIn {
    #[serde(default)]
    credential_id_local: Option<String>,
    #[serde(default)]
    cred_def_id: Option<String>,
    #[serde(rename = "root_merkle_L")]
    root_merkle_l: String,
}

#[derive(Debug, Serialize)]
struct MixedCredentialStatusOut {
    sub_proof_index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_id_local: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cred_def_id: Option<String>,
    revocable: bool,
    proof_verified: Option<bool>,
    revoked: bool,
    details: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation_status: Option<RevocationStatus>,
}

#[derive(Debug, Deserialize)]
struct RequestedRevocationWindowIn {
    credential_id_local: String,
    window_index: u32,
}

#[derive(Debug, Deserialize)]
struct RequestedRevocationSequenceIn {
    credential_id_local: String,
    primary_window_index: u32,
    #[serde(default)]
    additional_window_count: Option<u32>,
}

#[derive(Debug, Serialize)]
struct PresentationPackageUsedCredentialOut {
    credential_id_local: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cred_def_id: Option<String>,
    revocable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_id_local: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    window_index: Option<u32>,
}

#[derive(Debug, Serialize)]
struct PresentationPackageRevocationProofOut {
    credential_id_local: String,
    bundle_id_local: String,
    window_index: u32,
    proof: RevocationProofPayload,
}

#[derive(Debug, Serialize)]
struct PresentationPackageRevocationProofSequenceOut {
    credential_id_local: String,
    bundle_id_local: String,
    primary_window_index: u32,
    additional_window_count: u32,
    proof_sequence: RevocationProofSequence,
}

#[derive(Debug, Serialize)]
struct MixedCredentialStatusV2Out {
    sub_proof_index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_id_local: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cred_def_id: Option<String>,
    revocable: bool,
    proof_verified: Option<bool>,
    revoked: bool,
    accepted: bool,
    requires_more_windows: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_required_window_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issued_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_window_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_window_start: Option<i64>,
    details: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation_status: Option<RevocationDecisionResult>,
}

fn parse_optional_i64(raw: &str) -> Option<i64> {
    raw.trim().parse::<i64>().ok()
}

fn revoked_window_start_from_status(status: &RevocationDecisionResult) -> Option<i64> {
    if !status.revoked {
        return None;
    }

    status
        .trace
        .iter()
        .find(|item| item.window_index == status.primary_window_index)
        .map(|item| item.window_start)
}

fn canonical_revocation_control_name(name: &str) -> Option<&'static str> {
    match name.trim() {
        "seed" => Some("seed"),
        "start_time" => Some("start_time"),
        "unit_of_time" => Some("unit_of_time"),
        "time_window" => Some("time_window"),
        "root_merkle_L" | "root_merkle_l" => Some("root_merkle_L"),
        _ => None,
    }
}

fn json_stringish(value: &JsonValue) -> Option<String> {
    match value {
        JsonValue::String(s) => Some(s.clone()),
        JsonValue::Number(n) => Some(n.to_string()),
        JsonValue::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn resolve_requested_attr_name(presentation_request: Option<&JsonValue>, referent: &str) -> String {
    presentation_request
        .and_then(|request| request.get("requested_attributes"))
        .and_then(|value| value.as_object())
        .and_then(|attrs| attrs.get(referent))
        .and_then(|attr_spec| {
            attr_spec
                .get("name")
                .and_then(|value| value.as_str())
                .map(|value| value.to_string())
                .or_else(|| {
                    attr_spec
                        .get("names")
                        .and_then(|value| value.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|value| value.as_str())
                        .map(|value| value.to_string())
                })
        })
        .unwrap_or_else(|| referent.to_string())
}

fn collect_single_revealed_attr(
    grouped: &mut BTreeMap<usize, BTreeMap<String, String>>,
    grouped_refs: &mut BTreeMap<usize, BTreeMap<String, String>>,
    presentation_request: Option<&JsonValue>,
    referent: &str,
    attr_payload: &serde_json::Map<String, JsonValue>,
) {
    let sub_proof_index = attr_payload
        .get("sub_proof_index")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize);
    let raw = attr_payload.get("raw").and_then(json_stringish);
    if let (Some(sub_proof_index), Some(raw)) = (sub_proof_index, raw) {
        let attr_name = resolve_requested_attr_name(presentation_request, referent);
        if let Some(canonical_name) = canonical_revocation_control_name(&attr_name) {
            grouped
                .entry(sub_proof_index)
                .or_default()
                .insert(canonical_name.to_string(), raw);
            grouped_refs
                .entry(sub_proof_index)
                .or_default()
                .insert(canonical_name.to_string(), referent.to_string());
        }
    }
}

fn collect_grouped_revealed_attrs(
    grouped: &mut BTreeMap<usize, BTreeMap<String, String>>,
    grouped_refs: &mut BTreeMap<usize, BTreeMap<String, String>>,
    group_referent: &str,
    group_payload: &serde_json::Map<String, JsonValue>,
) {
    let sub_proof_index = group_payload
        .get("sub_proof_index")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize);
    let values = group_payload.get("values").and_then(|v| v.as_object());

    if let (Some(sub_proof_index), Some(values)) = (sub_proof_index, values) {
        for (attr_name, attr_payload) in values {
            let raw = attr_payload
                .as_object()
                .and_then(|obj| obj.get("raw"))
                .and_then(json_stringish);
            if let (Some(canonical_name), Some(raw)) =
                (canonical_revocation_control_name(attr_name), raw)
            {
                grouped
                    .entry(sub_proof_index)
                    .or_default()
                    .insert(canonical_name.to_string(), raw);
                grouped_refs.entry(sub_proof_index).or_default().insert(
                    canonical_name.to_string(),
                    format!("{}.{}", group_referent, attr_name),
                );
            }
        }
    }
}

fn extract_revocation_controls_from_presentation_value(
    presentation: &JsonValue,
    presentation_request: Option<&JsonValue>,
) -> std::result::Result<Vec<ExtractedRevocableCredentialOut>, napi::Error> {
    let requested_proof = presentation
        .get("requested_proof")
        .and_then(|v| v.as_object())
        .ok_or_else(|| napi::Error::from_reason("presentation_json sem requested_proof"))?;

    let mut grouped_controls: BTreeMap<usize, BTreeMap<String, String>> = BTreeMap::new();
    let mut grouped_refs: BTreeMap<usize, BTreeMap<String, String>> = BTreeMap::new();

    if let Some(revealed_attrs) = requested_proof
        .get("revealed_attrs")
        .and_then(|v| v.as_object())
    {
        for (referent, attr_payload) in revealed_attrs {
            if let Some(attr_obj) = attr_payload.as_object() {
                collect_single_revealed_attr(
                    &mut grouped_controls,
                    &mut grouped_refs,
                    presentation_request,
                    referent,
                    attr_obj,
                );
            }
        }
    }

    if let Some(revealed_attr_groups) = requested_proof
        .get("revealed_attr_groups")
        .and_then(|v| v.as_object())
    {
        for (group_referent, group_payload) in revealed_attr_groups {
            if let Some(group_obj) = group_payload.as_object() {
                collect_grouped_revealed_attrs(
                    &mut grouped_controls,
                    &mut grouped_refs,
                    group_referent,
                    group_obj,
                );
            }
        }
    }

    let identifiers = presentation
        .get("identifiers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut revocable_credentials = Vec::new();
    for (sub_proof_index, controls) in grouped_controls {
        let has_all_controls = REVOCATION_CONTROL_ATTRS
            .iter()
            .all(|required| controls.contains_key(*required));
        if !has_all_controls {
            continue;
        }

        let identifier = identifiers
            .get(sub_proof_index)
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();

        let credential_hint = ExtractedCredentialHintOut {
            schema_id: identifier
                .get("schema_id")
                .or_else(|| identifier.get("schemaId"))
                .and_then(json_stringish),
            cred_def_id: identifier
                .get("cred_def_id")
                .or_else(|| identifier.get("credDefId"))
                .and_then(json_stringish),
            issuer_id: identifier
                .get("issuer_id")
                .or_else(|| identifier.get("issuerId"))
                .and_then(json_stringish),
        };

        let slot = grouped_refs
            .get(&sub_proof_index)
            .and_then(|refs| refs.get("root_merkle_L"))
            .cloned()
            .unwrap_or_else(|| format!("sub_proof_index:{}", sub_proof_index));

        revocable_credentials.push(ExtractedRevocableCredentialOut {
            slot,
            sub_proof_index,
            credential_hint,
            controls: ExtractedRevocationControlsOut {
                seed: controls.get("seed").cloned().unwrap_or_default(),
                start_time: controls.get("start_time").cloned().unwrap_or_default(),
                unit_of_time: controls.get("unit_of_time").cloned().unwrap_or_default(),
                time_window: controls.get("time_window").cloned().unwrap_or_default(),
                root_merkle_l: controls.get("root_merkle_L").cloned().unwrap_or_default(),
            },
            revealed_attr_refs: grouped_refs
                .get(&sub_proof_index)
                .cloned()
                .unwrap_or_default(),
        });
    }

    Ok(revocable_credentials)
}

fn extract_revocation_controls_from_presentation_json(
    presentation_json: &str,
) -> std::result::Result<String, napi::Error> {
    let presentation: JsonValue = serde_json::from_str(presentation_json)
        .map_err(|e| napi::Error::from_reason(format!("presentation_json inválido: {}", e)))?;

    let revocable_credentials =
        extract_revocation_controls_from_presentation_value(&presentation, None)?;

    let response = serde_json::json!({
        "ok": true,
        "revocable_credentials": revocable_credentials,
    });

    serde_json::to_string(&response).map_err(|e| {
        napi::Error::from_reason(format!("Erro serializando controles extraídos: {}", e))
    })
}

fn parse_verify_schemas(
    schemas_json: &str,
) -> std::result::Result<HashMap<AnonSchemaId, Schema>, napi::Error> {
    let schemas_raw: HashMap<String, serde_json::Value> =
        serde_json::from_str(schemas_json).map_err(|_| napi::Error::from_reason("Erro Schemas"))?;

    let mut schemas = HashMap::new();
    for (k, v) in schemas_raw {
        let id_json = serde_json::Value::String(k.clone());
        let id: AnonSchemaId = serde_json::from_value(id_json)
            .map_err(|_| napi::Error::from_reason("Bad SchemaId"))?;

        let mut final_val = v.clone();
        if let Some(res) = final_val.get("result") {
            if let Some(data) = res.get("data") {
                final_val = data.clone();
            }
        } else if let Some(data) = final_val.get("data") {
            final_val = data.clone();
        }

        if let Some(obj) = final_val.as_object_mut() {
            if !obj.contains_key("issuerId") {
                let parts: Vec<&str> = k.split(':').collect();
                if !parts.is_empty() {
                    obj.insert("issuerId".to_string(), serde_json::json!(parts[0]));
                }
            }
            if !obj.contains_key("attrNames") && obj.contains_key("attr_names") {
                let attrs = obj.get("attr_names").unwrap().clone();
                obj.insert("attrNames".to_string(), attrs);
            }
        }
        let schema: Schema = serde_json::from_value(final_val)
            .map_err(|e| napi::Error::from_reason(format!("Schema {} invalido: {}", k, e)))?;
        schemas.insert(id, schema);
    }

    Ok(schemas)
}

fn parse_verify_cred_defs(
    cred_defs_json: &str,
) -> std::result::Result<HashMap<AnonCredDefId, CredentialDefinition>, napi::Error> {
    let cred_defs_raw: HashMap<String, serde_json::Value> = serde_json::from_str(cred_defs_json)
        .map_err(|_| napi::Error::from_reason("Erro CredDefs"))?;
    let mut cred_defs = HashMap::new();
    for (k, v) in cred_defs_raw {
        let id_json = serde_json::Value::String(k.clone());
        let id: AnonCredDefId = serde_json::from_value(id_json)
            .map_err(|_| napi::Error::from_reason("Bad CredDefId"))?;

        let mut final_val = v.clone();
        if let Some(res) = final_val.get("result") {
            if let Some(data) = res.get("data") {
                final_val = data.clone();
            }
        } else if let Some(data) = final_val.get("data") {
            final_val = data.clone();
        }

        let needs_wrapping = if let Some(obj) = final_val.as_object() {
            !obj.contains_key("value") && obj.contains_key("primary")
        } else {
            false
        };

        if needs_wrapping {
            let content = final_val.clone();
            final_val = serde_json::json!({ "value": content });
        }

        if let Some(obj) = final_val.as_object_mut() {
            if !obj.contains_key("schemaId") {
                if let Some(sid) = obj.get("schema_id").cloned() {
                    obj.insert("schemaId".to_string(), sid);
                } else {
                    let parts: Vec<&str> = k.split(':').collect();
                    if parts.len() >= 4 {
                        obj.insert("schemaId".to_string(), serde_json::json!(parts[3]));
                    }
                }
            }
            if !obj.contains_key("issuerId") {
                let parts: Vec<&str> = k.split(':').collect();
                if !parts.is_empty() {
                    obj.insert("issuerId".to_string(), serde_json::json!(parts[0]));
                }
            }
            if !obj.contains_key("type") {
                obj.insert("type".to_string(), serde_json::json!("CL"));
            }
            if !obj.contains_key("ver") {
                obj.insert("ver".to_string(), serde_json::json!("1.0"));
            }
            if !obj.contains_key("tag") {
                obj.insert("tag".to_string(), serde_json::json!("TAG_PROOF"));
            }
        }

        let cd: CredentialDefinition = serde_json::from_value(final_val)
            .map_err(|e| napi::Error::from_reason(format!("CredDef invalida: {}", e)))?;
        cred_defs.insert(id, cd);
    }
    Ok(cred_defs)
}

fn collect_requested_credential_ids(
    requested_credentials_json: &str,
) -> std::result::Result<Vec<String>, napi::Error> {
    let req_creds_input: serde_json::Value = serde_json::from_str(requested_credentials_json)
        .map_err(|_| napi::Error::from_reason("Erro RequestedCredentials Input"))?;

    let mut ordered_ids = Vec::new();
    let mut seen = std::collections::HashSet::new();

    if let Some(req_attrs) = req_creds_input
        .get("requested_attributes")
        .and_then(|v| v.as_object())
    {
        for info in req_attrs.values() {
            if let Some(cred_id) = info.get("cred_id").and_then(|v| v.as_str()) {
                if seen.insert(cred_id.to_string()) {
                    ordered_ids.push(cred_id.to_string());
                }
            }
        }
    }

    if let Some(req_preds) = req_creds_input
        .get("requested_predicates")
        .and_then(|v| v.as_object())
    {
        for info in req_preds.values() {
            if let Some(cred_id) = info.get("cred_id").and_then(|v| v.as_str()) {
                if seen.insert(cred_id.to_string()) {
                    ordered_ids.push(cred_id.to_string());
                }
            }
        }
    }

    Ok(ordered_ids)
}

async fn create_presentation_json_internal(
    store: aries_askar::Store,
    presentation_request_json: String,
    requested_credentials_json: String,
    schemas_json: String,
    cred_defs_json: String,
) -> std::result::Result<String, napi::Error> {
    use anoncreds::data_types::cred_def::{CredentialDefinition, CredentialDefinitionId};
    use anoncreds::data_types::credential::Credential;
    use anoncreds::data_types::schema::{Schema, SchemaId};
    use anoncreds::types::{LinkSecret, PresentCredentials, PresentationRequest};
    use std::collections::HashMap;

    let mut session = store
        .session(None)
        .await
        .map_err(|e| napi::Error::from_reason(format!("Erro sessão: {}", e)))?;

    let link_secret = {
        let cached_ls = { LINK_SECRET_CACHE.lock().unwrap().clone() };
        if let Some(ls) = cached_ls {
            ls
        } else {
            let entry = session
                .fetch("link_secret", "default", false)
                .await
                .map_err(|e| napi::Error::from_reason(format!("Erro DB LS: {}", e)))?
                .ok_or_else(|| napi::Error::from_reason("Link Secret 'default' não encontrado"))?;
            let seed_str = String::from_utf8(entry.value.to_vec()).unwrap_or_default();
            let ls_obj = LinkSecret::try_from(seed_str.as_str())
                .map_err(|e| napi::Error::from_reason(format!("Erro LS math: {:?}", e)))?;
            let arc_ls = std::sync::Arc::new(ls_obj);
            {
                *LINK_SECRET_CACHE.lock().unwrap() = Some(arc_ls.clone());
            }
            arc_ls
        }
    };

    let request: PresentationRequest = serde_json::from_str(&presentation_request_json)
        .map_err(|e| napi::Error::from_reason(format!("Erro Request JSON: {}", e)))?;

    let schemas_raw: HashMap<String, serde_json::Value> = serde_json::from_str(&schemas_json)
        .map_err(|e| napi::Error::from_reason(format!("Erro JSON Schemas: {}", e)))?;

    let mut schemas: HashMap<SchemaId, Schema> = HashMap::new();
    for (k, v) in schemas_raw {
        let id = SchemaId::new(k.clone())
            .map_err(|_| napi::Error::from_reason(format!("SchemaId inválido: {}", k)))?;

        let mut target = &v;
        if let Some(res) = v.get("result") {
            if let Some(data) = res.get("data") {
                target = data;
            } else {
                target = res;
            }
        }
        let parsed_inner: serde_json::Value;
        if target.is_string() {
            let s = target.as_str().unwrap();
            parsed_inner = serde_json::from_str(s).unwrap_or(serde_json::Value::Null);
            target = &parsed_inner;
        }
        let source = target
            .as_object()
            .ok_or_else(|| napi::Error::from_reason("Schema invalido"))?;

        let mut clean = serde_json::Map::new();
        if let Some(x) = source.get("name") {
            clean.insert("name".to_string(), x.clone());
        }
        if let Some(x) = source.get("version") {
            clean.insert("version".to_string(), x.clone());
        }

        let attrs = source.get("attrNames").or_else(|| source.get("attr_names"));
        if let Some(x) = attrs {
            clean.insert("attrNames".to_string(), x.clone());
        }

        let derived_issuer = k.split(':').next().unwrap_or("unknown");
        clean.insert("issuerId".to_string(), serde_json::json!(derived_issuer));

        if let Some(x) = source.get("id") {
            clean.insert("id".to_string(), x.clone());
        }
        if let Some(x) = source.get("ver") {
            clean.insert("ver".to_string(), x.clone());
        }

        let schema_struct: Schema = serde_json::from_value(serde_json::Value::Object(clean))
            .map_err(|e| napi::Error::from_reason(format!("Erro Struct Schema {}: {}", k, e)))?;

        schemas.insert(id, schema_struct);
    }

    let cred_defs_raw: HashMap<String, serde_json::Value> =
        serde_json::from_str(&cred_defs_json)
            .map_err(|e| napi::Error::from_reason(format!("Erro JSON CredDefs: {}", e)))?;

    let mut cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition> = HashMap::new();
    for (k, v) in cred_defs_raw {
        let id = CredentialDefinitionId::new(k.clone())
            .map_err(|_| napi::Error::from_reason(format!("CredDefId inválido: {}", k)))?;

        let mut target = &v;
        if let Some(res) = v.get("result") {
            if let Some(data) = res.get("data") {
                target = data;
            } else {
                target = res;
            }
        }
        let parsed_inner: serde_json::Value;
        if target.is_string() {
            let s = target.as_str().unwrap();
            parsed_inner = serde_json::from_str(s).unwrap_or(serde_json::Value::Null);
            target = &parsed_inner;
        }
        let source = target
            .as_object()
            .ok_or_else(|| napi::Error::from_reason(format!("CredDef {} invalida", k)))?;

        let mut clean = serde_json::Map::new();
        clean.insert("id".to_string(), serde_json::json!(k));

        let derived_issuer = k.split(':').next().unwrap_or("unknown");
        clean.insert("issuerId".to_string(), serde_json::json!(derived_issuer));

        let derived_schema_id = k.split(':').nth(3).unwrap_or("1");
        let sid = source
            .get("schemaId")
            .or_else(|| source.get("schema_id"))
            .cloned()
            .unwrap_or(serde_json::json!(derived_schema_id));
        clean.insert("schemaId".to_string(), sid);

        clean.insert(
            "type".to_string(),
            source
                .get("type")
                .cloned()
                .unwrap_or(serde_json::json!("CL")),
        );
        clean.insert(
            "tag".to_string(),
            source
                .get("tag")
                .cloned()
                .unwrap_or(serde_json::json!("TAG_PROOF")),
        );
        clean.insert(
            "ver".to_string(),
            source
                .get("ver")
                .cloned()
                .unwrap_or(serde_json::json!("1.0")),
        );

        if source.contains_key("primary") && !source.contains_key("value") {
            let mut val_map = serde_json::Map::new();
            val_map.insert(
                "primary".to_string(),
                source.get("primary").unwrap().clone(),
            );
            if let Some(rev) = source.get("revocation") {
                val_map.insert("revocation".to_string(), rev.clone());
            }
            clean.insert("value".to_string(), serde_json::Value::Object(val_map));
        } else if let Some(val) = source.get("value") {
            clean.insert("value".to_string(), val.clone());
        } else {
            return Err(napi::Error::from_reason(format!(
                "CredDef {} sem chaves",
                k
            )));
        }

        let cd_struct: CredentialDefinition =
            serde_json::from_value(serde_json::Value::Object(clean)).map_err(|e| {
                napi::Error::from_reason(format!("Erro Struct CredDef {}: {}", k, e))
            })?;

        cred_defs.insert(id, cd_struct);
    }

    let req_creds_input: serde_json::Value = serde_json::from_str(&requested_credentials_json)
        .map_err(|_| napi::Error::from_reason("Erro RequestedCredentials Input"))?;

    struct CredentialAction {
        referent: String,
        is_predicate: bool,
        revealed: bool,
        #[allow(dead_code)]
        timestamp: Option<u64>,
    }
    let mut cred_actions: HashMap<String, Vec<CredentialAction>> = HashMap::new();

    if let Some(req_attrs) = req_creds_input
        .get("requested_attributes")
        .and_then(|v| v.as_object())
    {
        for (referent, info) in req_attrs {
            let cred_id = info.get("cred_id").unwrap().as_str().unwrap().to_string();
            let revealed = info.get("revealed").unwrap().as_bool().unwrap_or(true);
            let timestamp = info.get("timestamp").and_then(|t| t.as_u64());
            cred_actions
                .entry(cred_id)
                .or_default()
                .push(CredentialAction {
                    referent: referent.clone(),
                    is_predicate: false,
                    revealed,
                    timestamp,
                });
        }
    }
    if let Some(req_preds) = req_creds_input
        .get("requested_predicates")
        .and_then(|v| v.as_object())
    {
        for (referent, info) in req_preds {
            let cred_id = info.get("cred_id").unwrap().as_str().unwrap().to_string();
            let timestamp = info.get("timestamp").and_then(|t| t.as_u64());
            cred_actions
                .entry(cred_id)
                .or_default()
                .push(CredentialAction {
                    referent: referent.clone(),
                    is_predicate: true,
                    revealed: false,
                    timestamp,
                });
        }
    }

    let mut credential_keeper: HashMap<String, Credential> = HashMap::new();
    for cred_id in cred_actions.keys() {
        let cred_entry = session
            .fetch("credential", cred_id, false)
            .await
            .map_err(|e| napi::Error::from_reason(format!("Erro DB fetch {}: {}", cred_id, e)))?
            .ok_or_else(|| napi::Error::from_reason(format!("Cred {} nao achada", cred_id)))?;

        let cred_str = String::from_utf8(cred_entry.value.to_vec()).unwrap_or_default();
        let cred_json: serde_json::Value = serde_json::from_str(&cred_str).unwrap();
        let actual_cred = cred_json.get("credential").unwrap_or(&cred_json).clone();

        let credential: Credential = serde_json::from_value(actual_cred)
            .map_err(|e| napi::Error::from_reason(format!("Erro parse Cred {}: {}", cred_id, e)))?;

        credential_keeper.insert(cred_id.clone(), credential);
    }

    let mut present_credentials = PresentCredentials::default();
    for (cred_id, actions) in cred_actions {
        let credential_ref = credential_keeper
            .get(&cred_id)
            .ok_or_else(|| napi::Error::from_reason("Erro interno keeper"))?;

        let mut cred_builder = present_credentials.add_credential(credential_ref, None, None);

        for action in actions {
            if action.is_predicate {
                cred_builder.add_requested_predicate(&action.referent);
            } else {
                cred_builder.add_requested_attribute(&action.referent, action.revealed);
            }
        }
    }

    let presentation = anoncreds::prover::create_presentation(
        &request,
        present_credentials,
        Some(HashMap::new()),
        &link_secret,
        &schemas,
        &cred_defs,
    )
    .map_err(|e| napi::Error::from_reason(format!("Erro MATEMÁTICO create_presentation: {}", e)))?;

    serde_json::to_string(&presentation)
        .map_err(|e| napi::Error::from_reason(format!("Erro serializando apresentação: {}", e)))
}

fn verify_presentation_json_internal(
    presentation_request_json: &str,
    presentation_json: &str,
    schemas_json: &str,
    cred_defs_json: &str,
) -> std::result::Result<bool, napi::Error> {
    let request: PresentationRequest = serde_json::from_str(presentation_request_json)
        .map_err(|e| napi::Error::from_reason(format!("Erro Request: {}", e)))?;

    let presentation: Presentation = serde_json::from_str(presentation_json)
        .map_err(|e| napi::Error::from_reason(format!("Erro Presentation: {}", e)))?;

    let schemas = parse_verify_schemas(schemas_json)?;
    let cred_defs = parse_verify_cred_defs(cred_defs_json)?;

    verify_presentation(
        &presentation,
        &request,
        &schemas,
        &cred_defs,
        None,
        None,
        None,
    )
    .map_err(|e| napi::Error::from_reason(format!("Erro verificação: {}", e)))
}

// -------------------------------
// Spec UI-friendly
// -------------------------------
#[derive(Debug, Deserialize)]
struct RequestedCredsSpecV1 {
    #[serde(default)]
    selection: Vec<RequestedCredSelectionItemV1>,

    #[serde(default)]
    self_attested: std::collections::HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct RequestedCredSelectionItemV1 {
    cred_id: String,

    #[serde(default)]
    attributes: Vec<RequestedAttrPickV1>,

    #[serde(default)]
    predicates: Vec<RequestedPredPickV1>,

    #[serde(default)]
    timestamp: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RequestedAttrPickV1 {
    referent: String,
    #[serde(default = "default_true")]
    revealed: bool,
}

#[derive(Debug, Deserialize)]
struct RequestedPredPickV1 {
    referent: String,
}

fn default_true() -> bool {
    true
}

// -------------------------------
// Saída no formato que seu core já consome
// -------------------------------
#[derive(Debug, Serialize)]
struct RequestedCredentialsJsonOut {
    requested_attributes: std::collections::HashMap<String, RequestedAttrOut>,
    requested_predicates: std::collections::HashMap<String, RequestedPredOut>,
    self_attested_attributes: std::collections::HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct RequestedAttrOut {
    cred_id: String,
    revealed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<u64>,
}

#[derive(Debug, Serialize)]
struct RequestedPredOut {
    cred_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredPresentationRecordV1 {
    #[serde(default)]
    presentation: JsonValue,

    #[serde(skip_serializing_if = "Option::is_none")]
    presentation_request: Option<JsonValue>,

    #[serde(skip_serializing_if = "Option::is_none")]
    meta: Option<JsonValue>,
}

use std::collections::BTreeMap;

#[derive(Debug, Serialize, Deserialize)]
struct PresentationPackageV1 {
    #[serde(rename = "type")]
    pkg_type: String,
    version: u32,
    id_local: String,
    stored_at_ms: i64,
    record: StoredPresentationRecordV1,

    #[serde(default)]
    tags: BTreeMap<String, String>,
}

fn extract_revocation_sequences_from_meta(meta: &mut Option<JsonValue>) -> Option<JsonValue> {
    let obj = meta.as_mut()?.as_object_mut()?;
    obj.remove("revocation_proof_sequences")
}

fn attach_revocation_sequences_to_meta(meta: &mut Option<JsonValue>, seqs: Option<JsonValue>) {
    let Some(seqs_val) = seqs else {
        return;
    };
    if meta.is_none() {
        *meta = Some(serde_json::json!({}));
    }
    if let Some(obj) = meta.as_mut().and_then(|v| v.as_object_mut()) {
        obj.insert("revocation_proof_sequences".to_string(), seqs_val);
    }
}

// -------------------------------
// Validação via JSON (compatível com qualquer versão do anoncreds)
// -------------------------------
fn validate_selection_against_pres_req_json(
    pres_req_json: &JsonValue,
    spec: &RequestedCredsSpecV1,
) -> std::result::Result<(), napi::Error> {
    let req_attrs = pres_req_json
        .get("requested_attributes")
        .and_then(|v| v.as_object())
        .ok_or_else(|| napi::Error::from_reason("presentationRequest sem requested_attributes"))?;

    let req_preds = pres_req_json
        .get("requested_predicates")
        .and_then(|v| v.as_object())
        .ok_or_else(|| napi::Error::from_reason("presentationRequest sem requested_predicates"))?;

    for item in &spec.selection {
        for a in &item.attributes {
            if !req_attrs.contains_key(&a.referent) {
                return Err(napi::Error::from_reason(format!(
                    "selection.attributes.referent '{}' não existe em presentationRequest.requested_attributes",
                    a.referent
                )));
            }
        }
        for p in &item.predicates {
            if !req_preds.contains_key(&p.referent) {
                return Err(napi::Error::from_reason(format!(
                    "selection.predicates.referent '{}' não existe em presentationRequest.requested_predicates",
                    p.referent
                )));
            }
        }
    }

    Ok(())
}

// -------------------------------
// Builder: spec -> requested_credentials_json
// -------------------------------
fn build_requested_credentials_from_spec(
    spec: RequestedCredsSpecV1,
) -> std::result::Result<String, napi::Error> {
    let mut out = RequestedCredentialsJsonOut {
        requested_attributes: std::collections::HashMap::new(),
        requested_predicates: std::collections::HashMap::new(),
        self_attested_attributes: spec.self_attested,
    };

    for item in spec.selection {
        for a in item.attributes {
            out.requested_attributes.insert(
                a.referent,
                RequestedAttrOut {
                    cred_id: item.cred_id.clone(),
                    revealed: a.revealed,
                    timestamp: item.timestamp,
                },
            );
        }

        for p in item.predicates {
            out.requested_predicates.insert(
                p.referent,
                RequestedPredOut {
                    cred_id: item.cred_id.clone(),
                    timestamp: item.timestamp,
                },
            );
        }
    }

    serde_json::to_string(&out).map_err(|e| {
        napi::Error::from_reason(format!("Erro serializar requested_credentials: {}", e))
    })
}

fn ensure_legacy_revocation_proof_uses_validity_window(
    proof: &RevocationProofPayload,
) -> std::result::Result<(), napi::Error> {
    let layout = crate::modules::revocation::windows::window_layout_from_control(&proof.control)
        .map_err(|e| {
            napi::Error::from_reason(format!(
                "Erro lendo layout de janelas da prova complementar: {}",
                e
            ))
        })?;
    if proof.window_index > layout.last_valid_window_index {
        return Err(napi::Error::from_reason(format!(
            "window_index {} é janela exclusiva de confirmação; last_valid_window_index={}",
            proof.window_index, layout.last_valid_window_index
        )));
    }
    Ok(())
}

// =====================================================================================================
#[napi]
impl IndyAgent {
    // =========================================================================
    //  6. HOLDER: GERAR APRESENTAÇÃO (FINAL)
    // =========================================================================
    // =========================================================================
    //  PROVA: CRIAR APRESENTAÇÃO (CORRIGIDO: LIFETIME KEEPER)
    // =========================================================================
    #[napi]
    pub fn create_presentation(
        &self,
        env: Env,
        presentation_request_json: String,
        requested_credentials_json: String,
        schemas_json: String,
        cred_defs_json: String,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                create_presentation_json_internal(
                    store,
                    presentation_request_json,
                    requested_credentials_json,
                    schemas_json,
                    cred_defs_json,
                )
                .await
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn create_presentation_package_with_revocation(
        &self,
        env: Env,
        presentation_request_json: String,
        requested_credentials_json: String,
        schemas_json: String,
        cred_defs_json: String,
        revocation_windows_json: Option<String>,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let presentation_json = create_presentation_json_internal(
                    store.clone(),
                    presentation_request_json,
                    requested_credentials_json.clone(),
                    schemas_json,
                    cred_defs_json,
                )
                .await?;

                let requested_windows: Vec<RequestedRevocationWindowIn> = match revocation_windows_json {
                    Some(raw) if !raw.trim().is_empty() => serde_json::from_str(&raw).map_err(|e| {
                        napi::Error::from_reason(format!("revocation_windows_json inválido: {}", e))
                    })?,
                    _ => Vec::new(),
                };

                let mut requested_window_map = HashMap::new();
                for item in requested_windows {
                    requested_window_map.insert(item.credential_id_local, item.window_index);
                }

                let used_credential_ids =
                    collect_requested_credential_ids(&requested_credentials_json)?;
                let mut used_credentials = Vec::new();
                let mut revocation_proofs = Vec::new();

                for credential_id_local in used_credential_ids {
                    if let Some((bundle_id_local, bundle)) =
                        find_holder_revocation_bundle_by_credential_id(&store, &credential_id_local)
                            .await?
                    {
                        let window_index = requested_window_map.get(&credential_id_local).copied().ok_or_else(|| {
                            napi::Error::from_reason(format!(
                                "window_index explícito é obrigatório para a credencial revogável {}",
                                credential_id_local
                            ))
                        })?;
                        let proof = build_primary_revocation_proof_for_window(
                            &credential_id_local,
                            &bundle,
                            window_index,
                        )
                        .map_err(|e| {
                            napi::Error::from_reason(format!(
                                "Erro montando prova de revogação para {}: {}",
                                credential_id_local, e
                            ))
                        })?;

                        revocation_proofs.push(PresentationPackageRevocationProofOut {
                            credential_id_local: credential_id_local.clone(),
                            bundle_id_local: bundle_id_local.clone(),
                            window_index,
                            proof,
                        });
                        used_credentials.push(PresentationPackageUsedCredentialOut {
                            credential_id_local,
                            cred_def_id: Some(bundle.cred_def_id.clone()),
                            revocable: true,
                            bundle_id_local: Some(bundle_id_local),
                            window_index: Some(window_index),
                        });
                    } else {
                        used_credentials.push(PresentationPackageUsedCredentialOut {
                            credential_id_local,
                            cred_def_id: None,
                            revocable: false,
                            bundle_id_local: None,
                            window_index: None,
                        });
                    }
                }

                let revocable_credentials_count =
                    used_credentials.iter().filter(|item| item.revocable).count();

                let response = serde_json::json!({
                    "ok": true,
                    "presentation_json": presentation_json,
                    "used_credentials": used_credentials,
                    "revocation_proofs": revocation_proofs,
                    "revocable_credentials_count": revocable_credentials_count,
                });

                serde_json::to_string(&response).map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando presentation package com revogação: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn create_presentation_package_with_revocation_v2(
        &self,
        env: Env,
        presentation_request_json: String,
        requested_credentials_json: String,
        schemas_json: String,
        cred_defs_json: String,
        revocation_sequences_json: Option<String>,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let presentation_json = create_presentation_json_internal(
                    store.clone(),
                    presentation_request_json,
                    requested_credentials_json.clone(),
                    schemas_json,
                    cred_defs_json,
                )
                .await?;

                let requested_sequences: Vec<RequestedRevocationSequenceIn> =
                    match revocation_sequences_json {
                        Some(raw) if !raw.trim().is_empty() => serde_json::from_str(&raw)
                            .map_err(|e| {
                                napi::Error::from_reason(format!(
                                    "revocation_sequences_json inválido: {}",
                                    e
                                ))
                            })?,
                        _ => Vec::new(),
                    };

                let mut requested_sequence_map = HashMap::new();
                for item in requested_sequences {
                    requested_sequence_map.insert(
                        item.credential_id_local,
                        (
                            item.primary_window_index,
                            item.additional_window_count.unwrap_or(0),
                        ),
                    );
                }

                let used_credential_ids =
                    collect_requested_credential_ids(&requested_credentials_json)?;
                let mut used_credentials = Vec::new();
                let mut revocation_proof_sequences = Vec::new();

                for credential_id_local in used_credential_ids {
                    if let Some((bundle_id_local, bundle)) =
                        find_holder_revocation_bundle_by_credential_id(&store, &credential_id_local)
                            .await?
                    {
                        let (primary_window_index, additional_window_count) =
                            requested_sequence_map.get(&credential_id_local).copied().ok_or_else(|| {
                                napi::Error::from_reason(format!(
                                    "primary_window_index explícito é obrigatório para a credencial revogável {}",
                                    credential_id_local
                                ))
                            })?;
                        let proof_sequence = build_revocation_proof_sequence_for_window(
                            &credential_id_local,
                            &bundle,
                            primary_window_index,
                            additional_window_count,
                        )
                        .map_err(|e| {
                            napi::Error::from_reason(format!(
                                "Erro montando sequência de prova de revogação para {}: {}",
                                credential_id_local, e
                            ))
                        })?;

                        revocation_proof_sequences.push(
                            PresentationPackageRevocationProofSequenceOut {
                                credential_id_local: credential_id_local.clone(),
                                bundle_id_local: bundle_id_local.clone(),
                                primary_window_index,
                                additional_window_count,
                                proof_sequence,
                            },
                        );
                        used_credentials.push(PresentationPackageUsedCredentialOut {
                            credential_id_local,
                            cred_def_id: Some(bundle.cred_def_id.clone()),
                            revocable: true,
                            bundle_id_local: Some(bundle_id_local),
                            window_index: Some(primary_window_index),
                        });
                    } else {
                        used_credentials.push(PresentationPackageUsedCredentialOut {
                            credential_id_local,
                            cred_def_id: None,
                            revocable: false,
                            bundle_id_local: None,
                            window_index: None,
                        });
                    }
                }

                let revocable_credentials_count =
                    used_credentials.iter().filter(|item| item.revocable).count();

                let response = serde_json::json!({
                    "ok": true,
                    "presentation_json": presentation_json,
                    "used_credentials": used_credentials,
                    "revocation_proof_sequences": revocation_proof_sequences,
                    "revocable_credentials_count": revocable_credentials_count,
                });

                serde_json::to_string(&response).map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando presentation package v2 com revogação: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    // =========================================================================
    //  7. VERIFIER: VALIDAR (FINAL)
    // =========================================================================
    #[napi]
    pub fn verify_presentation(
        &self,
        env: Env,
        presentation_request_json: String,
        presentation_json: String,
        schemas_json: String,
        cred_defs_json: String,
    ) -> Result<JsObject> {
        env.execute_tokio_future(
            async move {
                let valid = verify_presentation_json_internal(
                    &presentation_request_json,
                    &presentation_json,
                    &schemas_json,
                    &cred_defs_json,
                )?;
                Ok(valid)
            },
            |&mut env, data| env.get_boolean(data),
        )
    }

    #[napi]
    pub fn verify_mixed_presentation_package(
        &self,
        env: Env,
        presentation_request_json: String,
        presentation_json: String,
        schemas_json: String,
        cred_defs_json: String,
        revocation_proofs_json: String,
        expected_roots_json: Option<String>,
    ) -> Result<JsObject> {
        let pool = self.pool.clone();
        env.execute_tokio_future(
            async move {
                let cryptographic_valid = verify_presentation_json_internal(
                    &presentation_request_json,
                    &presentation_json,
                    &schemas_json,
                    &cred_defs_json,
                )?;

                let presentation_value: JsonValue = serde_json::from_str(&presentation_json)
                    .map_err(|e| {
                        napi::Error::from_reason(format!("presentation_json inválido: {}", e))
                    })?;
                let presentation_request_value: JsonValue =
                    serde_json::from_str(&presentation_request_json).map_err(|e| {
                        napi::Error::from_reason(format!(
                            "presentation_request_json inválido: {}",
                            e
                        ))
                    })?;

                let revocable_from_presentation =
                    extract_revocation_controls_from_presentation_value(
                        &presentation_value,
                        Some(&presentation_request_value),
                    )?;

                let proof_items: Vec<MixedRevocationProofIn> =
                    serde_json::from_str(&revocation_proofs_json).map_err(|e| {
                        napi::Error::from_reason(format!("revocation_proofs_json inválido: {}", e))
                    })?;

                let expected_roots: Vec<MixedExpectedRootIn> = match expected_roots_json {
                    Some(raw) if !raw.trim().is_empty() => serde_json::from_str(&raw).map_err(|e| {
                        napi::Error::from_reason(format!("expected_roots_json inválido: {}", e))
                    })?,
                    _ => Vec::new(),
                };

                let mut matched_revocable = vec![false; revocable_from_presentation.len()];
                let mut per_credential_status = Vec::new();

                for proof_item in proof_items {
                    ensure_legacy_revocation_proof_uses_validity_window(&proof_item.proof)?;
                    let explicit_expected_root = expected_roots
                        .iter()
                        .find(|item| {
                            proof_item
                                .credential_id_local
                                .as_ref()
                                .zip(item.credential_id_local.as_ref())
                                .map(|(a, b)| a == b)
                                .unwrap_or(false)
                                || proof_item
                                    .cred_def_id
                                    .as_ref()
                                    .zip(item.cred_def_id.as_ref())
                                    .map(|(a, b)| a == b)
                                    .unwrap_or(false)
                        })
                        .map(|item| item.root_merkle_l.clone());

                    let expected_root_candidate =
                        explicit_expected_root.unwrap_or_else(|| proof_item.proof.control.root_merkle_l.clone());

                    let matching_unused_index = revocable_from_presentation
                        .iter()
                        .enumerate()
                        .find(|(idx, item)| {
                            !matched_revocable[*idx]
                                && item.controls.root_merkle_l == expected_root_candidate
                        })
                        .map(|(idx, _)| idx);

                    let duplicate_match_exists = revocable_from_presentation
                        .iter()
                        .enumerate()
                        .any(|(idx, item)| {
                            matched_revocable[idx]
                                && item.controls.root_merkle_l == expected_root_candidate
                        });

                    let Some(match_index) = matching_unused_index else {
                        let details = if duplicate_match_exists {
                            "Prova complementar duplicada para um root_merkle_L já processado"
                                .to_string()
                        } else {
                            "Nenhum root_merkle_L correspondente foi encontrado na apresentação"
                                .to_string()
                        };
                        per_credential_status.push(MixedCredentialStatusOut {
                            sub_proof_index: usize::MAX,
                            credential_id_local: proof_item
                                .credential_id_local
                                .clone()
                                .or_else(|| Some(proof_item.proof.credential_id_local.clone())),
                            cred_def_id: proof_item.cred_def_id.clone(),
                            revocable: true,
                            proof_verified: Some(false),
                            revoked: false,
                            details,
                            revocation_status: None,
                        });
                        continue;
                    };

                    matched_revocable[match_index] = true;
                    let matched = &revocable_from_presentation[match_index];
                    let status = verify_revocation_proof_payload(
                        pool.clone(),
                        &proof_item.proof,
                        Some(&matched.controls.root_merkle_l),
                    )
                    .await
                    .map_err(|e| {
                        napi::Error::from_reason(format!(
                            "Erro validando prova complementar de revogação: {}",
                            e
                        ))
                    })?;

                    per_credential_status.push(MixedCredentialStatusOut {
                        sub_proof_index: matched.sub_proof_index,
                        credential_id_local: proof_item
                            .credential_id_local
                            .clone()
                            .or_else(|| Some(proof_item.proof.credential_id_local.clone())),
                        cred_def_id: matched.credential_hint.cred_def_id.clone(),
                        revocable: true,
                        proof_verified: Some(status.verified),
                        revoked: status.revoked,
                        details: status.details.clone(),
                        revocation_status: Some(status),
                    });
                }

                for (idx, matched) in revocable_from_presentation.iter().enumerate() {
                    if matched_revocable[idx] {
                        continue;
                    }
                    per_credential_status.push(MixedCredentialStatusOut {
                        sub_proof_index: matched.sub_proof_index,
                        credential_id_local: None,
                        cred_def_id: matched.credential_hint.cred_def_id.clone(),
                        revocable: true,
                        proof_verified: Some(false),
                        revoked: false,
                        details: "Prova complementar de revogação ausente para credencial revogável revelada na apresentação".to_string(),
                        revocation_status: None,
                    });
                }

                let identifiers = presentation_value
                    .get("identifiers")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                for (sub_proof_index, identifier) in identifiers.iter().enumerate() {
                    if revocable_from_presentation
                        .iter()
                        .any(|item| item.sub_proof_index == sub_proof_index)
                    {
                        continue;
                    }

                    let identifier_obj = identifier.as_object().cloned().unwrap_or_default();
                    per_credential_status.push(MixedCredentialStatusOut {
                        sub_proof_index,
                        credential_id_local: None,
                        cred_def_id: identifier_obj
                            .get("cred_def_id")
                            .or_else(|| identifier_obj.get("credDefId"))
                            .and_then(json_stringish),
                        revocable: false,
                        proof_verified: None,
                        revoked: false,
                        details: "Credencial não revogável; validade depende apenas da prova criptográfica".to_string(),
                        revocation_status: None,
                    });
                }

                per_credential_status.sort_by_key(|item| item.sub_proof_index);

                let proofs_verified = per_credential_status
                    .iter()
                    .filter(|item| item.revocable)
                    .all(|item| item.proof_verified == Some(true));
                let revoked = per_credential_status.iter().any(|item| item.revoked);
                let accepted = cryptographic_valid && proofs_verified && !revoked;

                let response = serde_json::json!({
                    "ok": true,
                    "cryptographic_valid": cryptographic_valid,
                    "proofs_verified": proofs_verified,
                    "revoked": revoked,
                    "accepted": accepted,
                    "per_credential_status": per_credential_status,
                });

                serde_json::to_string(&response).map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando resultado da verificação agregada: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn verify_mixed_presentation_package_v2(
        &self,
        env: Env,
        presentation_request_json: String,
        presentation_json: String,
        schemas_json: String,
        cred_defs_json: String,
        revocation_proof_sequences_json: String,
        expected_roots_json: Option<String>,
        policy_json: Option<String>,
    ) -> Result<JsObject> {
        let pool = self.pool.clone();
        let store = self.store.clone();
        env.execute_tokio_future(
            async move {
                let cryptographic_valid = verify_presentation_json_internal(
                    &presentation_request_json,
                    &presentation_json,
                    &schemas_json,
                    &cred_defs_json,
                )?;

                let presentation_value: JsonValue = serde_json::from_str(&presentation_json)
                    .map_err(|e| {
                        napi::Error::from_reason(format!("presentation_json inválido: {}", e))
                    })?;
                let presentation_request_value: JsonValue =
                    serde_json::from_str(&presentation_request_json).map_err(|e| {
                        napi::Error::from_reason(format!(
                            "presentation_request_json inválido: {}",
                            e
                        ))
                    })?;

                let revocable_from_presentation =
                    extract_revocation_controls_from_presentation_value(
                        &presentation_value,
                        Some(&presentation_request_value),
                    )?;

                let proof_items: Vec<MixedRevocationProofSequenceIn> =
                    serde_json::from_str(&revocation_proof_sequences_json).map_err(|e| {
                        napi::Error::from_reason(format!(
                            "revocation_proof_sequences_json inválido: {}",
                            e
                        ))
                    })?;

                let expected_roots: Vec<MixedExpectedRootIn> = match expected_roots_json {
                    Some(raw) if !raw.trim().is_empty() => serde_json::from_str(&raw).map_err(|e| {
                        napi::Error::from_reason(format!("expected_roots_json inválido: {}", e))
                    })?,
                    _ => Vec::new(),
                };
                let policy: Option<RevocationConfirmationPolicy> = match policy_json {
                    Some(raw) if !raw.trim().is_empty() => Some(
                        serde_json::from_str(&raw).map_err(|e| {
                            napi::Error::from_reason(format!("policy_json inválido: {}", e))
                        })?,
                    ),
                    _ => None,
                };
                if let Some(policy) = &policy {
                    policy.ensure_protocol_compliance().map_err(|e| {
                        napi::Error::from_reason(format!(
                            "policy_json diverge do mecanismo de revogação: {}",
                            e
                        ))
                    })?;
                }

                let mut matched_revocable = vec![false; revocable_from_presentation.len()];
                let mut per_credential_status = Vec::new();

                for proof_item in proof_items {
                    let explicit_expected_root = expected_roots
                        .iter()
                        .find(|item| {
                            proof_item
                                .credential_id_local
                                .as_ref()
                                .zip(item.credential_id_local.as_ref())
                                .map(|(a, b)| a == b)
                                .unwrap_or(false)
                                || proof_item
                                    .cred_def_id
                                    .as_ref()
                                    .zip(item.cred_def_id.as_ref())
                                    .map(|(a, b)| a == b)
                                    .unwrap_or(false)
                        })
                        .map(|item| item.root_merkle_l.clone());

                    let expected_root_candidate = explicit_expected_root.unwrap_or_else(|| {
                        proof_item
                            .proof_sequence
                            .primary_proof
                            .control
                            .root_merkle_l
                            .clone()
                    });

                    let matching_unused_index = revocable_from_presentation
                        .iter()
                        .enumerate()
                        .find(|(idx, item)| {
                            !matched_revocable[*idx]
                                && item.controls.root_merkle_l == expected_root_candidate
                        })
                        .map(|(idx, _)| idx);

                    let duplicate_match_exists = revocable_from_presentation
                        .iter()
                        .enumerate()
                        .any(|(idx, item)| {
                            matched_revocable[idx]
                                && item.controls.root_merkle_l == expected_root_candidate
                        });

                    let Some(match_index) = matching_unused_index else {
                        let details = if duplicate_match_exists {
                            "Sequência complementar duplicada para um root_merkle_L já processado"
                                .to_string()
                        } else {
                            "Nenhum root_merkle_L correspondente foi encontrado na apresentação"
                                .to_string()
                        };
                        per_credential_status.push(MixedCredentialStatusV2Out {
                            sub_proof_index: usize::MAX,
                            credential_id_local: proof_item
                                .credential_id_local
                                .clone()
                                .or_else(|| Some(proof_item.proof_sequence.credential_id_local)),
                            cred_def_id: proof_item.cred_def_id.clone(),
                            revocable: true,
                            proof_verified: Some(false),
                            revoked: false,
                            accepted: false,
                            requires_more_windows: false,
                            next_required_window_index: None,
                            issued_at: Some(
                                proof_item.proof_sequence.primary_proof.control.start_time,
                            ),
                            revoked_window_index: None,
                            revoked_window_start: None,
                            details,
                            revocation_status: None,
                        });
                        continue;
                    };

                    matched_revocable[match_index] = true;
                    let matched = &revocable_from_presentation[match_index];
                    let status = verify_revocation_proof_sequence_payload(
                        pool.clone(),
                        &proof_item.proof_sequence,
                        Some(&matched.controls.root_merkle_l),
                        policy.as_ref(),
                    )
                    .await
                    .map_err(|e| {
                        napi::Error::from_reason(format!(
                            "Erro validando sequência complementar de revogação: {}",
                            e
                        ))
                    })?;

                    per_credential_status.push(MixedCredentialStatusV2Out {
                        sub_proof_index: matched.sub_proof_index,
                        credential_id_local: proof_item
                            .credential_id_local
                            .clone()
                            .or_else(|| {
                                Some(proof_item.proof_sequence.credential_id_local.clone())
                            }),
                        cred_def_id: matched.credential_hint.cred_def_id.clone(),
                        revocable: true,
                        proof_verified: Some(status.verified),
                        revoked: status.revoked,
                        accepted: status.accepted,
                        requires_more_windows: status.requires_more_windows,
                        next_required_window_index: status.next_required_window_index,
                        issued_at: Some(
                            proof_item.proof_sequence.primary_proof.control.start_time,
                        ),
                        revoked_window_index: if status.revoked {
                            Some(status.primary_window_index)
                        } else {
                            None
                        },
                        revoked_window_start: revoked_window_start_from_status(&status),
                        details: status.details.clone(),
                        revocation_status: Some(status),
                    });
                }

                for (idx, matched) in revocable_from_presentation.iter().enumerate() {
                    if matched_revocable[idx] {
                        continue;
                    }
                    per_credential_status.push(MixedCredentialStatusV2Out {
                        sub_proof_index: matched.sub_proof_index,
                        credential_id_local: None,
                        cred_def_id: matched.credential_hint.cred_def_id.clone(),
                        revocable: true,
                        proof_verified: Some(false),
                        revoked: false,
                        accepted: false,
                        requires_more_windows: false,
                        next_required_window_index: None,
                        issued_at: parse_optional_i64(&matched.controls.start_time),
                        revoked_window_index: None,
                        revoked_window_start: None,
                        details: "Sequência complementar de revogação ausente para credencial revogável revelada na apresentação".to_string(),
                        revocation_status: None,
                    });
                }

                let identifiers = presentation_value
                    .get("identifiers")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                for (sub_proof_index, identifier) in identifiers.iter().enumerate() {
                    if revocable_from_presentation
                        .iter()
                        .any(|item| item.sub_proof_index == sub_proof_index)
                    {
                        continue;
                    }

                    let identifier_obj = identifier.as_object().cloned().unwrap_or_default();
                    per_credential_status.push(MixedCredentialStatusV2Out {
                        sub_proof_index,
                        credential_id_local: None,
                        cred_def_id: identifier_obj
                            .get("cred_def_id")
                            .or_else(|| identifier_obj.get("credDefId"))
                            .and_then(json_stringish),
                        revocable: false,
                        proof_verified: None,
                        revoked: false,
                        accepted: true,
                        requires_more_windows: false,
                        next_required_window_index: None,
                        issued_at: None,
                        revoked_window_index: None,
                        revoked_window_start: None,
                        details: "Credencial não revogável; validade depende apenas da prova criptográfica".to_string(),
                        revocation_status: None,
                    });
                }

                per_credential_status.sort_by_key(|item| item.sub_proof_index);

                let proofs_verified = per_credential_status
                    .iter()
                    .filter(|item| item.revocable)
                    .all(|item| item.proof_verified == Some(true));
                let revoked = per_credential_status.iter().any(|item| item.revoked);
                let requires_more_windows = per_credential_status
                    .iter()
                    .any(|item| item.requires_more_windows);
                let accepted =
                    cryptographic_valid && proofs_verified && !revoked && !requires_more_windows;

                if let Some(store) = &store {
                    let first_decision = per_credential_status
                        .iter()
                        .filter_map(|item| item.revocation_status.as_ref())
                        .map(|status| status.decision.clone())
                        .next();
                    let event = RevocationEventRecord {
                        event_id: make_revocation_event_id("verify-mixed-presentation-v2"),
                        created_at: crate::modules::common::now_ts(),
                        event_type: "verify_mixed_presentation_package_v2".to_string(),
                        credential_id_local: None,
                        issuer_did: None,
                        decision: first_decision,
                        trace_len: per_credential_status
                            .iter()
                            .filter_map(|item| item.revocation_status.as_ref())
                            .map(|status| status.trace.len())
                            .sum(),
                        payload: serde_json::json!({
                            "cryptographic_valid": cryptographic_valid,
                            "proofs_verified": proofs_verified,
                            "revoked": revoked,
                            "requires_more_windows": requires_more_windows,
                            "accepted": accepted,
                            "policy": policy.clone().unwrap_or_default(),
                            "per_credential_status": &per_credential_status,
                        }),
                    };
                    store_revocation_event(store, &event).await?;
                }

                let response = serde_json::json!({
                    "ok": true,
                    "cryptographic_valid": cryptographic_valid,
                    "proofs_verified": proofs_verified,
                    "revoked": revoked,
                    "requires_more_windows": requires_more_windows,
                    "accepted": accepted,
                    "policy": policy.unwrap_or_default(),
                    "per_credential_status": per_credential_status,
                });

                serde_json::to_string(&response).map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando resultado da verificação agregada v2: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    /// 1) Converte "selection_json" (UI friendly) -> requested_credentials_json (formato anoncreds)
    /// Útil para debug e para o Electron montar facilmente.
    #[napi]
    pub fn build_requested_credentials_v1(
        &self,
        env: Env,
        selection_json: String,
    ) -> Result<JsObject> {
        env.execute_tokio_future(
            async move {
                let spec: RequestedCredsSpecV1 =
                    serde_json::from_str(&selection_json).map_err(|e| {
                        napi::Error::from_reason(format!("JSON inválido selection_json: {}", e))
                    })?;

                let out = build_requested_credentials_from_spec(spec)?;
                Ok(out)
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    /// 2) Create presentation "v2" (multi-cred + reveal/unrevealed + predicates)
    /// Entrada:
    /// - presentation_request_json: igual hoje (anoncreds PresentationRequest)
    /// - selection_json: formato UI-friendly (RequestedCredsSpecV1)
    /// - schemas_json: map schemaId -> payload ledger/local
    /// - cred_defs_json: map credDefId -> payload ledger/local
    #[napi]
    pub fn create_presentation_v2(
        &self,
        env: Env,
        presentation_request_json: String,
        selection_json: String,
        schemas_json: String,
        cred_defs_json: String,
    ) -> Result<JsObject> {
        // Imports (iguais ao seu create_presentation atual)
        use anoncreds::data_types::cred_def::{CredentialDefinition, CredentialDefinitionId};
        use anoncreds::data_types::credential::Credential;
        use anoncreds::data_types::schema::{Schema, SchemaId};
        use anoncreds::types::{LinkSecret, PresentCredentials, PresentationRequest};
        use std::collections::HashMap;

        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let mut session = store
                    .session(None)
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro sessão: {}", e)))?;

                // 1) Link secret (igual você já faz)
                let link_secret = {
                    let cached_ls = { LINK_SECRET_CACHE.lock().unwrap().clone() };
                    if let Some(ls) = cached_ls {
                        ls
                    } else {
                        let entry = session
                            .fetch("link_secret", "default", false)
                            .await
                            .map_err(|e| napi::Error::from_reason(format!("Erro DB LS: {}", e)))?
                            .ok_or_else(|| {
                                napi::Error::from_reason("Link Secret 'default' não encontrado")
                            })?;
                        let seed_str = String::from_utf8(entry.value.to_vec()).unwrap_or_default();
                        let ls_obj = LinkSecret::try_from(seed_str.as_str()).map_err(|e| {
                            napi::Error::from_reason(format!("Erro LS math: {:?}", e))
                        })?;
                        let arc_ls = std::sync::Arc::new(ls_obj);
                        *LINK_SECRET_CACHE.lock().unwrap() = Some(arc_ls.clone());
                        arc_ls
                    }
                };

                // 2) Parse PresentationRequest
                let request: PresentationRequest = serde_json::from_str(&presentation_request_json)
                    .map_err(|e| napi::Error::from_reason(format!("Erro Request JSON: {}", e)))?;

                // 3) Parse selection spec e validar referents
                let spec: RequestedCredsSpecV1 =
                    serde_json::from_str(&selection_json).map_err(|e| {
                        napi::Error::from_reason(format!("JSON inválido selection_json: {}", e))
                    })?;

                let pres_req_json_val: serde_json::Value =
                    serde_json::from_str(&presentation_request_json).map_err(|e| {
                        napi::Error::from_reason(format!(
                            "presentationRequest JSON inválido: {}",
                            e
                        ))
                    })?;

                validate_selection_against_pres_req_json(&pres_req_json_val, &spec)?;

                // 4) Converter selection -> requested_credentials_json (formato esperado pelo seu core)
                let requested_credentials_json = build_requested_credentials_from_spec(spec)
                    .map_err(|e| napi::Error::from_reason(format!("{}", e)))?;

                // 5) A partir daqui, reutilizamos sua lógica atual:
                //    - parse schemas_json e cred_defs_json
                //    - agrupar ações por cred_id
                //    - carregar N credenciais do DB
                //    - montar PresentCredentials com revealed/predicates

                // -------- SCHEMAS (igual ao seu create_presentation) --------
                let schemas_raw: HashMap<String, serde_json::Value> =
                    serde_json::from_str(&schemas_json).map_err(|e| {
                        napi::Error::from_reason(format!("Erro JSON Schemas: {}", e))
                    })?;

                let mut schemas: HashMap<SchemaId, Schema> = HashMap::new();
                for (k, v) in schemas_raw {
                    let id = SchemaId::new(k.clone()).map_err(|_| {
                        napi::Error::from_reason(format!("SchemaId inválido: {}", k))
                    })?;

                    let mut target = &v;
                    if let Some(res) = v.get("result") {
                        if let Some(data) = res.get("data") {
                            target = data;
                        } else {
                            target = res;
                        }
                    }
                    let parsed_inner: serde_json::Value;
                    if target.is_string() {
                        let s = target.as_str().unwrap();
                        parsed_inner = serde_json::from_str(s).unwrap_or(serde_json::Value::Null);
                        target = &parsed_inner;
                    }
                    let source = target
                        .as_object()
                        .ok_or_else(|| napi::Error::from_reason("Schema invalido"))?;

                    let mut clean = serde_json::Map::new();
                    if let Some(x) = source.get("name") {
                        clean.insert("name".to_string(), x.clone());
                    }
                    if let Some(x) = source.get("version") {
                        clean.insert("version".to_string(), x.clone());
                    }
                    let attrs = source.get("attrNames").or_else(|| source.get("attr_names"));
                    if let Some(x) = attrs {
                        clean.insert("attrNames".to_string(), x.clone());
                    }

                    let derived_issuer = k.split(':').next().unwrap_or("unknown");
                    clean.insert("issuerId".to_string(), serde_json::json!(derived_issuer));

                    if let Some(x) = source.get("id") {
                        clean.insert("id".to_string(), x.clone());
                    }
                    if let Some(x) = source.get("ver") {
                        clean.insert("ver".to_string(), x.clone());
                    }

                    let schema_struct: Schema =
                        serde_json::from_value(serde_json::Value::Object(clean)).map_err(|e| {
                            napi::Error::from_reason(format!("Erro Struct Schema {}: {}", k, e))
                        })?;

                    schemas.insert(id, schema_struct);
                }

                // -------- CRED DEFS (igual ao seu create_presentation) --------
                let cred_defs_raw: HashMap<String, serde_json::Value> =
                    serde_json::from_str(&cred_defs_json).map_err(|e| {
                        napi::Error::from_reason(format!("Erro JSON CredDefs: {}", e))
                    })?;

                let mut cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition> =
                    HashMap::new();
                for (k, v) in cred_defs_raw {
                    let id = CredentialDefinitionId::new(k.clone()).map_err(|_| {
                        napi::Error::from_reason(format!("CredDefId inválido: {}", k))
                    })?;

                    let mut target = &v;
                    if let Some(res) = v.get("result") {
                        if let Some(data) = res.get("data") {
                            target = data;
                        } else {
                            target = res;
                        }
                    }
                    let parsed_inner: serde_json::Value;
                    if target.is_string() {
                        let s = target.as_str().unwrap();
                        parsed_inner = serde_json::from_str(s).unwrap_or(serde_json::Value::Null);
                        target = &parsed_inner;
                    }
                    let source = target.as_object().ok_or_else(|| {
                        napi::Error::from_reason(format!("CredDef {} invalida", k))
                    })?;

                    let mut clean = serde_json::Map::new();
                    clean.insert("id".to_string(), serde_json::json!(k));

                    let derived_issuer = k.split(':').next().unwrap_or("unknown");
                    clean.insert("issuerId".to_string(), serde_json::json!(derived_issuer));

                    let derived_schema_id = k.split(':').nth(3).unwrap_or("1");
                    let sid = source
                        .get("schemaId")
                        .or_else(|| source.get("schema_id"))
                        .cloned()
                        .unwrap_or(serde_json::json!(derived_schema_id));
                    clean.insert("schemaId".to_string(), sid);

                    clean.insert(
                        "type".to_string(),
                        source
                            .get("type")
                            .cloned()
                            .unwrap_or(serde_json::json!("CL")),
                    );
                    clean.insert(
                        "tag".to_string(),
                        source
                            .get("tag")
                            .cloned()
                            .unwrap_or(serde_json::json!("TAG_PROOF")),
                    );
                    clean.insert(
                        "ver".to_string(),
                        source
                            .get("ver")
                            .cloned()
                            .unwrap_or(serde_json::json!("1.0")),
                    );

                    if source.contains_key("primary") && !source.contains_key("value") {
                        let mut val_map = serde_json::Map::new();
                        val_map.insert(
                            "primary".to_string(),
                            source.get("primary").unwrap().clone(),
                        );
                        if let Some(rev) = source.get("revocation") {
                            val_map.insert("revocation".to_string(), rev.clone());
                        }
                        clean.insert("value".to_string(), serde_json::Value::Object(val_map));
                    } else if let Some(val) = source.get("value") {
                        clean.insert("value".to_string(), val.clone());
                    } else {
                        return Err(napi::Error::from_reason(format!(
                            "CredDef {} sem chaves",
                            k
                        )));
                    }

                    let cd_struct: CredentialDefinition =
                        serde_json::from_value(serde_json::Value::Object(clean)).map_err(|e| {
                            napi::Error::from_reason(format!("Erro Struct CredDef {}: {}", k, e))
                        })?;

                    cred_defs.insert(id, cd_struct);
                }

                // -------- parse requested_credentials_json (formato anoncreds-like) --------
                let req_creds_input: serde_json::Value =
                    serde_json::from_str(&requested_credentials_json)
                        .map_err(|_| napi::Error::from_reason("Erro RequestedCredentials Input"))?;

                // Agrupar por cred_id
                struct CredentialAction {
                    referent: String,
                    is_predicate: bool,
                    revealed: bool,
                    timestamp: Option<u64>,
                }
                let mut cred_actions: HashMap<String, Vec<CredentialAction>> = HashMap::new();

                if let Some(req_attrs) = req_creds_input
                    .get("requested_attributes")
                    .and_then(|v| v.as_object())
                {
                    for (referent, info) in req_attrs {
                        let cred_id = info
                            .get("cred_id")
                            .and_then(|x| x.as_str())
                            .ok_or_else(|| {
                                napi::Error::from_reason("requested_attributes.*.cred_id ausente")
                            })?
                            .to_string();
                        let revealed = info
                            .get("revealed")
                            .and_then(|x| x.as_bool())
                            .unwrap_or(true);
                        let timestamp = info.get("timestamp").and_then(|t| t.as_u64());

                        cred_actions
                            .entry(cred_id)
                            .or_default()
                            .push(CredentialAction {
                                referent: referent.clone(),
                                is_predicate: false,
                                revealed,
                                timestamp,
                            });
                    }
                }

                if let Some(req_preds) = req_creds_input
                    .get("requested_predicates")
                    .and_then(|v| v.as_object())
                {
                    for (referent, info) in req_preds {
                        let cred_id = info
                            .get("cred_id")
                            .and_then(|x| x.as_str())
                            .ok_or_else(|| {
                                napi::Error::from_reason("requested_predicates.*.cred_id ausente")
                            })?
                            .to_string();
                        let timestamp = info.get("timestamp").and_then(|t| t.as_u64());

                        cred_actions
                            .entry(cred_id)
                            .or_default()
                            .push(CredentialAction {
                                referent: referent.clone(),
                                is_predicate: true,
                                revealed: false,
                                timestamp,
                            });
                    }
                }

                // Carregar credenciais do DB (categoria "credential") e manter vivas
                let mut credential_keeper: HashMap<String, Credential> = HashMap::new();
                for cred_id in cred_actions.keys() {
                    let cred_entry = session
                        .fetch("credential", cred_id, false)
                        .await
                        .map_err(|e| {
                            napi::Error::from_reason(format!("Erro DB fetch {}: {}", cred_id, e))
                        })?
                        .ok_or_else(|| {
                            napi::Error::from_reason(format!("Cred {} nao achada", cred_id))
                        })?;

                    let cred_str = String::from_utf8(cred_entry.value.to_vec()).unwrap_or_default();
                    let cred_json: serde_json::Value =
                        serde_json::from_str(&cred_str).unwrap_or(serde_json::Value::Null);
                    let actual_cred = cred_json.get("credential").unwrap_or(&cred_json).clone();

                    let credential: Credential =
                        serde_json::from_value(actual_cred).map_err(|e| {
                            napi::Error::from_reason(format!("Erro parse Cred {}: {}", cred_id, e))
                        })?;

                    credential_keeper.insert(cred_id.clone(), credential);
                }

                // Montar PresentCredentials
                let mut present_credentials = PresentCredentials::default();
                for (cred_id, actions) in cred_actions {
                    let credential_ref = credential_keeper
                        .get(&cred_id)
                        .ok_or_else(|| napi::Error::from_reason("Erro interno keeper"))?;

                    let mut cred_builder =
                        present_credentials.add_credential(credential_ref, None, None);

                    for action in actions {
                        if action.is_predicate {
                            cred_builder.add_requested_predicate(&action.referent);
                        } else {
                            cred_builder.add_requested_attribute(&action.referent, action.revealed);
                        }
                    }
                }

                // Self-attested (do spec)
                let self_attested = req_creds_input
                    .get("self_attested_attributes")
                    .and_then(|v| v.as_object())
                    .map(|m| {
                        m.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                            .collect::<HashMap<String, String>>()
                    })
                    .unwrap_or_else(HashMap::new);

                let presentation = anoncreds::prover::create_presentation(
                    &request,
                    present_credentials,
                    Some(self_attested),
                    &link_secret,
                    &schemas,
                    &cred_defs,
                )
                .map_err(|e| {
                    napi::Error::from_reason(format!("Erro MATEMÁTICO create_presentation: {}", e))
                })?;

                Ok(serde_json::to_string(&presentation).unwrap())
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn store_presentation(
        &self,
        env: Env,
        presentation_id_local: String,
        presentation_json: String,
        presentation_request_json: Option<String>,
        meta_json: Option<String>,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let mut session = store
                    .session(None)
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro sessão: {}", e)))?;

                // Parse apresentação (objeto)
                let pres_val: JsonValue =
                    serde_json::from_str(&presentation_json).map_err(|e| {
                        napi::Error::from_reason(format!("Presentation JSON inválido: {}", e))
                    })?;

                // Opcional: parse request e extrair nonce para tag
                let mut req_nonce: String = "".to_string();
                let pres_req_val: Option<JsonValue> =
                    if let Some(req_str) = presentation_request_json.as_ref() {
                        if req_str.trim().is_empty() {
                            None
                        } else {
                            let v: JsonValue = serde_json::from_str(req_str).map_err(|e| {
                                napi::Error::from_reason(format!(
                                    "PresentationRequest JSON inválido: {}",
                                    e
                                ))
                            })?;
                            if let Some(n) = v.get("nonce").and_then(|x| x.as_str()) {
                                req_nonce = n.to_string();
                            }
                            Some(v)
                        }
                    } else {
                        None
                    };

                // Meta livre (ex.: verifierDid, holderDid, verified=true, verified_at etc.)
                let mut meta_val: Option<JsonValue> = if let Some(m) = meta_json.as_ref() {
                    if m.trim().is_empty() {
                        None
                    } else {
                        Some(serde_json::from_str(m).map_err(|e| {
                            napi::Error::from_reason(format!("Meta JSON inválido: {}", e))
                        })?)
                    }
                } else {
                    None
                };
                let revocation_sequences_val =
                    extract_revocation_sequences_from_meta(&mut meta_val);

                let record = StoredPresentationRecordV1 {
                    presentation: pres_val,
                    presentation_request: pres_req_val,
                    meta: meta_val,
                };

                let record_str = serde_json::to_string(&record).map_err(|e| {
                    napi::Error::from_reason(format!("Erro serializar record: {}", e))
                })?;

                let now_ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .to_string();

                let mut tags = vec![EntryTag::Encrypted("created_at".to_string(), now_ts)];

                if !req_nonce.is_empty() {
                    tags.push(EntryTag::Encrypted("request_nonce".to_string(), req_nonce));
                }

                session
                    .insert(
                        "presentation",
                        &presentation_id_local,
                        record_str.as_bytes(),
                        Some(&tags),
                        None,
                    )
                    .await
                    .map_err(|e| {
                        napi::Error::from_reason(format!("Erro salvar apresentação: {}", e))
                    })?;

                let existing_revocation = session
                    .fetch(
                        PRESENTATION_REVOCATION_CATEGORY,
                        &presentation_id_local,
                        false,
                    )
                    .await
                    .map_err(|e| {
                        napi::Error::from_reason(format!(
                            "Erro fetch sidecar de revogação da apresentação: {}",
                            e
                        ))
                    })?;
                if existing_revocation.is_some() {
                    session
                        .remove(PRESENTATION_REVOCATION_CATEGORY, &presentation_id_local)
                        .await
                        .map_err(|e| {
                            napi::Error::from_reason(format!(
                                "Erro removendo sidecar antigo de revogação da apresentação: {}",
                                e
                            ))
                        })?;
                }

                if let Some(seqs_val) = revocation_sequences_val {
                    let seqs_str = serde_json::to_string(&seqs_val).map_err(|e| {
                        napi::Error::from_reason(format!(
                            "Erro serializar sidecar de revogação da apresentação: {}",
                            e
                        ))
                    })?;
                    session
                        .insert(
                            PRESENTATION_REVOCATION_CATEGORY,
                            &presentation_id_local,
                            seqs_str.as_bytes(),
                            Some(&[]),
                            None,
                        )
                        .await
                        .map_err(|e| {
                            napi::Error::from_reason(format!(
                                "Erro salvando sidecar de revogação da apresentação: {}",
                                e
                            ))
                        })?;
                }

                session
                    .commit()
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro commit: {}", e)))?;

                Ok(presentation_id_local)
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn get_stored_presentation(
        &self,
        env: Env,
        presentation_id_local: String,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let mut session = store
                    .session(None)
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro sessão: {}", e)))?;

                let entry = session
                    .fetch("presentation", &presentation_id_local, false)
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro fetch: {}", e)))?
                    .ok_or_else(|| napi::Error::from_reason("Apresentação não encontrada"))?;

                let record_str = String::from_utf8(entry.value.to_vec()).unwrap_or_default();
                let mut record: StoredPresentationRecordV1 =
                    serde_json::from_str(&record_str).map_err(|e| {
                        napi::Error::from_reason(format!(
                            "Record armazenado inválido (não é StoredPresentationRecordV1): {}",
                            e
                        ))
                    })?;

                let embedded_seqs = extract_revocation_sequences_from_meta(&mut record.meta);
                if let Some(seqs_val) = embedded_seqs {
                    let seqs_str = serde_json::to_string(&seqs_val).map_err(|e| {
                        napi::Error::from_reason(format!(
                            "Erro serializar sidecar migrado de revogação da apresentação: {}",
                            e
                        ))
                    })?;
                    let sidecar_exists = session
                        .fetch(PRESENTATION_REVOCATION_CATEGORY, &presentation_id_local, false)
                        .await
                        .map_err(|e| {
                            napi::Error::from_reason(format!(
                                "Erro fetch sidecar de revogação da apresentação: {}",
                                e
                            ))
                        })?
                        .is_some();
                    if sidecar_exists {
                        session
                            .replace(
                                PRESENTATION_REVOCATION_CATEGORY,
                                &presentation_id_local,
                                seqs_str.as_bytes(),
                                Some(&[]),
                                None,
                            )
                            .await
                            .map_err(|e| {
                                napi::Error::from_reason(format!(
                                    "Erro atualizando sidecar de revogação da apresentação: {}",
                                    e
                                ))
                            })?;
                    } else {
                        session
                            .insert(
                                PRESENTATION_REVOCATION_CATEGORY,
                                &presentation_id_local,
                                seqs_str.as_bytes(),
                                Some(&[]),
                                None,
                            )
                            .await
                            .map_err(|e| {
                                napi::Error::from_reason(format!(
                                    "Erro salvando sidecar migrado de revogação da apresentação: {}",
                                    e
                                ))
                            })?;
                    }

                    let sanitized_record_str = serde_json::to_string(&record).map_err(|e| {
                        napi::Error::from_reason(format!(
                            "Erro serializar record sanitizado da apresentação: {}",
                            e
                        ))
                    })?;
                    let tags: Vec<EntryTag> = entry
                        .tags
                        .iter()
                        .map(|t| EntryTag::Encrypted(t.name().to_string(), t.value().to_string()))
                        .collect();
                    session
                        .replace(
                            "presentation",
                            &presentation_id_local,
                            sanitized_record_str.as_bytes(),
                            Some(&tags),
                            None,
                        )
                        .await
                        .map_err(|e| {
                            napi::Error::from_reason(format!(
                                "Erro atualizando record sanitizado da apresentação: {}",
                                e
                            ))
                        })?;
                    session
                        .commit()
                        .await
                        .map_err(|e| napi::Error::from_reason(format!("Erro commit: {}", e)))?;
                    Ok(sanitized_record_str)
                } else {
                    Ok(record_str)
                }
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn get_stored_presentation_revocation_sequences(
        &self,
        env: Env,
        presentation_id_local: String,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let mut session = store
                    .session(None)
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro sessão: {}", e)))?;

                let sidecar = session
                    .fetch(
                        PRESENTATION_REVOCATION_CATEGORY,
                        &presentation_id_local,
                        false,
                    )
                    .await
                    .map_err(|e| {
                        napi::Error::from_reason(format!(
                            "Erro fetch sidecar de revogação da apresentação: {}",
                            e
                        ))
                    })?;

                if let Some(entry) = sidecar {
                    let s = String::from_utf8(entry.value.to_vec())
                        .unwrap_or_else(|_| "[]".to_string());
                    return Ok(s);
                }

                Ok("[]".to_string())
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn list_presentations(&self, env: Env) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let mut session = store
                    .session(None)
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro sessão: {}", e)))?;

                let entries = session
                    .fetch_all(Some("presentation"), None, None, None, false, false)
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro fetch_all: {}", e)))?;

                let mut out = Vec::new();
                for e in entries {
                    let mut tags_obj = serde_json::Map::new();
                    for t in &e.tags {
                        tags_obj.insert(t.name().to_string(), serde_json::json!(t.value()));
                    }
                    out.push(serde_json::json!({
                        "id_local": e.name,
                        "tags": tags_obj,
                    }));
                }

                serde_json::to_string(&out)
                    .map_err(|_| napi::Error::from_reason("Erro serializando lista"))
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn delete_stored_presentation(
        &self,
        env: Env,
        presentation_id_local: String,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let mut session = store
                    .session(None)
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro sessão: {}", e)))?;

                let existing = session
                    .fetch("presentation", &presentation_id_local, false)
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro fetch: {}", e)))?;

                if existing.is_none() {
                    return Err(napi::Error::from_reason(format!(
                        "Apresentação não encontrada: {}",
                        presentation_id_local
                    )));
                }

                let existing_revocation = session
                    .fetch(
                        PRESENTATION_REVOCATION_CATEGORY,
                        &presentation_id_local,
                        false,
                    )
                    .await
                    .map_err(|e| {
                        napi::Error::from_reason(format!(
                            "Erro fetch sidecar de revogação da apresentação: {}",
                            e
                        ))
                    })?;
                if existing_revocation.is_some() {
                    session
                        .remove(PRESENTATION_REVOCATION_CATEGORY, &presentation_id_local)
                        .await
                        .map_err(|e| {
                            napi::Error::from_reason(format!(
                                "Erro ao deletar sidecar de revogação da apresentação: {}",
                                e
                            ))
                        })?;
                }

                session
                    .remove("presentation", &presentation_id_local)
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro ao deletar: {}", e)))?;

                session
                    .commit()
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro commit delete: {}", e)))?;

                Ok(true)
            },
            |&mut env, data| env.get_boolean(data),
        )
    }

    #[napi]
    pub fn export_stored_presentation(
        &self,
        env: Env,
        presentation_id_local: String,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let mut session = store
                    .session(None)
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro sessão: {}", e)))?;

                let entry = session
                    .fetch("presentation", &presentation_id_local, false)
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro fetch: {}", e)))?
                    .ok_or_else(|| napi::Error::from_reason("Apresentação não encontrada"))?;

                let record_str = String::from_utf8(entry.value.to_vec()).unwrap_or_default();

                let mut record: StoredPresentationRecordV1 = serde_json::from_str(&record_str)
                    .map_err(|e| {
                        napi::Error::from_reason(format!(
                            "Record armazenado inválido (não é StoredPresentationRecordV1): {}",
                            e
                        ))
                    })?;

                let sidecar = session
                    .fetch(
                        PRESENTATION_REVOCATION_CATEGORY,
                        &presentation_id_local,
                        false,
                    )
                    .await
                    .map_err(|e| {
                        napi::Error::from_reason(format!(
                            "Erro fetch sidecar de revogação da apresentação: {}",
                            e
                        ))
                    })?;
                if let Some(seq_entry) = sidecar {
                    let seq_str = String::from_utf8(seq_entry.value.to_vec())
                        .unwrap_or_else(|_| "[]".to_string());
                    let seq_val: JsonValue = serde_json::from_str(&seq_str).map_err(|e| {
                        napi::Error::from_reason(format!(
                            "Sidecar de revogação da apresentação inválido: {}",
                            e
                        ))
                    })?;
                    attach_revocation_sequences_to_meta(&mut record.meta, Some(seq_val));
                }

                let stored_at_ms = (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis()) as i64;

                let mut tags_map = BTreeMap::new();
                for t in &entry.tags {
                    // em geral, t.value() aqui vira string (compatível com seu list_presentations)
                    tags_map.insert(t.name().to_string(), t.value().to_string());
                }

                let pkg = PresentationPackageV1 {
                    pkg_type: "ssi.presentation.package".to_string(),
                    version: 1,
                    id_local: presentation_id_local,
                    stored_at_ms,
                    record,
                    tags: tags_map,
                };

                serde_json::to_string(&pkg).map_err(|e| {
                    napi::Error::from_reason(format!("Erro serializar package: {}", e))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn import_stored_presentation(
        &self,
        env: Env,
        package_json: String,
        overwrite: Option<bool>,
        new_id_local: Option<String>,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let overwrite = overwrite.unwrap_or(false);

                let pkg: PresentationPackageV1 =
                    serde_json::from_str(&package_json).map_err(|e| {
                        napi::Error::from_reason(format!("Package JSON inválido: {}", e))
                    })?;

                if pkg.pkg_type != "ssi.presentation.package" || pkg.version != 1 {
                    return Err(napi::Error::from_reason(format!(
                        "Package inválido: type/version inesperados (type={}, version={})",
                        pkg.pkg_type, pkg.version
                    )));
                }

                let target_id = new_id_local.unwrap_or(pkg.id_local);

                let mut record_to_store = pkg.record;
                let revocation_sequences_val =
                    extract_revocation_sequences_from_meta(&mut record_to_store.meta);
                let record_str = serde_json::to_string(&record_to_store).map_err(|e| {
                    napi::Error::from_reason(format!("Erro serializar record: {}", e))
                })?;

                let mut tags: Vec<EntryTag> = Vec::new();

                // 1) Se o package trouxe tags, use-as (preferência)
                if !pkg.tags.is_empty() {
                    for (k, v) in &pkg.tags {
                        tags.push(EntryTag::Encrypted(k.to_string(), v.to_string()));
                    }
                } else {
                    // tags: created_at + request_nonce (se houver)
                    let now_ts = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        .to_string();

                    let mut tags = vec![EntryTag::Encrypted("created_at".to_string(), now_ts)];

                    if let Some(req) = &record_to_store.presentation_request {
                        if let Some(n) = req.get("nonce").and_then(|x| x.as_str()) {
                            tags.push(EntryTag::Encrypted(
                                "request_nonce".to_string(),
                                n.to_string(),
                            ));
                        }
                    }
                }

                let mut session = store
                    .session(None)
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro sessão: {}", e)))?;

                let existing = session
                    .fetch("presentation", &target_id, false)
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro fetch: {}", e)))?;

                if existing.is_some() && !overwrite {
                    return Err(napi::Error::from_reason(format!(
                        "Apresentação já existe: {} (use overwrite=true ou new_id_local)",
                        target_id
                    )));
                }

                if existing.is_some() && overwrite {
                    session
                        .remove("presentation", &target_id)
                        .await
                        .map_err(|e| {
                            napi::Error::from_reason(format!("Erro remove overwrite: {}", e))
                        })?;
                }

                let existing_revocation = session
                    .fetch(PRESENTATION_REVOCATION_CATEGORY, &target_id, false)
                    .await
                    .map_err(|e| {
                        napi::Error::from_reason(format!(
                            "Erro fetch sidecar de revogação da apresentação: {}",
                            e
                        ))
                    })?;
                if existing_revocation.is_some() {
                    session
                        .remove(PRESENTATION_REVOCATION_CATEGORY, &target_id)
                        .await
                        .map_err(|e| {
                            napi::Error::from_reason(format!(
                                "Erro remove sidecar overwrite: {}",
                                e
                            ))
                        })?;
                }

                session
                    .insert(
                        "presentation",
                        &target_id,
                        record_str.as_bytes(),
                        Some(&tags),
                        None,
                    )
                    .await
                    .map_err(|e| {
                        napi::Error::from_reason(format!(
                            "Erro salvar apresentação (import): {}",
                            e
                        ))
                    })?;

                if let Some(seqs_val) = revocation_sequences_val {
                    let seqs_str = serde_json::to_string(&seqs_val).map_err(|e| {
                        napi::Error::from_reason(format!(
                            "Erro serializar sidecar de revogação da apresentação: {}",
                            e
                        ))
                    })?;
                    session
                        .insert(
                            PRESENTATION_REVOCATION_CATEGORY,
                            &target_id,
                            seqs_str.as_bytes(),
                            Some(&[]),
                            None,
                        )
                        .await
                        .map_err(|e| {
                            napi::Error::from_reason(format!(
                                "Erro salvar sidecar de revogação da apresentação: {}",
                                e
                            ))
                        })?;
                }

                session
                    .commit()
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro commit import: {}", e)))?;

                Ok(target_id)
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn extract_revocation_controls_from_presentation(
        &self,
        env: Env,
        presentation_json: String,
    ) -> Result<JsObject> {
        env.execute_tokio_future(
            async move { extract_revocation_controls_from_presentation_json(&presentation_json) },
            |&mut env, data| env.create_string(&data),
        )
    }
}
