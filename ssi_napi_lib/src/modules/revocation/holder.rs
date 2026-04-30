use crate::modules::revocation::merkle::{
    build_merkle_levels, build_merkle_proof_from_levels,
};
use crate::modules::revocation::storage::{
    get_holder_revocation_bundle, store_holder_revocation_bundle,
};
use crate::modules::revocation::types::{
    HolderRevocationBundle, RevocationProofPayload, RevocationProofSequence,
};
use crate::modules::revocation::windows::{
    is_confirmation_only_window_index, is_validity_window_index, window_layout_from_control,
    window_start_for_index,
};
use crate::IndyAgent;
use napi::{Env, Error, JsObject, Result};
use napi_derive::napi;

pub fn build_revocation_proof_for_window(
    credential_id_local: &str,
    bundle: &HolderRevocationBundle,
    window_index: u32,
) -> std::result::Result<RevocationProofPayload, String> {
    let merkle_levels = build_merkle_levels(&bundle.l_values)?;
    build_revocation_proof_for_window_with_levels(
        credential_id_local,
        bundle,
        window_index,
        &merkle_levels,
    )
}

fn build_revocation_proof_for_window_with_levels(
    credential_id_local: &str,
    bundle: &HolderRevocationBundle,
    window_index: u32,
    merkle_levels: &[Vec<String>],
) -> std::result::Result<RevocationProofPayload, String> {
    let idx = window_index as usize;
    let t_entry = bundle
        .t_entries
        .get(idx)
        .ok_or_else(|| "window_index fora da faixa para T".to_string())?
        .clone();
    let l_value = bundle
        .l_values
        .get(idx)
        .ok_or_else(|| "window_index fora da faixa para L".to_string())?
        .clone();
    let merkle_path = build_merkle_proof_from_levels(merkle_levels, idx)?;
    let window_start = window_start_for_index(
        bundle.control.start_time,
        &bundle.control.unit_of_time,
        bundle.control.time_window,
        window_index,
    )?;

    Ok(RevocationProofPayload {
        credential_id_local: credential_id_local.to_string(),
        control: bundle.control.clone(),
        k_ledger_anchor: bundle.k_ledger_anchor.clone(),
        window_index,
        window_start,
        t_entry,
        l_value,
        merkle_path,
        manifest: bundle.manifest.clone(),
    })
}

fn ensure_window_index_in_total_range(
    bundle: &HolderRevocationBundle,
    window_index: u32,
) -> std::result::Result<(), String> {
    if window_index >= bundle.control.window_count {
        return Err(format!(
            "window_index {} fora do total de janelas ({})",
            window_index, bundle.control.window_count
        ));
    }
    Ok(())
}

pub fn build_primary_revocation_proof_for_window(
    credential_id_local: &str,
    bundle: &HolderRevocationBundle,
    window_index: u32,
) -> std::result::Result<RevocationProofPayload, String> {
    ensure_window_index_in_total_range(bundle, window_index)?;
    let layout = window_layout_from_control(&bundle.control)?;
    if !is_validity_window_index(&layout, window_index) {
        return Err(format!(
            "window_index {} é janela exclusiva de confirmação; last_valid_window_index={}",
            window_index, layout.last_valid_window_index
        ));
    }

    build_revocation_proof_for_window(credential_id_local, bundle, window_index)
}

pub fn build_confirmation_revocation_proofs(
    credential_id_local: &str,
    bundle: &HolderRevocationBundle,
    primary_window_index: u32,
    additional_window_count: u32,
) -> std::result::Result<Vec<RevocationProofPayload>, String> {
    let merkle_levels = build_merkle_levels(&bundle.l_values)?;
    build_confirmation_revocation_proofs_with_levels(
        credential_id_local,
        bundle,
        primary_window_index,
        additional_window_count,
        &merkle_levels,
    )
}

fn build_confirmation_revocation_proofs_with_levels(
    credential_id_local: &str,
    bundle: &HolderRevocationBundle,
    primary_window_index: u32,
    additional_window_count: u32,
    merkle_levels: &[Vec<String>],
) -> std::result::Result<Vec<RevocationProofPayload>, String> {
    ensure_window_index_in_total_range(bundle, primary_window_index)?;
    let layout = window_layout_from_control(&bundle.control)?;
    if !is_validity_window_index(&layout, primary_window_index) {
        return Err(format!(
            "primary_window_index {} inválido para prova principal; last_valid_window_index={}",
            primary_window_index, layout.last_valid_window_index
        ));
    }

    if additional_window_count == 0 {
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(additional_window_count as usize);
    for offset in 1..=additional_window_count {
        let window_index = primary_window_index
            .checked_add(offset)
            .ok_or_else(|| "Overflow ao calcular janela de confirmação".to_string())?;
        ensure_window_index_in_total_range(bundle, window_index)?;
        if window_index > layout.last_confirmation_window_index {
            return Err(format!(
                "window_index {} excede last_confirmation_window_index={}",
                window_index, layout.last_confirmation_window_index
            ));
        }
        if window_index > layout.last_valid_window_index
            && !is_confirmation_only_window_index(&layout, window_index)
        {
            return Err(format!(
                "window_index {} inválido como confirmação",
                window_index
            ));
        }
        out.push(build_revocation_proof_for_window_with_levels(
            credential_id_local,
            bundle,
            window_index,
            merkle_levels,
        )?);
    }

    Ok(out)
}

pub fn build_revocation_proof_sequence_for_window(
    credential_id_local: &str,
    bundle: &HolderRevocationBundle,
    primary_window_index: u32,
    additional_window_count: u32,
) -> std::result::Result<RevocationProofSequence, String> {
    let merkle_levels = build_merkle_levels(&bundle.l_values)?;
    let primary_proof = {
        ensure_window_index_in_total_range(bundle, primary_window_index)?;
        let layout = window_layout_from_control(&bundle.control)?;
        if !is_validity_window_index(&layout, primary_window_index) {
            return Err(format!(
                "window_index {} é janela exclusiva de confirmação; last_valid_window_index={}",
                primary_window_index, layout.last_valid_window_index
            ));
        }
        build_revocation_proof_for_window_with_levels(
            credential_id_local,
            bundle,
            primary_window_index,
            &merkle_levels,
        )?
    };
    let confirmation_proofs = build_confirmation_revocation_proofs_with_levels(
        credential_id_local,
        bundle,
        primary_window_index,
        additional_window_count,
        &merkle_levels,
    )?;

    Ok(RevocationProofSequence {
        credential_id_local: credential_id_local.to_string(),
        cred_def_id: Some(bundle.cred_def_id.clone()),
        primary_proof,
        confirmation_proofs,
    })
}

#[napi]
impl IndyAgent {
    #[napi]
    pub fn store_received_revocable_credential(
        &self,
        env: Env,
        bundle_id_local: String,
        holder_bundle_json: String,
        credential_id_local: Option<String>,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let mut bundle: HolderRevocationBundle = serde_json::from_str(&holder_bundle_json)
                    .map_err(|e| {
                        napi::Error::from_reason(format!("holder_bundle_json inválido: {}", e))
                    })?;

                let credential_id_local = credential_id_local
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty());

                if let Some(credential_id) = credential_id_local.clone() {
                    bundle.credential_id = Some(credential_id);
                }

                let saved_id =
                    store_holder_revocation_bundle(&store, &bundle_id_local, &bundle).await?;

                let response = serde_json::json!({
                    "ok": true,
                    "bundle_id_local": saved_id,
                    "credential_id_local": bundle.credential_id,
                    "holder_bundle": bundle,
                });

                serde_json::to_string(&response).map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando resultado do bundle revogável: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn get_holder_revocation_bundle(
        &self,
        env: Env,
        bundle_id_local: String,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let bundle = get_holder_revocation_bundle(&store, &bundle_id_local)
                    .await?
                    .ok_or_else(|| {
                        napi::Error::from_reason(format!(
                            "Holder revocation bundle não encontrado: {}",
                            bundle_id_local
                        ))
                    })?;

                serde_json::to_string(&bundle).map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando holder revocation bundle: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn build_presentation_revocation_proof(
        &self,
        env: Env,
        bundle_id_local: String,
        window_index: u32,
        credential_id_local: Option<String>,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let bundle = get_holder_revocation_bundle(&store, &bundle_id_local)
                    .await?
                    .ok_or_else(|| {
                        napi::Error::from_reason(format!(
                            "Holder revocation bundle não encontrado: {}",
                            bundle_id_local
                        ))
                    })?;

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

                let proof = build_primary_revocation_proof_for_window(
                    &proof_credential_id,
                    &bundle,
                    window_index,
                )
                .map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro montando prova de revogação para apresentação: {}",
                        e
                    ))
                })?;

                let response = serde_json::json!({
                    "ok": true,
                    "bundle_id_local": bundle_id_local,
                    "credential_id_local": proof_credential_id,
                    "proof": proof,
                });

                serde_json::to_string(&response).map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando prova de revogação para apresentação: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn build_presentation_revocation_proof_v2(
        &self,
        env: Env,
        bundle_id_local: String,
        primary_window_index: u32,
        additional_window_count: Option<u32>,
        credential_id_local: Option<String>,
    ) -> Result<JsObject> {
        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                let bundle = get_holder_revocation_bundle(&store, &bundle_id_local)
                    .await?
                    .ok_or_else(|| {
                        napi::Error::from_reason(format!(
                            "Holder revocation bundle não encontrado: {}",
                            bundle_id_local
                        ))
                    })?;

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

                let proof_sequence = build_revocation_proof_sequence_for_window(
                    &proof_credential_id,
                    &bundle,
                    primary_window_index,
                    additional_window_count.unwrap_or(0),
                )
                .map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro montando sequência de prova de revogação: {}",
                        e
                    ))
                })?;

                let response = serde_json::json!({
                    "ok": true,
                    "bundle_id_local": bundle_id_local,
                    "credential_id_local": proof_credential_id,
                    "primary_window_index": primary_window_index,
                    "additional_window_count": additional_window_count.unwrap_or(0),
                    "proof_sequence": proof_sequence,
                });

                serde_json::to_string(&response).map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Erro serializando sequência de prova de revogação: {}",
                        e
                    ))
                })
            },
            |&mut env, data| env.create_string(&data),
        )
    }
}
