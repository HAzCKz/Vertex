use argon2::Algorithm;
use argon2::Argon2;
use argon2::Params;
use argon2::Version;
use aries_askar::Store;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use indy_vdr::ledger::RequestBuilder;
use indy_vdr::pool::ProtocolVersion;
use indy_vdr::utils::did::DidValue;
use napi::{Error, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;
use sha3::Sha3_256;
use std::fs;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

// Helpers Schemas >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

#[derive(Debug, Serialize, Deserialize)]
pub struct SchemaRecord {
    pub id_local: String,
    pub name: String,
    pub version: String,
    pub attr_names: Vec<String>,       // atributos da credencial
    pub revocable: bool,               // se usa controle do holder
    pub final_attr_names: Vec<String>, // attr_names + CONTROL_ATTRS (se revocable)
    pub on_ledger: bool,
    pub schema_id: Option<String>, // quando on_ledger=true
    pub issuer_did: Option<String>,
    pub env: String, // "prod" | "test" | "template"
    pub created_at: i64,
    pub updated_at: i64,
}

// Helpers CredDefs >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#[derive(Debug, Serialize, Deserialize)]
pub struct CredDefRecord {
    pub id_local: String,
    pub issuer_did: String,

    // >>> ADICIONAR ESTES 2:
    pub schema_id: String,
    pub tag: String,

    pub signature_type: String, // "CL" (padrão anoncreds)
    pub support_revocation: bool,
    pub on_ledger: bool,
    pub cred_def_id: Option<String>,
    pub env: String, // "prod" | "test" | "template"
    pub created_at: i64,
    pub updated_at: i64,
}

pub fn make_creddef_local_id() -> String {
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    format!("local:creddef:{}", bs58::encode(buf).into_string())
}

pub const CONFIG_CATEGORY: &str = "config";
pub const KEY_DEFAULT_SCHEMA_ISSUER_DID: &str = "default_schema_issuer_did";

pub fn napi_err(code: &str, message: impl Into<String>) -> napi::Error {
    napi::Error::from_reason(
        serde_json::json!({
            "ok": false,
            "code": code,
            "message": message.into()
        })
        .to_string(),
    )
}

pub fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn make_schema_local_id() -> String {
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    format!("local:{}", bs58::encode(buf).into_string())
}

pub const CONTROL_ATTRS: [&str; 5] = [
    "seed",
    "start_time",
    "unit_of_time",
    "time_window",
    "root_merkle_L",
];

pub fn is_reserved_control_attr(a: &str) -> bool {
    CONTROL_ATTRS.iter().any(|x| x.eq_ignore_ascii_case(a))
}

pub fn build_final_attr_names(mut user_attrs: Vec<String>, revocable: bool) -> Result<Vec<String>> {
    use std::collections::HashSet;

    let mut seen = HashSet::<String>::new();
    for a in &user_attrs {
        let k = a.trim().to_string();
        if k.is_empty() {
            return Err(Error::from_reason("Atributo vazio não é permitido"));
        }
        if is_reserved_control_attr(&k) {
            return Err(Error::from_reason(format!(
                "Atributo reservado de controle não pode ser definido manualmente: {}",
                k
            )));
        }
        let norm = k.to_lowercase();
        if !seen.insert(norm) {
            return Err(Error::from_reason(format!("Atributo duplicado: {}", k)));
        }
    }

    if revocable {
        for c in CONTROL_ATTRS {
            user_attrs.push(c.to_string());
        }
    }
    Ok(user_attrs)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletKdfSidecar {
    pub version: u32,
    pub kdf: String,

    // Argon2id
    pub salt_b64: Option<String>,
    pub m_cost_kib: Option<u32>,
    pub t_cost: Option<u32>,
    pub p_cost: Option<u32>,
    pub dk_len: Option<u32>,

    // Legado
    pub rounds: Option<u32>,
}

pub fn sidecar_path_for(wallet_path: &str) -> String {
    format!("{}.kdf.json", wallet_path)
}

pub fn write_sidecar(path: &str, sc: &WalletKdfSidecar) -> napi::Result<()> {
    let tmp = format!("{}.tmp", path);
    let content = serde_json::to_vec_pretty(sc)
        .map_err(|e| napi_err("SidecarSerializeFailed", e.to_string()))?;
    fs::write(&tmp, content).map_err(|e| napi_err("SidecarWriteFailed", e.to_string()))?;
    fs::rename(&tmp, path).map_err(|e| napi_err("SidecarRenameFailed", e.to_string()))?;
    Ok(())
}

pub fn read_sidecar(path: &str) -> napi::Result<WalletKdfSidecar> {
    let content = fs::read(path).map_err(|e| napi_err("SidecarReadFailed", e.to_string()))?;
    serde_json::from_slice(&content).map_err(|e| napi_err("SidecarParseFailed", e.to_string()))
}

// KDF legado (SHA256 + SHA3 em loop) — usado apenas para abrir wallets antigas.
pub fn derive_raw_key_legacy(password: &str, rounds: u32) -> String {
    let mut current_bytes = password.as_bytes().to_vec();
    for _ in 0..rounds {
        let mut hasher2 = Sha256::new();
        hasher2.update(&current_bytes);
        current_bytes = hasher2.finalize().to_vec();

        let mut hasher3 = Sha3_256::new();
        hasher3.update(&current_bytes);
        current_bytes = hasher3.finalize().to_vec();
    }
    bs58::encode(current_bytes).into_string()
}

pub fn derive_raw_key_argon2id(
    password: &str,
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> napi::Result<String> {
    let params = Params::new(m_cost_kib, t_cost, p_cost, Some(32))
        .map_err(|e| napi_err("Argon2ParamsInvalid", e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| napi_err("Argon2DeriveFailed", e.to_string()))?;

    Ok(bs58::encode(out).into_string())
}

pub fn derive_raw_key_from_sidecar(password: &str, sc: &WalletKdfSidecar) -> napi::Result<String> {
    match sc.kdf.as_str() {
        "argon2id" => {
            let salt_b64 = sc
                .salt_b64
                .as_ref()
                .ok_or_else(|| napi_err("KdfParamsMissing", "salt_b64 ausente"))?;
            let salt = B64
                .decode(salt_b64)
                .map_err(|e| napi_err("KdfParamsInvalid", e.to_string()))?;
            let m = sc.m_cost_kib.unwrap_or(65536);
            let t = sc.t_cost.unwrap_or(3);
            let p = sc.p_cost.unwrap_or(1);
            derive_raw_key_argon2id(password, &salt, m, t, p)
        }
        "legacy_sha256_sha3" => {
            let rounds = sc.rounds.unwrap_or(128);
            Ok(derive_raw_key_legacy(password, rounds))
        }
        other => Err(napi_err(
            "KdfUnknown",
            format!("KDF não suportado: {other}"),
        )),
    }
}

pub fn default_argon2_sidecar() -> (WalletKdfSidecar, [u8; 16]) {
    // Defaults conservadores (desktop): 64 MiB, 3 iterações, 1 thread.
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let sc = WalletKdfSidecar {
        version: 1,
        kdf: "argon2id".to_string(),
        salt_b64: Some(B64.encode(salt)),
        m_cost_kib: Some(65536),
        t_cost: Some(3),
        p_cost: Some(1),
        dk_len: Some(32),
        rounds: None,
    };
    (sc, salt)
}

pub fn is_wallet_auth_error(msg: &str) -> bool {
    // Erros típicos quando a chave derivada não bate (senha errada / KDF errado)
    msg.contains("AEAD decryption error")
        || msg.contains("Error decrypting profile key")
        || msg.contains("decrypting profile key")
}

/// Best-effort: remove artefatos de wallet para evitar "wallet órfã"
/// (db criada, mas sidecar não escrito).
pub fn cleanup_wallet_files(wallet_path: &str, sidecar_path: &str) {
    // db principal
    let _ = std::fs::remove_file(wallet_path);
    // sidecar
    let _ = std::fs::remove_file(sidecar_path);
    // sqlite journaling (quando aplicável)
    let _ = std::fs::remove_file(format!("{}-wal", wallet_path));
    let _ = std::fs::remove_file(format!("{}-shm", wallet_path));
    // temporários possíveis
    let _ = std::fs::remove_file(format!("{}.tmp", sidecar_path));
}

// =============================================================================
// 1. HELPER (CORRIGIDO) - Coloque fora do "impl IndyAgent"
// =============================================================================
pub async fn send_request_async(
    client: &indy_vdr::pool::PoolRunner,
    req: indy_vdr::pool::PreparedRequest,
) -> napi::Result<String> {
    // CORREÇÃO: Usamos um canal OneShot do Tokio (Async) em vez de MPSC (Sync)
    let (tx, rx) = tokio::sync::oneshot::channel();

    // O callback do Indy-VDR é chamado quando a resposta chega.
    // Enviamos o resultado para o canal.
    client
        .send_request(
            req,
            Box::new(move |res| {
                // Se o receptor (rx) já tiver sido dropado (timeout/cancelamento),
                // o send falha, mas aqui ignoramos o erro (let _).
                let _ = tx.send(res);
            }),
        )
        .map_err(|e| napi::Error::from_reason(format!("Erro interno VDR (Send): {}", e)))?;

    // AGUARDAR RESPOSTA (AWAIT)
    // Aqui está a mágica: o .await libera a thread do Tokio para fazer outras coisas
    // enquanto o Ledger não responde. Não há bloqueio de CPU.
    let vdr_return_result = rx.await.map_err(|_| {
        napi::Error::from_reason("Erro: Canal de resposta fechado inesperadamente (Dropped)")
    })?;

    // Processar o resultado do VDR
    let (res, _meta) = vdr_return_result
        .map_err(|e| napi::Error::from_reason(format!("Erro retornado pelo Ledger/VDR: {}", e)))?;

    match res {
        indy_vdr::pool::RequestResult::Reply(body) => Ok(body),
        indy_vdr::pool::RequestResult::Failed(e) => Err(napi::Error::from_reason(format!(
            "Transação rejeitada pelo Ledger: {:?}",
            e
        ))),
    }
}

pub async fn write_attrib_raw_async(
    store: &Store,
    pool: &indy_vdr::pool::PoolRunner,
    did: &str,
    key: &str,
    value: &str,
) -> napi::Result<String> {
    let rb = RequestBuilder::new(ProtocolVersion::Node1_4);

    let taa_req = rb
        .build_get_txn_author_agreement_request(None, None)
        .map_err(|e| napi::Error::from_reason(format!("Erro TAA req: {}", e)))?;

    let taa_resp = send_request_async(pool, taa_req).await?;
    let taa_val: serde_json::Value = serde_json::from_str(&taa_resp)
        .map_err(|e| napi::Error::from_reason(format!("Erro JSON TAA: {}", e)))?;

    let taa_acceptance = if !taa_val["result"]["data"].is_null() {
        let text = taa_val["result"]["data"]["text"].as_str();
        let version = taa_val["result"]["data"]["version"].as_str();
        let digest = taa_val["result"]["data"]["digest"].as_str();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Some(
            rb.prepare_txn_author_agreement_acceptance_data(
                text,
                version,
                digest,
                "wallet_agreement",
                ts,
            )
            .map_err(|e| napi::Error::from_reason(format!("Erro TAA data: {}", e)))?,
        )
    } else {
        None
    };

    let did_obj = DidValue(did.to_string());
    let raw_obj = serde_json::json!({
        key: value
    });

    let mut req = rb
        .build_attrib_request(&did_obj, &did_obj, None, Some(&raw_obj), None)
        .map_err(|e| napi::Error::from_reason(format!("Erro build ATTRIB: {}", e)))?;

    if let Some(taa) = taa_acceptance {
        req.set_txn_author_agreement_acceptance(&taa)
            .map_err(|e| napi::Error::from_reason(format!("Erro set TAA: {}", e)))?;
    }

    let mut session = store
        .session(None)
        .await
        .map_err(|e| napi::Error::from_reason(format!("Erro sessão: {}", e)))?;

    let did_entry = session
        .fetch("did", did, false)
        .await
        .map_err(|e| napi::Error::from_reason(format!("Erro fetch DID: {}", e)))?
        .ok_or_else(|| napi::Error::from_reason("DID não encontrado na wallet"))?;

    let did_json: serde_json::Value = serde_json::from_slice(&did_entry.value)
        .map_err(|e| napi::Error::from_reason(format!("DID JSON corrompido: {}", e)))?;

    let verkey_ref = did_json["verkey"]
        .as_str()
        .ok_or_else(|| napi::Error::from_reason("DID sem verkey"))?;

    let key_entry = session
        .fetch_key(verkey_ref, false)
        .await
        .map_err(|e| napi::Error::from_reason(format!("Erro fetch key: {}", e)))?
        .ok_or_else(|| napi::Error::from_reason("Chave privada não encontrada"))?;

    let local_key = key_entry
        .load_local_key()
        .map_err(|e| napi::Error::from_reason(format!("Erro load key: {}", e)))?;

    let signature_input = req
        .get_signature_input()
        .map_err(|e| napi::Error::from_reason(format!("Erro sig input: {}", e)))?;

    let signature = local_key
        .sign_message(signature_input.as_bytes(), None)
        .map_err(|e| napi::Error::from_reason(format!("Erro assinar: {}", e)))?;

    req.set_signature(&signature)
        .map_err(|e| napi::Error::from_reason(format!("Erro set sig: {}", e)))?;

    send_request_async(pool, req).await
}

pub async fn read_attrib_raw_async(
    pool: &indy_vdr::pool::PoolRunner,
    target_did: &str,
    key: &str,
) -> napi::Result<String> {
    let rb = RequestBuilder::new(ProtocolVersion::Node1_4);
    let target = DidValue(target_did.to_string());

    let req = rb
        .build_get_attrib_request(None, &target, Some(key.to_string()), None, None, None, None)
        .map_err(|e| napi::Error::from_reason(format!("Erro build GET_ATTRIB: {}", e)))?;

    let response_str = send_request_async(pool, req).await?;
    let json: serde_json::Value = serde_json::from_str(&response_str)
        .map_err(|e| napi::Error::from_reason(format!("Erro parse JSON resposta: {}", e)))?;

    let data_field = &json["result"]["data"];

    let inner_json: serde_json::Value = if data_field.is_string() {
        serde_json::from_str(data_field.as_str().unwrap_or("{}")).map_err(|e| {
            napi::Error::from_reason(format!("Erro parse dados internos string: {}", e))
        })?
    } else if data_field.is_object() {
        data_field.clone()
    } else {
        return Err(napi::Error::from_reason(format!(
            "Atributo '{}' não encontrado (data null/invalido) para DID {}",
            key, target_did
        )));
    };

    if let Some(val) = inner_json.get(key) {
        if let Some(s) = val.as_str() {
            Ok(s.to_string())
        } else {
            Ok(val.to_string())
        }
    } else {
        Err(napi::Error::from_reason(format!(
            "Chave '{}' não encontrada no payload do atributo",
            key
        )))
    }
}
