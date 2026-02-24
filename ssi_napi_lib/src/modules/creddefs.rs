// src/modules/creddefs.rs
use crate::IndyAgent;
use aries_askar::entry::EntryTag;
use napi::{Env, Error, JsObject, Result};
use napi_derive::napi;
use std::time::{SystemTime, UNIX_EPOCH};

// Imports de dados do Anoncreds
// use anoncreds::data_types::issuer_id::IssuerId;
// use anoncreds::data_types::schema::{AttributeNames, Schema, SchemaId as AnonSchemaId};
// use anoncreds::issuer::create_credential_definition;
// use anoncreds::types::{CredentialDefinitionConfig, SignatureType};

// Imports do Indy VDR para Ledger
use indy_vdr::config::PoolConfig;
// use indy_vdr::ledger::requests::cred_def::{
//     CredentialDefinition as VdrCredDefEnum, CredentialDefinitionV1 as VdrCredDefStruct,
// };
use indy_vdr::ledger::RequestBuilder;
use indy_vdr::pool::PoolBuilder;
use indy_vdr::pool::{PoolTransactions, ProtocolVersion};
use indy_vdr::utils::did::DidValue;

// Import de ID tipado para busca
use indy_data_types::CredentialDefinitionId;

use crate::modules::common::{make_creddef_local_id, now_ts, send_request_async, CredDefRecord};
use aries_askar::entry::TagFilter;

// ============================================================

#[napi]
impl IndyAgent {
    // =========================================================================
    //  CATÁLOGO LOCAL: CREDDEFS (SAVE/LIST/GET/IMPORT/EXPORT)
    // =========================================================================

    #[napi]
    pub async fn creddef_save_local(
        &self,
        issuer_did: String,
        schema_id: String,
        tag: String,
        support_revocation: bool,
        env_label: Option<String>,
    ) -> Result<String> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| Error::from_reason("Wallet fechada!"))?;

        let mut session = store
            .session(None)
            .await
            .map_err(|e| Error::from_reason(format!("Erro sessão: {}", e)))?;

        let envv = env_label.unwrap_or_else(|| "template".to_string());

        // ---------------------------------------------------------------------
        // IDEMPOTÊNCIA: se já existir (env, issuer_did, schema_id, tag), retorna.
        // ---------------------------------------------------------------------
        let filter = TagFilter::all_of(vec![
            TagFilter::is_eq("env", &envv),
            TagFilter::is_eq("issuer_did", &issuer_did),
            TagFilter::is_eq("schema_id", &schema_id),
            TagFilter::is_eq("tag", &tag),
        ]);

        let existing = session
            .fetch_all(
                Some("creddef_local"),
                Some(filter),
                None,
                None,
                false,
                false,
            )
            .await
            .map_err(|e| Error::from_reason(format!("Erro fetch_all creddef_local: {}", e)))?;

        if let Some(first) = existing.into_iter().next() {
            let json = String::from_utf8(first.value.to_vec()).unwrap_or_default();
            return Ok(json);
        }

        // ---------------------------------------------------------------------
        // Não existe -> cria novo
        // ---------------------------------------------------------------------
        let now = now_ts();
        let id_local = make_creddef_local_id();

        let rec = CredDefRecord {
            id_local: id_local.clone(),
            issuer_did: issuer_did.clone(),
            schema_id: schema_id.clone(),
            tag: tag.clone(),
            signature_type: "CL".to_string(),
            support_revocation,
            on_ledger: false,
            cred_def_id: None,
            env: envv.clone(),
            created_at: now,
            updated_at: now,
        };

        let json = serde_json::to_string(&rec)
            .map_err(|e| Error::from_reason(format!("Erro serializar creddef local: {}", e)))?;

        let tags = vec![
            EntryTag::Encrypted("on_ledger".to_string(), "false".to_string()),
            EntryTag::Encrypted("env".to_string(), envv),
            EntryTag::Encrypted("issuer_did".to_string(), issuer_did),
            EntryTag::Encrypted("schema_id".to_string(), schema_id),
            EntryTag::Encrypted("tag".to_string(), tag),
            EntryTag::Encrypted(
                "support_revocation".to_string(),
                if support_revocation { "true" } else { "false" }.to_string(),
            ),
            EntryTag::Encrypted("signature_type".to_string(), "CL".to_string()),
        ];

        session
            .insert(
                "creddef_local",
                &id_local,
                json.as_bytes(),
                Some(&tags),
                None,
            )
            .await
            .map_err(|e| Error::from_reason(format!("Erro salvar creddef local: {}", e)))?;

        session
            .commit()
            .await
            .map_err(|e| Error::from_reason(format!("Erro commit: {}", e)))?;

        Ok(json)
    }

    #[napi]
    pub fn creddef_get_local(&self, env: Env, id_local: String) -> Result<JsObject> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| Error::from_reason("Wallet fechada!"))?;

        env.execute_tokio_future(
            async move {
                let mut session = store
                    .session(None)
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro sessão: {}", e)))?;

                let entry = session
                    .fetch("creddef_local", &id_local, false)
                    .await
                    .map_err(|e| {
                        napi::Error::from_reason(format!("Erro fetch creddef_local: {}", e))
                    })?
                    .ok_or_else(|| napi::Error::from_reason("CredDef local não encontrada"))?;

                Ok(String::from_utf8(entry.value.to_vec()).unwrap_or_default())
            },
            |&mut env, json| {
                let mut obj = env.create_object()?;
                obj.set_named_property("ok", env.get_boolean(true)?)?;
                obj.set_named_property("json", env.create_string(&json)?)?;
                Ok(obj)
            },
        )
    }

    #[napi]
    pub async fn creddef_list_local(
        &self,
        on_ledger: Option<bool>,
        env_filter: Option<String>,
        issuer_did_eq: Option<String>,
        schema_id_eq: Option<String>,
        tag_eq: Option<String>,
    ) -> Result<Vec<String>> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| Error::from_reason("Wallet fechada!"))?;
        let mut session = store
            .session(None)
            .await
            .map_err(|e| Error::from_reason(format!("Erro sessão: {}", e)))?;

        let mut filter: Option<TagFilter> = None;

        if let Some(b) = on_ledger {
            filter = Some(TagFilter::is_eq(
                "on_ledger",
                if b { "true" } else { "false" },
            ));
        }
        if let Some(envv) = env_filter {
            let f2 = TagFilter::is_eq("env", &envv);
            filter = Some(match filter {
                Some(f1) => TagFilter::all_of(vec![f1, f2]),
                None => f2,
            });
        }
        if let Some(d) = issuer_did_eq {
            let f2 = TagFilter::is_eq("issuer_did", &d);
            filter = Some(match filter {
                Some(f1) => TagFilter::all_of(vec![f1, f2]),
                None => f2,
            });
        }
        if let Some(sid) = schema_id_eq {
            let f2 = TagFilter::is_eq("schema_id", &sid);
            filter = Some(match filter {
                Some(f1) => TagFilter::all_of(vec![f1, f2]),
                None => f2,
            });
        }
        if let Some(t) = tag_eq {
            let f2 = TagFilter::is_eq("tag", &t);
            filter = Some(match filter {
                Some(f1) => TagFilter::all_of(vec![f1, f2]),
                None => f2,
            });
        }

        let entries = session
            .fetch_all(Some("creddef_local"), filter, None, None, false, false)
            .await
            .map_err(|e| Error::from_reason(format!("Erro fetch_all creddef_local: {}", e)))?;

        Ok(entries
            .into_iter()
            .map(|e| String::from_utf8(e.value.to_vec()).unwrap_or_default())
            .collect())
    }

    #[napi]
    pub async fn creddef_export_local(&self, id_local: String) -> Result<String> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| Error::from_reason("Wallet fechada!"))?;
        let mut session = store
            .session(None)
            .await
            .map_err(|e| Error::from_reason(format!("Erro sessão: {}", e)))?;

        let entry = session
            .fetch("creddef_local", &id_local, false)
            .await
            .map_err(|e| Error::from_reason(format!("Erro fetch creddef_local: {}", e)))?
            .ok_or_else(|| Error::from_reason("CredDef local não encontrada"))?;

        Ok(String::from_utf8(entry.value.to_vec()).unwrap_or_default())
    }

    #[napi]
    pub async fn creddef_import_local(&self, json: String) -> Result<String> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| Error::from_reason("Wallet fechada!"))?;
        let mut session = store
            .session(None)
            .await
            .map_err(|e| Error::from_reason(format!("Erro sessão: {}", e)))?;

        let mut rec: CredDefRecord = serde_json::from_str(&json)
            .map_err(|e| Error::from_reason(format!("JSON inválido (CredDefRecord): {}", e)))?;

        // Normalizações mínimas
        if rec.signature_type.trim().is_empty() {
            rec.signature_type = "CL".to_string();
        }
        if rec.env.trim().is_empty() {
            rec.env = "template".to_string();
        }

        let now = now_ts();
        if rec.created_at <= 0 {
            rec.created_at = now;
        }
        rec.updated_at = now;

        // ---------------------------------------------------------------------
        // Política de colisão: NEW_ID (sempre que o id_local já existir)
        // ---------------------------------------------------------------------
        let mut id_to_use = rec.id_local.trim().to_string();
        if id_to_use.is_empty() {
            id_to_use = make_creddef_local_id();
        } else {
            let exists = session
                .fetch("creddef_local", &id_to_use, false)
                .await
                .map_err(|e| Error::from_reason(format!("Erro checando colisão: {}", e)))?
                .is_some();

            if exists {
                id_to_use = make_creddef_local_id();
            }
        }
        rec.id_local = id_to_use.clone();

        let json2 = serde_json::to_string(&rec)
            .map_err(|e| Error::from_reason(format!("Erro re-serializar creddef: {}", e)))?;

        let tags = vec![
            EntryTag::Encrypted(
                "on_ledger".to_string(),
                if rec.on_ledger { "true" } else { "false" }.to_string(),
            ),
            EntryTag::Encrypted("env".to_string(), rec.env.clone()),
            EntryTag::Encrypted("issuer_did".to_string(), rec.issuer_did.clone()),
            EntryTag::Encrypted("schema_id".to_string(), rec.schema_id.clone()),
            EntryTag::Encrypted("tag".to_string(), rec.tag.clone()),
            EntryTag::Encrypted(
                "support_revocation".to_string(),
                if rec.support_revocation {
                    "true"
                } else {
                    "false"
                }
                .to_string(),
            ),
            EntryTag::Encrypted("signature_type".to_string(), rec.signature_type.clone()),
        ];

        session
            .insert(
                "creddef_local",
                &rec.id_local,
                json2.as_bytes(),
                Some(&tags),
                None,
            )
            .await
            .map_err(|e| Error::from_reason(format!("Erro importar creddef_local: {}", e)))?;

        session
            .commit()
            .await
            .map_err(|e| Error::from_reason(format!("Erro commit: {}", e)))?;

        Ok(json2)
    }

    #[napi]
    pub async fn creddef_delete_local(&self, id_local: String) -> Result<bool> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| Error::from_reason("Wallet fechada!"))?;

        let mut session = store
            .session(None)
            .await
            .map_err(|e| Error::from_reason(format!("Erro sessão: {}", e)))?;

        // Se não existir, retorna false (sem erro)
        let exists = session
            .fetch("creddef_local", &id_local, false)
            .await
            .map_err(|e| Error::from_reason(format!("Erro fetch creddef_local: {}", e)))?
            .is_some();

        if !exists {
            return Ok(false);
        }

        session
            .remove("creddef_local", &id_local)
            .await
            .map_err(|e| Error::from_reason(format!("Erro remove creddef_local: {}", e)))?;

        session
            .commit()
            .await
            .map_err(|e| Error::from_reason(format!("Erro commit: {}", e)))?;

        Ok(true)
    }

    // =========================================================================
    //  CONSULTA DE CREDENTIAL DEFINITION (GET)
    // =========================================================================
    #[napi]
    pub fn fetch_cred_def_from_ledger(
        &self,
        env: Env,
        _genesis_path: String, // Mantido para compatibilidade, mas ignorado (usamos o pool conectado)
        cred_def_id: String,
    ) -> Result<JsObject> {
        // 1. Verificação de Conexão (Pool Compartilhado)
        let pool = match &self.pool {
            Some(p) => p.clone(), // Clone barato do Arc
            None => {
                return Err(Error::from_reason(
                    "Não conectado à rede. Execute connect_network antes.",
                ))
            }
        };

        // Opcional: Verificação da Wallet (Consistência)
        if self.store.is_none() {
            return Err(Error::from_reason("Wallet fechada!"));
        }

        env.execute_tokio_future(
            async move {
                // NÃO recriamos o pool. Usamos a conexão persistente.
                let rb = RequestBuilder::new(ProtocolVersion::Node1_4);

                // O ID da CredDef é tipado no Indy VDR
                let ledger_id = CredentialDefinitionId(cred_def_id.clone());

                let req = rb
                    .build_get_cred_def_request(None, &ledger_id)
                    .map_err(|e| {
                        napi::Error::from_reason(format!("Erro build GET request: {}", e))
                    })?;

                // Envio usando o pool compartilhado
                let response_str = send_request_async(&pool, req).await?;

                let json: serde_json::Value = serde_json::from_str(&response_str)
                    .map_err(|_e| napi::Error::from_reason("Erro parse JSON resposta"))?;

                // === VALIDAÇÃO (MANTIDA) ===
                // O Ledger retorna { result: { data: { ... } } }
                let result = &json["result"];

                if result["data"].is_null() {
                    return Err(napi::Error::from_reason(format!(
                        "CredDef {} não encontrada (data is null).",
                        cred_def_id
                    )));
                }

                // Opcional: Validação extra de 'seqNo' ou campos internos se desejar,
                // mas 'data' não nulo já é um forte indicador de sucesso.

                Ok(response_str)
            },
            |&mut env, data| env.create_string(&data),
        )
    }

    #[napi]
    pub fn creddef_register_from_local(
        &self,
        env: Env,
        genesis_path: String,
        id_local: String,
        issuer_did_opt: Option<String>,
    ) -> Result<JsObject> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| Error::from_reason("Wallet fechada!"))?;

        env.execute_tokio_future(
            async move {
                use anoncreds::data_types::issuer_id::IssuerId;
                use anoncreds::data_types::schema::{AttributeNames, Schema, SchemaId};
                use anoncreds::issuer::create_credential_definition;
                use anoncreds::types::{CredentialDefinitionConfig, SignatureType};

                use indy_vdr::ledger::requests::cred_def::{
                    CredentialDefinition as VdrCredDefEnum,
                    CredentialDefinitionV1 as VdrCredDefStruct,
                };

                // 1) pool + sessão
                let transactions = PoolTransactions::from_json_file(&genesis_path)
                    .map_err(|e| napi::Error::from_reason(format!("Erro genesis: {}", e)))?;
                let pool = PoolBuilder::new(PoolConfig::default(), transactions)
                    .into_runner(None)
                    .map_err(|e| napi::Error::from_reason(format!("Erro pool: {}", e)))?;

                let rb = RequestBuilder::new(ProtocolVersion::Node1_4);

                let mut session = store
                    .session(None)
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro sessão: {}", e)))?;

                // 2) carrega template local (creddef_local)
                let entry = session
                    .fetch("creddef_local", &id_local, false)
                    .await
                    .map_err(|e| {
                        napi::Error::from_reason(format!("Erro fetch creddef_local: {}", e))
                    })?
                    .ok_or_else(|| napi::Error::from_reason("CredDef local não encontrada"))?;

                let mut rec: CredDefRecord = serde_json::from_slice(&entry.value).map_err(|e| {
                    napi::Error::from_reason(format!("JSON creddef_local inválido: {}", e))
                })?;

                // 3) resolve issuer_did (override > record)
                let issuer_did = issuer_did_opt.unwrap_or_else(|| rec.issuer_did.clone());

                if issuer_did.trim().is_empty() {
                    return Err(napi::Error::from_reason(
                        "issuer_did vazio (override e record)",
                    ));
                }
                if rec.schema_id.trim().is_empty() {
                    return Err(napi::Error::from_reason("schema_id vazio no record local"));
                }
                if rec.tag.trim().is_empty() {
                    return Err(napi::Error::from_reason("tag vazio no record local"));
                }

                // 4) GET_SCHEMA para obter seqNo e dados do schema
                let schema_id_ledger =
                    indy_vdr::ledger::identifiers::SchemaId(rec.schema_id.clone());
                let get_schema_req = rb
                    .build_get_schema_request(None, &schema_id_ledger)
                    .map_err(|e| {
                        napi::Error::from_reason(format!("Erro build GET_SCHEMA: {}", e))
                    })?;

                let get_schema_resp = send_request_async(&pool, get_schema_req).await?;
                let get_schema_json: serde_json::Value = serde_json::from_str(&get_schema_resp)
                    .map_err(|e| {
                        napi::Error::from_reason(format!("Erro parse GET_SCHEMA: {}", e))
                    })?;

                let seq_no = get_schema_json["result"]["seqNo"].as_u64().ok_or_else(|| {
                    napi::Error::from_reason("SeqNo ausente (Schema não confirmado no ledger)")
                })?;

                // 5) cred_def_id determinístico (padrão indy)
                let cred_def_id = format!("{}:3:CL:{}:{}", issuer_did, seq_no, rec.tag);

                // 6) idempotência na wallet: se já existe, só atualiza o record local e retorna
                let already = session
                    .fetch("cred_def_private", &cred_def_id, false)
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro verificar wallet: {}", e)))?
                    .is_some();

                if already {
                    rec.on_ledger = true;
                    rec.cred_def_id = Some(cred_def_id.clone());
                    rec.env = "prod".to_string();
                    rec.updated_at = now_ts();

                    let json_updated = serde_json::to_string(&rec).map_err(|e| {
                        napi::Error::from_reason(format!("Erro serializar record: {}", e))
                    })?;

                    let tags = vec![
                        EntryTag::Encrypted("on_ledger".to_string(), "true".to_string()),
                        EntryTag::Encrypted("env".to_string(), "prod".to_string()),
                        EntryTag::Encrypted("issuer_did".to_string(), issuer_did.clone()),
                        EntryTag::Encrypted("schema_id".to_string(), rec.schema_id.clone()),
                        EntryTag::Encrypted("tag".to_string(), rec.tag.clone()),
                        EntryTag::Encrypted(
                            "support_revocation".to_string(),
                            if rec.support_revocation {
                                "true"
                            } else {
                                "false"
                            }
                            .to_string(),
                        ),
                        EntryTag::Encrypted(
                            "signature_type".to_string(),
                            rec.signature_type.clone(),
                        ),
                    ];

                    session
                        .replace(
                            "creddef_local",
                            &id_local,
                            json_updated.as_bytes(),
                            Some(&tags),
                            None,
                        )
                        .await
                        .map_err(|e| {
                            napi::Error::from_reason(format!("Erro atualizar creddef_local: {}", e))
                        })?;

                    session
                        .commit()
                        .await
                        .map_err(|e| napi::Error::from_reason(format!("Erro commit: {}", e)))?;

                    return Ok((cred_def_id, rec));
                }

                // 7) reconstrói Schema (Anoncreds) a partir do retorno do ledger
                let schema_data_val = &get_schema_json["result"]["data"];

                let schema_json_obj: serde_json::Value = if schema_data_val.is_string() {
                    serde_json::from_str(schema_data_val.as_str().unwrap()).map_err(|e| {
                        napi::Error::from_reason(format!("Erro parse Schema Data: {}", e))
                    })?
                } else {
                    schema_data_val.clone()
                };

                let name = schema_json_obj["name"].as_str().unwrap_or("").to_string();
                let version = schema_json_obj["version"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();

                let attr_vec: Vec<String> =
                    if let Some(arr) = schema_json_obj["attrNames"].as_array() {
                        arr.iter()
                            .map(|v| v.as_str().unwrap_or("").to_string())
                            .collect()
                    } else if let Some(arr) = schema_json_obj["attr_names"].as_array() {
                        arr.iter()
                            .map(|v| v.as_str().unwrap_or("").to_string())
                            .collect()
                    } else {
                        return Err(napi::Error::from_reason(
                            "Atributos não encontrados no Schema",
                        ));
                    };

                let schema_issuer_did = rec
                    .schema_id
                    .split(':')
                    .next()
                    .unwrap_or(&issuer_did)
                    .to_string();

                let schema_obj = Schema {
                    name,
                    version,
                    attr_names: AttributeNames(attr_vec),
                    issuer_id: IssuerId::new(schema_issuer_did).map_err(|e| {
                        napi::Error::from_reason(format!("IssuerID schema inválido: {}", e))
                    })?,
                };

                // 8) cria creddef (Anoncreds) com support_revocation do catálogo local
                let anon_schema_id = SchemaId::new(rec.schema_id.clone())
                    .map_err(|e| napi::Error::from_reason(format!("SchemaID inválido: {}", e)))?;

                let anon_issuer_id = IssuerId::new(issuer_did.clone())
                    .map_err(|e| napi::Error::from_reason(format!("IssuerID inválido: {}", e)))?;

                let config = CredentialDefinitionConfig {
                    support_revocation: rec.support_revocation,
                };

                let (cred_def_pub, cred_def_priv, key_proof) = create_credential_definition(
                    anon_schema_id,
                    &schema_obj,
                    anon_issuer_id,
                    &rec.tag,
                    SignatureType::CL,
                    config,
                )
                .map_err(|e| napi::Error::from_reason(format!("Erro criando CredDef: {}", e)))?;

                // 9) salva na wallet (priv + pub)
                let priv_json = serde_json::to_string(&cred_def_priv)
                    .map_err(|_| napi::Error::from_reason("Serializar priv"))?;
                let key_proof_json = serde_json::to_string(&key_proof)
                    .map_err(|_| napi::Error::from_reason("Serializar key_proof"))?;
                let pub_json = serde_json::to_string(&cred_def_pub)
                    .map_err(|_| napi::Error::from_reason("Serializar pub"))?;

                session
                    .insert(
                        "cred_def_private",
                        &cred_def_id,
                        priv_json.as_bytes(),
                        Some(&vec![EntryTag::Encrypted(
                            "key_proof".to_string(),
                            key_proof_json,
                        )]),
                        None,
                    )
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Save Private: {}", e)))?;

                session
                    .insert(
                        "cred_def",
                        &cred_def_id,
                        pub_json.as_bytes(),
                        Some(&vec![EntryTag::Encrypted(
                            "schema_id".to_string(),
                            rec.schema_id.clone(),
                        )]),
                        None,
                    )
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Save Public: {}", e)))?;

                // 10) publica no ledger (VDR)
                let mut cred_def_val = serde_json::to_value(&cred_def_pub)
                    .map_err(|e| napi::Error::from_reason(format!("Erro json value: {}", e)))?;

                if let Some(obj) = cred_def_val.as_object_mut() {
                    obj.insert("ver".to_string(), serde_json::json!("1.0"));
                    obj.insert("id".to_string(), serde_json::json!(cred_def_id.clone()));
                    obj.insert(
                        "schemaId".to_string(),
                        serde_json::json!(seq_no.to_string()),
                    );
                    obj.insert("type".to_string(), serde_json::json!("CL"));
                }

                let vdr_struct: VdrCredDefStruct =
                    serde_json::from_value(cred_def_val).map_err(|e| {
                        napi::Error::from_reason(format!("Erro convert VDR Struct: {}", e))
                    })?;

                let vdr_enum = VdrCredDefEnum::CredentialDefinitionV1(vdr_struct);

                let did_obj = DidValue(issuer_did.clone());
                let mut req = rb
                    .build_cred_def_request(&did_obj, vdr_enum)
                    .map_err(|e| napi::Error::from_reason(format!("Erro build req: {}", e)))?;

                // 11) TAA (igual seu create_and_register_cred_def)
                let taa_req = rb
                    .build_get_txn_author_agreement_request(None, None)
                    .map_err(|e| napi::Error::from_reason(format!("TAA req build: {}", e)))?;
                let taa_resp = send_request_async(&pool, taa_req).await?;
                let taa_val: serde_json::Value = serde_json::from_str(&taa_resp)
                    .map_err(|_| napi::Error::from_reason("TAA parse error"))?;

                if let Some(res) = taa_val.get("result") {
                    if let Some(data) = res.get("data") {
                        if !data.is_null() {
                            let text = data.get("text").and_then(|t| t.as_str());
                            let version = data.get("version").and_then(|v| v.as_str());
                            let digest = data.get("digest").and_then(|d| d.as_str());

                            if let (Some(t), Some(v)) = (text, version) {
                                let ts = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                let ts_midnight = (ts / 86400) * 86400;

                                let taa = rb
                                    .prepare_txn_author_agreement_acceptance_data(
                                        Some(t),
                                        Some(v),
                                        digest,
                                        "wallet_agreement",
                                        ts_midnight,
                                    )
                                    .map_err(|e| {
                                        napi::Error::from_reason(format!("TAA prep: {}", e))
                                    })?;
                                req.set_txn_author_agreement_acceptance(&taa).map_err(|e| {
                                    napi::Error::from_reason(format!("TAA set: {}", e))
                                })?;
                            }
                        }
                    }
                }

                // 12) assina e envia
                let did_entry = session
                    .fetch("did", &issuer_did, false)
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Fetch DID: {}", e)))?
                    .ok_or_else(|| napi::Error::from_reason("DID issuer não achado"))?;

                let did_json_val: serde_json::Value = serde_json::from_slice(&did_entry.value)
                    .map_err(|_| napi::Error::from_reason("DID JSON inválido"))?;
                let verkey = did_json_val["verkey"]
                    .as_str()
                    .ok_or_else(|| napi::Error::from_reason("Campo verkey ausente no DID"))?;

                let key_entry = session
                    .fetch_key(verkey, false)
                    .await
                    .map_err(|_| napi::Error::from_reason("Fetch key error"))?
                    .ok_or_else(|| napi::Error::from_reason("Chave privada não achada"))?;

                let signer_key = key_entry
                    .load_local_key()
                    .map_err(|_| napi::Error::from_reason("Load key error"))?;

                let sig_input = req
                    .get_signature_input()
                    .map_err(|e| napi::Error::from_reason(format!("Sig input error: {}", e)))?;
                let signature = signer_key
                    .sign_message(sig_input.as_bytes(), None)
                    .map_err(|e| napi::Error::from_reason(format!("Sign error: {}", e)))?;

                req.set_signature(&signature)
                    .map_err(|e| napi::Error::from_reason(format!("Set sig error: {}", e)))?;

                let _resp = send_request_async(&pool, req).await?;

                // 13) atualiza catálogo local (marca como prod + ledger)
                rec.on_ledger = true;
                rec.cred_def_id = Some(cred_def_id.clone());
                rec.env = "prod".to_string();
                rec.issuer_did = issuer_did.clone();
                rec.updated_at = now_ts();

                let json_updated = serde_json::to_string(&rec).map_err(|e| {
                    napi::Error::from_reason(format!("Erro serializar record: {}", e))
                })?;

                let tags = vec![
                    EntryTag::Encrypted("on_ledger".to_string(), "true".to_string()),
                    EntryTag::Encrypted("env".to_string(), "prod".to_string()),
                    EntryTag::Encrypted("issuer_did".to_string(), issuer_did),
                    EntryTag::Encrypted("schema_id".to_string(), rec.schema_id.clone()),
                    EntryTag::Encrypted("tag".to_string(), rec.tag.clone()),
                    EntryTag::Encrypted(
                        "support_revocation".to_string(),
                        if rec.support_revocation {
                            "true"
                        } else {
                            "false"
                        }
                        .to_string(),
                    ),
                    EntryTag::Encrypted("signature_type".to_string(), rec.signature_type.clone()),
                ];

                session
                    .replace(
                        "creddef_local",
                        &id_local,
                        json_updated.as_bytes(),
                        Some(&tags),
                        None,
                    )
                    .await
                    .map_err(|e| {
                        napi::Error::from_reason(format!("Erro atualizar creddef_local: {}", e))
                    })?;

                session
                    .commit()
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Commit: {}", e)))?;

                Ok((cred_def_id, rec))
            },
            |&mut env, (cred_def_id, rec)| {
                let mut obj = env.create_object()?;
                obj.set_named_property("ok", env.get_boolean(true)?)?;
                obj.set_named_property("credDefId", env.create_string(&cred_def_id)?)?;
                obj.set_named_property(
                    "json",
                    env.create_string(&serde_json::to_string(&rec).unwrap_or_default())?,
                )?;
                Ok(obj)
            },
        )
    }

    #[napi]
    pub async fn creddef_set_env_local(&self, id_local: String, env_new: String) -> Result<String> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| Error::from_reason("Wallet fechada!"))?;

        let mut session = store
            .session(None)
            .await
            .map_err(|e| Error::from_reason(format!("Erro sessão: {}", e)))?;

        let entry = session
            .fetch("creddef_local", &id_local, false)
            .await
            .map_err(|e| Error::from_reason(format!("Erro fetch creddef_local: {}", e)))?
            .ok_or_else(|| Error::from_reason("CredDef local não encontrada"))?;

        let mut rec: CredDefRecord = serde_json::from_slice(&entry.value)
            .map_err(|e| Error::from_reason(format!("JSON creddef_local inválido: {}", e)))?;

        if env_new.trim().is_empty() {
            return Err(Error::from_reason("env_new vazio"));
        }

        rec.env = env_new.clone();
        rec.updated_at = now_ts();

        let json_updated = serde_json::to_string(&rec)
            .map_err(|e| Error::from_reason(format!("Erro serializar record: {}", e)))?;

        let tags = vec![
            EntryTag::Encrypted(
                "on_ledger".to_string(),
                if rec.on_ledger { "true" } else { "false" }.to_string(),
            ),
            EntryTag::Encrypted("env".to_string(), rec.env.clone()),
            EntryTag::Encrypted("issuer_did".to_string(), rec.issuer_did.clone()),
            EntryTag::Encrypted("schema_id".to_string(), rec.schema_id.clone()),
            EntryTag::Encrypted("tag".to_string(), rec.tag.clone()),
            EntryTag::Encrypted(
                "support_revocation".to_string(),
                if rec.support_revocation {
                    "true"
                } else {
                    "false"
                }
                .to_string(),
            ),
            EntryTag::Encrypted("signature_type".to_string(), rec.signature_type.clone()),
        ];

        session
            .replace(
                "creddef_local",
                &id_local,
                json_updated.as_bytes(),
                Some(&tags),
                None,
            )
            .await
            .map_err(|e| Error::from_reason(format!("Erro atualizar creddef_local: {}", e)))?;

        session
            .commit()
            .await
            .map_err(|e| Error::from_reason(format!("Erro commit: {}", e)))?;

        Ok(json_updated)
    }

    #[napi]
    pub async fn creddef_mark_on_ledger_local(
        &self,
        id_local: String,
        cred_def_id: String,
    ) -> Result<String> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| Error::from_reason("Wallet fechada!"))?;

        let mut session = store
            .session(None)
            .await
            .map_err(|e| Error::from_reason(format!("Erro sessão: {}", e)))?;

        let entry = session
            .fetch("creddef_local", &id_local, false)
            .await
            .map_err(|e| Error::from_reason(format!("Erro fetch creddef_local: {}", e)))?
            .ok_or_else(|| Error::from_reason("CredDef local não encontrada"))?;

        let mut rec: CredDefRecord = serde_json::from_slice(&entry.value)
            .map_err(|e| Error::from_reason(format!("JSON creddef_local inválido: {}", e)))?;

        if cred_def_id.trim().is_empty() {
            return Err(Error::from_reason("cred_def_id vazio"));
        }

        rec.on_ledger = true;
        rec.cred_def_id = Some(cred_def_id);
        rec.env = "prod".to_string();
        rec.updated_at = now_ts();

        let json_updated = serde_json::to_string(&rec)
            .map_err(|e| Error::from_reason(format!("Erro serializar record: {}", e)))?;

        let tags = vec![
            EntryTag::Encrypted("on_ledger".to_string(), "true".to_string()),
            EntryTag::Encrypted("env".to_string(), rec.env.clone()),
            EntryTag::Encrypted("issuer_did".to_string(), rec.issuer_did.clone()),
            EntryTag::Encrypted("schema_id".to_string(), rec.schema_id.clone()),
            EntryTag::Encrypted("tag".to_string(), rec.tag.clone()),
            EntryTag::Encrypted(
                "support_revocation".to_string(),
                if rec.support_revocation {
                    "true"
                } else {
                    "false"
                }
                .to_string(),
            ),
            EntryTag::Encrypted("signature_type".to_string(), rec.signature_type.clone()),
        ];

        session
            .replace(
                "creddef_local",
                &id_local,
                json_updated.as_bytes(),
                Some(&tags),
                None,
            )
            .await
            .map_err(|e| Error::from_reason(format!("Erro atualizar creddef_local: {}", e)))?;

        session
            .commit()
            .await
            .map_err(|e| Error::from_reason(format!("Erro commit: {}", e)))?;

        Ok(json_updated)
    }

    #[napi]
    pub async fn creddef_get_local_by_cred_def_id(&self, cred_def_id: String) -> Result<String> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| Error::from_reason("Wallet fechada!"))?;

        if cred_def_id.trim().is_empty() {
            return Err(Error::from_reason("cred_def_id vazio"));
        }

        let mut session = store
            .session(None)
            .await
            .map_err(|e| Error::from_reason(format!("Erro sessão: {}", e)))?;

        // 1) Fast path: tag filter (se você gravou cred_def_id como tag)
        let filter = TagFilter::is_eq("cred_def_id", &cred_def_id);

        let found = session
            .fetch_all(
                Some("creddef_local"),
                Some(filter),
                None,
                None,
                false,
                false,
            )
            .await
            .map_err(|e| Error::from_reason(format!("Erro fetch_all: {}", e)))?;

        if let Some(first) = found.into_iter().next() {
            let json = String::from_utf8(first.value.to_vec()).unwrap_or_default();
            return Ok(json);
        }

        // 2) Fallback: varredura (compat com registros antigos sem tag cred_def_id)
        let all = session
            .fetch_all(Some("creddef_local"), None, None, None, false, false)
            .await
            .map_err(|e| Error::from_reason(format!("Erro fetch_all (scan): {}", e)))?;

        for it in all {
            if let Ok(rec) = serde_json::from_slice::<CredDefRecord>(&it.value) {
                if rec.cred_def_id.as_deref() == Some(&cred_def_id) {
                    return Ok(String::from_utf8(it.value.to_vec()).unwrap_or_default());
                }
            }
        }

        Err(Error::from_reason(
            "CredDef local não encontrada para este cred_def_id",
        ))
    }

    #[napi]
    pub async fn creddef_list_local_view_cursor(
        &self,
        mode: String,           // "compact" | "full"
        cursor: Option<String>, // id_local do último item retornado
        limit: u32,             // page size
        on_ledger: Option<bool>,
        env_label: Option<String>,
        issuer_did: Option<String>,
        schema_id: Option<String>,
        tag: Option<String>,
    ) -> Result<String> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| Error::from_reason("Wallet fechada!"))?;

        let mut session = store
            .session(None)
            .await
            .map_err(|e| Error::from_reason(format!("Erro sessão: {}", e)))?;

        // Monta TagFilter "all_of" conforme parâmetros fornecidos
        let mut filters: Vec<TagFilter> = vec![];

        if let Some(v) = on_ledger {
            filters.push(TagFilter::is_eq(
                "on_ledger",
                if v { "true" } else { "false" },
            ));
        }
        if let Some(v) = env_label.as_ref().filter(|s| !s.trim().is_empty()) {
            filters.push(TagFilter::is_eq("env", v));
        }
        if let Some(v) = issuer_did.as_ref().filter(|s| !s.trim().is_empty()) {
            filters.push(TagFilter::is_eq("issuer_did", v));
        }
        if let Some(v) = schema_id.as_ref().filter(|s| !s.trim().is_empty()) {
            filters.push(TagFilter::is_eq("schema_id", v));
        }
        if let Some(v) = tag.as_ref().filter(|s| !s.trim().is_empty()) {
            filters.push(TagFilter::is_eq("tag", v));
        }

        let filter = if filters.is_empty() {
            None
        } else {
            Some(TagFilter::all_of(filters))
        };

        let rows = session
            .fetch_all(Some("creddef_local"), filter, None, None, false, false)
            .await
            .map_err(|e| Error::from_reason(format!("Erro fetch_all creddef_local: {}", e)))?;

        // Parse + coleta
        let mut recs: Vec<CredDefRecord> = vec![];
        for r in rows {
            if let Ok(rec) = serde_json::from_slice::<CredDefRecord>(&r.value) {
                recs.push(rec);
            }
        }

        // Ordena por id_local para paginação estável
        recs.sort_by(|a, b| a.id_local.cmp(&b.id_local));

        // Aplica cursor (id_local > cursor)
        let start_idx = if let Some(c) = cursor.as_ref().filter(|s| !s.trim().is_empty()) {
            match recs.binary_search_by(|r| r.id_local.cmp(c)) {
                Ok(i) => i + 1, // começa depois do cursor
                Err(i) => i,    // primeira posição onde entraria -> já é ">" cursor
            }
        } else {
            0
        };

        let lim = if limit == 0 { 25 } else { limit as usize };
        let slice = recs
            .into_iter()
            .skip(start_idx)
            .take(lim)
            .collect::<Vec<_>>();

        let next_cursor = slice.last().map(|r| r.id_local.clone());

        // Monta items compact/full
        let mode_lc = mode.to_lowercase();
        let items_val = if mode_lc == "compact" {
            let mut v = vec![];
            for r in &slice {
                v.push(serde_json::json!({
                    "id_local": r.id_local,
                    "issuer_did": r.issuer_did,
                    "schema_id": r.schema_id,
                    "tag": r.tag,
                    "env": r.env,
                    "on_ledger": r.on_ledger,
                    "cred_def_id": r.cred_def_id,
                    "support_revocation": r.support_revocation,
                    "signature_type": r.signature_type,
                    "updated_at": r.updated_at
                }));
            }
            serde_json::Value::Array(v)
        } else {
            serde_json::to_value(&slice)
                .map_err(|e| Error::from_reason(format!("Erro serializar items full: {}", e)))?
        };

        let out = serde_json::json!({
            "ok": true,
            "mode": if mode_lc == "compact" { "compact" } else { "full" },
            "cursor": cursor,
            "limit": lim,
            "next_cursor": next_cursor,
            "items": items_val
        });

        Ok(out.to_string())
    }

    #[napi]
    pub async fn creddef_list_local_view_cursor_v2(
        &self,
        mode: String,           // "compact" | "full"
        cursor: Option<String>, // id_local OU "updated_at|id_local"
        limit: u32,             // page size
        on_ledger: Option<bool>,
        env_label: Option<String>,
        issuer_did: Option<String>,
        schema_id: Option<String>,
        tag: Option<String>,
        order_by: Option<String>, // "id_local" (default) | "updated_at_desc"
    ) -> Result<String> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| Error::from_reason("Wallet fechada!"))?;

        let mut session = store
            .session(None)
            .await
            .map_err(|e| Error::from_reason(format!("Erro sessão: {}", e)))?;

        // ---- filtros via tags (mesma lógica do v1) ----
        let mut filters: Vec<TagFilter> = vec![];

        if let Some(v) = on_ledger {
            filters.push(TagFilter::is_eq(
                "on_ledger",
                if v { "true" } else { "false" },
            ));
        }
        if let Some(v) = env_label.as_ref().filter(|s| !s.trim().is_empty()) {
            filters.push(TagFilter::is_eq("env", v));
        }
        if let Some(v) = issuer_did.as_ref().filter(|s| !s.trim().is_empty()) {
            filters.push(TagFilter::is_eq("issuer_did", v));
        }
        if let Some(v) = schema_id.as_ref().filter(|s| !s.trim().is_empty()) {
            filters.push(TagFilter::is_eq("schema_id", v));
        }
        if let Some(v) = tag.as_ref().filter(|s| !s.trim().is_empty()) {
            filters.push(TagFilter::is_eq("tag", v));
        }

        let filter = if filters.is_empty() {
            None
        } else {
            Some(TagFilter::all_of(filters))
        };

        let rows = session
            .fetch_all(Some("creddef_local"), filter, None, None, false, false)
            .await
            .map_err(|e| Error::from_reason(format!("Erro fetch_all creddef_local: {}", e)))?;

        let mut recs: Vec<CredDefRecord> = vec![];
        for r in rows {
            if let Ok(rec) = serde_json::from_slice::<CredDefRecord>(&r.value) {
                recs.push(rec);
            }
        }

        let lim = if limit == 0 { 25 } else { limit as usize };
        let mode_lc = mode.to_lowercase();
        let order = order_by
            .unwrap_or_else(|| "id_local".to_string())
            .to_lowercase();

        // =====================================================================
        // ORDER BY: updated_at_desc (cursor composto "ts|id_local")
        // =====================================================================
        if order == "updated_at_desc" {
            // ordenação estável: updated_at DESC, id_local ASC
            recs.sort_by(|a, b| {
                match b.updated_at.cmp(&a.updated_at) {
                    // desc
                    std::cmp::Ordering::Equal => a.id_local.cmp(&b.id_local), // asc
                    other => other,
                }
            });

            // aplica cursor composto
            let (cur_ts, cur_id) = if let Some(c) = cursor.as_ref().filter(|s| !s.trim().is_empty())
            {
                let parts: Vec<&str> = c.split('|').collect();
                if parts.len() == 2 {
                    let ts = parts[0].parse::<i64>().unwrap_or(i64::MAX);
                    let id = parts[1].to_string();
                    (Some(ts), Some(id))
                } else {
                    // se vier cursor antigo, ignora e começa do topo
                    (None, None)
                }
            } else {
                (None, None)
            };

            let filtered: Vec<CredDefRecord> = if let (Some(ts), Some(id)) = (cur_ts, cur_id) {
                recs.into_iter()
                    .filter(|r| (r.updated_at < ts) || (r.updated_at == ts && r.id_local > id))
                    .collect()
            } else {
                recs
            };

            let slice: Vec<CredDefRecord> = filtered.into_iter().take(lim).collect();
            let next_cursor = slice
                .last()
                .map(|r| format!("{}|{}", r.updated_at, r.id_local));

            let items_val = if mode_lc == "compact" {
                let mut v = vec![];
                for r in &slice {
                    v.push(serde_json::json!({
                        "id_local": r.id_local,
                        "issuer_did": r.issuer_did,
                        "schema_id": r.schema_id,
                        "tag": r.tag,
                        "env": r.env,
                        "on_ledger": r.on_ledger,
                        "cred_def_id": r.cred_def_id,
                        "support_revocation": r.support_revocation,
                        "signature_type": r.signature_type,
                        "updated_at": r.updated_at
                    }));
                }
                serde_json::Value::Array(v)
            } else {
                serde_json::to_value(&slice)
                    .map_err(|e| Error::from_reason(format!("Erro serializar items full: {}", e)))?
            };

            let out = serde_json::json!({
                "ok": true,
                "mode": if mode_lc == "compact" { "compact" } else { "full" },
                "order_by": "updated_at_desc",
                "cursor": cursor,
                "limit": lim,
                "next_cursor": next_cursor,
                "items": items_val
            });

            return Ok(out.to_string());
        }

        // =====================================================================
        // ORDER BY: id_local (mesmo comportamento do v1) - cursor é id_local
        // =====================================================================
        recs.sort_by(|a, b| a.id_local.cmp(&b.id_local));

        let start_idx = if let Some(c) = cursor.as_ref().filter(|s| !s.trim().is_empty()) {
            match recs.binary_search_by(|r| r.id_local.cmp(c)) {
                Ok(i) => i + 1,
                Err(i) => i,
            }
        } else {
            0
        };

        let slice = recs
            .into_iter()
            .skip(start_idx)
            .take(lim)
            .collect::<Vec<_>>();
        let next_cursor = slice.last().map(|r| r.id_local.clone());

        let items_val = if mode_lc == "compact" {
            let mut v = vec![];
            for r in &slice {
                v.push(serde_json::json!({
                    "id_local": r.id_local,
                    "issuer_did": r.issuer_did,
                    "schema_id": r.schema_id,
                    "tag": r.tag,
                    "env": r.env,
                    "on_ledger": r.on_ledger,
                    "cred_def_id": r.cred_def_id,
                    "support_revocation": r.support_revocation,
                    "signature_type": r.signature_type,
                    "updated_at": r.updated_at
                }));
            }
            serde_json::Value::Array(v)
        } else {
            serde_json::to_value(&slice)
                .map_err(|e| Error::from_reason(format!("Erro serializar items full: {}", e)))?
        };

        let out = serde_json::json!({
            "ok": true,
            "mode": if mode_lc == "compact" { "compact" } else { "full" },
            "order_by": "id_local",
            "cursor": cursor,
            "limit": lim,
            "next_cursor": next_cursor,
            "items": items_val
        });

        Ok(out.to_string())
    }

    // =========================================================================
    //  11. EMISSÃO: CRIAR CRED DEF (CORRIGIDO: IMPORTS DATA_TYPES)
    // =========================================================================
    #[napi]
    pub fn create_and_register_cred_def(
        &self,
        env: Env,
        genesis_path: String,
        issuer_did: String,
        schema_id: String,
        tag: String,
    ) -> Result<JsObject> {
        // 1. IMPORTS CORRIGIDOS (SEPARADOS POR MÓDULO CORRETO)

        // A. Estruturas de Dados (Schema, ID, Atributos) -> data_types
        use anoncreds::data_types::issuer_id::IssuerId;
        use anoncreds::data_types::schema::{AttributeNames, Schema, SchemaId};

        // B. Configuração e Tipos de Assinatura -> types (conforme tentativas anteriores)
        // Se der erro aqui, mova para data_types::cred_def
        use anoncreds::types::{CredentialDefinitionConfig, SignatureType};

        use anoncreds::issuer::create_credential_definition;

        // C. VDR Imports
        use indy_vdr::ledger::requests::cred_def::{
            CredentialDefinition as VdrCredDefEnum, CredentialDefinitionV1 as VdrCredDefStruct,
        };

        let store = match &self.store {
            Some(s) => s.clone(),
            None => return Err(Error::from_reason("Wallet fechada!")),
        };

        env.execute_tokio_future(
            async move {
                // 2. Pool e Sessão
                let transactions = PoolTransactions::from_json_file(&genesis_path)
                    .map_err(|e| napi::Error::from_reason(format!("Erro genesis: {}", e)))?;
                let pool = PoolBuilder::new(PoolConfig::default(), transactions)
                    .into_runner(None)
                    .map_err(|e| napi::Error::from_reason(format!("Erro pool: {}", e)))?;
                let rb = RequestBuilder::new(ProtocolVersion::Node1_4);

                let mut session = store
                    .session(None)
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro sessão: {}", e)))?;

                // 3. GET_SCHEMA
                let schema_id_ledger = indy_vdr::ledger::identifiers::SchemaId(schema_id.clone());
                let get_schema_req = rb
                    .build_get_schema_request(None, &schema_id_ledger)
                    .map_err(|e| {
                        napi::Error::from_reason(format!("Erro build GET_SCHEMA: {}", e))
                    })?;

                let get_schema_resp = send_request_async(&pool, get_schema_req).await?;
                let get_schema_json: serde_json::Value = serde_json::from_str(&get_schema_resp)
                    .map_err(|e| {
                        napi::Error::from_reason(format!("Erro parse GET_SCHEMA: {}", e))
                    })?;

                let seq_no = get_schema_json["result"]["seqNo"].as_u64().ok_or_else(|| {
                    napi::Error::from_reason("SeqNo ausente (Schema não confirmado)")
                })?;

                // 4. ID Determinístico
                let cred_def_id = format!("{}:3:CL:{}:{}", issuer_did, seq_no, tag);

                // 5. Idempotência
                if session
                    .fetch("cred_def_private", &cred_def_id, false)
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Erro verificar wallet: {}", e)))?
                    .is_some()
                {
                    return Ok(cred_def_id);
                }

                // 6. Reconstruir Schema
                let schema_data_val = &get_schema_json["result"]["data"];

                let schema_json_obj: serde_json::Value = if schema_data_val.is_string() {
                    serde_json::from_str(schema_data_val.as_str().unwrap()).map_err(|e| {
                        napi::Error::from_reason(format!("Erro parse Schema Data: {}", e))
                    })?
                } else {
                    schema_data_val.clone()
                };

                let name = schema_json_obj["name"].as_str().unwrap_or("").to_string();
                let version = schema_json_obj["version"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();

                let attr_vec: Vec<String> =
                    if let Some(arr) = schema_json_obj["attrNames"].as_array() {
                        arr.iter()
                            .map(|v| v.as_str().unwrap_or("").to_string())
                            .collect()
                    } else if let Some(arr) = schema_json_obj["attr_names"].as_array() {
                        arr.iter()
                            .map(|v| v.as_str().unwrap_or("").to_string())
                            .collect()
                    } else {
                        return Err(napi::Error::from_reason(
                            "Atributos não encontrados no Schema",
                        ));
                    };

                let schema_issuer_did = schema_id
                    .split(':')
                    .next()
                    .unwrap_or(&issuer_did)
                    .to_string();

                // CORREÇÃO: Usamos o wrapper AttributeNames(vec) importado corretamente
                let schema_obj = Schema {
                    name,
                    version,
                    attr_names: AttributeNames(attr_vec),
                    issuer_id: IssuerId::new(schema_issuer_did).map_err(|e| {
                        napi::Error::from_reason(format!("IssuerID schema inválido: {}", e))
                    })?,
                };

                // 7. Criar Cred Def (Anoncreds)
                let anon_schema_id = SchemaId::new(schema_id.clone())
                    .map_err(|e| napi::Error::from_reason(format!("SchemaID inválido: {}", e)))?;

                let anon_issuer_id = IssuerId::new(issuer_did.clone())
                    .map_err(|e| napi::Error::from_reason(format!("IssuerID inválido: {}", e)))?;

                let config = CredentialDefinitionConfig {
                    support_revocation: false,
                };

                let (cred_def_pub, cred_def_priv, key_proof) = create_credential_definition(
                    anon_schema_id,
                    &schema_obj,
                    anon_issuer_id,
                    &tag,
                    SignatureType::CL,
                    config,
                )
                .map_err(|e| {
                    napi::Error::from_reason(format!("Erro criando CredDef Maths: {}", e))
                })?;

                // 8. Salvar na Wallet
                let priv_json = serde_json::to_string(&cred_def_priv)
                    .map_err(|_| napi::Error::from_reason("Serializar priv"))?;
                let key_proof_json = serde_json::to_string(&key_proof)
                    .map_err(|_| napi::Error::from_reason("Serializar key_proof"))?;
                let pub_json = serde_json::to_string(&cred_def_pub)
                    .map_err(|_| napi::Error::from_reason("Serializar pub"))?;

                session
                    .insert(
                        "cred_def_private",
                        &cred_def_id,
                        priv_json.as_bytes(),
                        Some(&vec![EntryTag::Encrypted(
                            "key_proof".to_string(),
                            key_proof_json,
                        )]),
                        None,
                    )
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Save Private: {}", e)))?;

                session
                    .insert(
                        "cred_def",
                        &cred_def_id,
                        pub_json.as_bytes(),
                        Some(&vec![EntryTag::Encrypted(
                            "schema_id".to_string(),
                            schema_id.clone(),
                        )]),
                        None,
                    )
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Save Public: {}", e)))?;

                // 9. Publicar no VDR
                let mut cred_def_val = serde_json::to_value(&cred_def_pub)
                    .map_err(|e| napi::Error::from_reason(format!("Erro json value: {}", e)))?;

                if let Some(obj) = cred_def_val.as_object_mut() {
                    obj.insert("ver".to_string(), serde_json::json!("1.0"));
                    obj.insert("id".to_string(), serde_json::json!(cred_def_id.clone()));
                    obj.insert(
                        "schemaId".to_string(),
                        serde_json::json!(seq_no.to_string()),
                    );
                    obj.insert("type".to_string(), serde_json::json!("CL"));
                }

                let vdr_struct: VdrCredDefStruct =
                    serde_json::from_value(cred_def_val).map_err(|e| {
                        napi::Error::from_reason(format!("Erro convert VDR Struct: {}", e))
                    })?;

                let vdr_enum = VdrCredDefEnum::CredentialDefinitionV1(vdr_struct);

                let did_obj = DidValue(issuer_did.clone());
                let mut req = rb
                    .build_cred_def_request(&did_obj, vdr_enum)
                    .map_err(|e| napi::Error::from_reason(format!("Erro build req: {}", e)))?;

                // 10. TAA
                let taa_req = rb
                    .build_get_txn_author_agreement_request(None, None)
                    .map_err(|e| napi::Error::from_reason(format!("TAA req build: {}", e)))?;
                let taa_resp = send_request_async(&pool, taa_req).await?;
                let taa_val: serde_json::Value = serde_json::from_str(&taa_resp)
                    .map_err(|_| napi::Error::from_reason("TAA parse error"))?;

                if let Some(res) = taa_val.get("result") {
                    if let Some(data) = res.get("data") {
                        if !data.is_null() {
                            let text = data.get("text").and_then(|t| t.as_str());
                            let version = data.get("version").and_then(|v| v.as_str());
                            let digest = data.get("digest").and_then(|d| d.as_str());

                            if let (Some(t), Some(v)) = (text, version) {
                                let ts = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs();
                                let ts_midnight = (ts / 86400) * 86400;
                                let taa = rb
                                    .prepare_txn_author_agreement_acceptance_data(
                                        Some(t),
                                        Some(v),
                                        digest,
                                        "wallet_agreement",
                                        ts_midnight,
                                    )
                                    .map_err(|e| {
                                        napi::Error::from_reason(format!("TAA prep: {}", e))
                                    })?;
                                req.set_txn_author_agreement_acceptance(&taa).map_err(|e| {
                                    napi::Error::from_reason(format!("TAA set: {}", e))
                                })?;
                            }
                        }
                    }
                }

                // 11. Assinar e Enviar
                let did_entry = session
                    .fetch("did", &issuer_did, false)
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Fetch DID: {}", e)))?
                    .ok_or_else(|| napi::Error::from_reason("DID issuer não achado"))?;

                let did_json_val: serde_json::Value =
                    serde_json::from_slice(&did_entry.value).unwrap();
                let verkey = did_json_val["verkey"].as_str().unwrap();

                let key_entry = session
                    .fetch_key(verkey, false)
                    .await
                    .map_err(|_| napi::Error::from_reason("Fetch key error"))?
                    .ok_or_else(|| napi::Error::from_reason("Chave privada não achada"))?;

                let signer_key = key_entry
                    .load_local_key()
                    .map_err(|_| napi::Error::from_reason("Load key error"))?;

                let signature = signer_key
                    .sign_message(req.get_signature_input().unwrap().as_bytes(), None)
                    .map_err(|e| napi::Error::from_reason(format!("Sign error: {}", e)))?;

                req.set_signature(&signature)
                    .map_err(|e| napi::Error::from_reason(format!("Set sig error: {}", e)))?;

                let _resp = send_request_async(&pool, req).await?;

                session
                    .commit()
                    .await
                    .map_err(|e| napi::Error::from_reason(format!("Commit: {}", e)))?;

                Ok(cred_def_id)
            },
            |&mut env, data| env.create_string(&data),
        )
    }
}
