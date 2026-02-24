// src/modules/wallets.rs
use crate::modules::common::napi_err; // Importa o utilitário que movemos
use crate::IndyAgent;
use aes_gcm::{aead::Aead, aead::KeyInit, Aes256Gcm};
use aries_askar::{PassKey, Store, StoreKeyMethod};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use napi::Result;
use napi_derive::napi;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::path::Path;

use serde_json::Value;

// Re-importando tipos internos necessários para a lógica de KDF
use crate::modules::common::{
    cleanup_wallet_files, default_argon2_sidecar, derive_raw_key_argon2id,
    derive_raw_key_from_sidecar, derive_raw_key_legacy, is_wallet_auth_error, read_sidecar,
    sidecar_path_for, write_sidecar, WalletKdfSidecar,
};

#[napi]
impl IndyAgent {
    // --- MÉTODOS DE WALLET (Askar) ---
    #[napi]
    pub async unsafe fn wallet_create(&mut self, path: String, pass: String) -> Result<String> {
        // 1) Validação básica
        if path.trim().is_empty() {
            return Err(napi_err("WalletPathInvalid", "wallet path vazio"));
        }

        let wallet_db_path = Path::new(&path);
        let sidecar_path = sidecar_path_for(&path);

        // Garante que o diretório existe
        if let Some(parent) = wallet_db_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| napi_err("WalletPathCreateDirFailed", e.to_string()))?;
            }
        }

        // Evita sobrescrever wallet existente
        if wallet_db_path.exists() || Path::new(&sidecar_path).exists() {
            return Err(napi_err(
                "WalletAlreadyExists",
                "wallet já existe (db e/ou sidecar já presentes)",
            ));
        }

        // 2) Gera KDF (Argon2id) + raw key
        let (sc, salt) = default_argon2_sidecar();
        let raw_key_string = derive_raw_key_argon2id(
            &pass,
            &salt,
            sc.m_cost_kib.unwrap_or(65536),
            sc.t_cost.unwrap_or(3),
            sc.p_cost.unwrap_or(1),
        )?;

        // 3) Cria o SQLite cifrado (Askar)
        let config_uri = format!("sqlite://{}", path);
        Store::provision(
            &config_uri,
            StoreKeyMethod::RawKey,
            PassKey::from(raw_key_string),
            None,
            false, // não recriar por cima
        )
        .await
        .map_err(|e| napi_err("WalletCreateFailed", e.to_string()))?;

        // 4) Persiste sidecar (salt + params)
        if let Err(e) = write_sidecar(&sidecar_path, &sc) {
            // Evita ficar com DB criada sem sidecar (inconsistência)
            cleanup_wallet_files(&path, &sidecar_path);
            return Err(e);
        }

        Ok("Carteira criada com sucesso!".to_string())
    }

    #[napi]
    pub async unsafe fn wallet_open(&mut self, path: String, pass: String) -> Result<String> {
        if path.trim().is_empty() {
            return Err(napi_err("WalletPathInvalid", "wallet path vazio"));
        }

        // Se o DB não existe, não faz sentido cair em KdfParamsMissing.
        // Retorna um erro claro de "wallet não encontrada".
        let wallet_db_path = std::path::Path::new(&path);
        if !wallet_db_path.exists() {
            return Err(napi_err(
                "WalletNotFound",
                format!("wallet db não encontrada ({})", path),
            ));
        }

        let config_uri = format!("sqlite://{}", path);
        self.connection_uri = config_uri.clone();

        let sidecar_path = sidecar_path_for(&path);
        let sc = if Path::new(&sidecar_path).exists() {
            Some(read_sidecar(&sidecar_path)?)
        } else {
            None
        };

        // 1) Deriva raw key a partir do sidecar (ou tenta modo legado para migração)
        let (raw_key_string, opened_with_legacy) = if let Some(sc) = &sc {
            (derive_raw_key_from_sidecar(&pass, sc)?, false)
        } else {
            // Compatibilidade: tenta abrir como legacy (wallets antigas)
            (derive_raw_key_legacy(&pass, 128), true)
        };

        // 2) Abre store
        let store_res = Store::open(
            &config_uri,
            Some(StoreKeyMethod::RawKey),
            PassKey::from(raw_key_string),
            None,
        )
        .await;

        let store = match store_res {
            Ok(s) => s,
            Err(e) => {
                let emsg = e.to_string();

                // Se NÃO há sidecar, a política principal é: sidecar obrigatório.
                // Não misture com "detalhe de decrypt", porque isso só confunde.
                if sc.is_none() {
                    return Err(napi_err(
                        "KdfParamsMissing",
                        format!(
        "sidecar ausente ({}). Para wallets criadas nesta versão, o sidecar é obrigatório.",
        sidecar_path
      ),
                    ));
                }

                // Se HÁ sidecar e deu AEAD decryption error => senha errada (ou chave derivada errada)
                if is_wallet_auth_error(&emsg) {
                    return Err(napi_err(
                        "WalletAuthFailed",
                        "Senha incorreta (falha na decifragem da chave da wallet).",
                    ));
                }

                // Outros erros reais de abertura
                return Err(napi_err("WalletOpenFailed", emsg));
            }
        };

        // 3) Migração automática: se abriu como legacy e sidecar não existia, cria sidecar legacy
        if opened_with_legacy && sc.is_none() {
            let legacy_sc = WalletKdfSidecar {
                version: 1,
                kdf: "legacy_sha256_sha3".to_string(),
                salt_b64: None,
                m_cost_kib: None,
                t_cost: None,
                p_cost: None,
                dk_len: None,
                rounds: Some(128),
            };
            // Best-effort: se falhar, não impede a abertura
            let _ = write_sidecar(&sidecar_path, &legacy_sc);
        }

        // Sessão global removida corretamente aqui
        self.store = Some(store);

        Ok("Conectado ao SQLite nativo com sucesso!".to_string())
    }

    #[napi]
    pub async unsafe fn wallet_close(&mut self) -> Result<bool> {
        // REMOVIDO: self.session = None; (Campo não existe mais)

        // Fecha o Store (libera o handle do arquivo SQLite)
        self.store = None;

        // Libera o Pool de conexão com o Ledger
        self.pool = None;

        Ok(true)
    }

    // ---------------------------------------------------------------------
    // BACKUP DE SENHA DA WALLET (arquivo separado cifrado com AES-256-GCM)
    // ---------------------------------------------------------------------
    #[napi]
    pub fn wallet_backup_create(
        &self,
        wallet_pass: String,
        backup_pass: String,
        backup_file_path: String,
    ) -> Result<bool> {
        if backup_file_path.trim().is_empty() {
            return Err(napi_err("BackupPathInvalid", "backup_file_path vazio"));
        }

        // 1) KDF (Argon2id) para chave de backup
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let key_b58 = derive_raw_key_argon2id(&backup_pass, &salt, 65536, 3, 1)?;

        // key_b58 é base58 de 32 bytes; decodificamos para bytes
        let key_bytes = bs58::decode(key_b58)
            .into_vec()
            .map_err(|e| napi_err("BackupKeyDecodeFailed", e.to_string()))?;
        if key_bytes.len() != 32 {
            return Err(napi_err(
                "BackupKeyInvalid",
                "chave derivada não tem 32 bytes",
            ));
        }

        // 2) AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| napi_err("BackupCipherInitFailed", e.to_string()))?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let ciphertext = cipher
            .encrypt((&nonce).into(), wallet_pass.as_bytes())
            .map_err(|e| napi_err("BackupEncryptFailed", e.to_string()))?;

        // 3) Persistência (JSON)
        let payload = serde_json::json!({
            "version": 1,
            "kdf": "argon2id",
            "salt_b64": B64.encode(salt),
            "m_cost_kib": 65536,
            "t_cost": 3,
            "p_cost": 1,
            "nonce_b64": B64.encode(nonce),
            "ct_b64": B64.encode(ciphertext),
        });

        let tmp = format!("{}.tmp", backup_file_path);
        let bytes = serde_json::to_vec_pretty(&payload)
            .map_err(|e| napi_err("BackupSerializeFailed", e.to_string()))?;
        fs::write(&tmp, bytes).map_err(|e| napi_err("BackupWriteFailed", e.to_string()))?;
        fs::rename(&tmp, &backup_file_path)
            .map_err(|e| napi_err("BackupRenameFailed", e.to_string()))?;

        Ok(true)
    }

    #[napi]
    pub fn wallet_backup_recover(
        &self,
        backup_pass: String,
        backup_file_path: String,
    ) -> Result<String> {
        let content =
            fs::read(&backup_file_path).map_err(|e| napi_err("BackupReadFailed", e.to_string()))?;
        let v: serde_json::Value = serde_json::from_slice(&content)
            .map_err(|e| napi_err("BackupParseFailed", e.to_string()))?;

        let salt_b64 = v["salt_b64"]
            .as_str()
            .ok_or_else(|| napi_err("BackupFormatInvalid", "salt_b64 ausente"))?;
        let nonce_b64 = v["nonce_b64"]
            .as_str()
            .ok_or_else(|| napi_err("BackupFormatInvalid", "nonce_b64 ausente"))?;
        let ct_b64 = v["ct_b64"]
            .as_str()
            .ok_or_else(|| napi_err("BackupFormatInvalid", "ct_b64 ausente"))?;

        let salt = B64
            .decode(salt_b64)
            .map_err(|e| napi_err("BackupFormatInvalid", e.to_string()))?;
        let nonce = B64
            .decode(nonce_b64)
            .map_err(|e| napi_err("BackupFormatInvalid", e.to_string()))?;
        let ct = B64
            .decode(ct_b64)
            .map_err(|e| napi_err("BackupFormatInvalid", e.to_string()))?;

        if nonce.len() != 12 {
            return Err(napi_err("BackupNonceInvalid", "nonce deve ter 12 bytes"));
        }

        // Deriva key e decripta
        let key_b58 = derive_raw_key_argon2id(&backup_pass, &salt, 65536, 3, 1)?;
        let key_bytes = bs58::decode(key_b58)
            .into_vec()
            .map_err(|e| napi_err("BackupKeyDecodeFailed", e.to_string()))?;
        if key_bytes.len() != 32 {
            return Err(napi_err(
                "BackupKeyInvalid",
                "chave derivada não tem 32 bytes",
            ));
        }
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| napi_err("BackupCipherInitFailed", e.to_string()))?;

        let pt = cipher
            .decrypt((&nonce[..]).into(), ct.as_ref())
            .map_err(|e| napi_err("BackupDecryptFailed", e.to_string()))?;

        String::from_utf8(pt).map_err(|e| napi_err("BackupPlaintextInvalid", e.to_string()))
    }

    #[napi]
    pub async unsafe fn wallet_verify_pass(&mut self, path: String, pass: String) -> Result<bool> {
        if path.trim().is_empty() {
            return Err(napi_err("WalletPathInvalid", "wallet path vazio"));
        }

        let wallet_db_path = std::path::Path::new(&path);
        if !wallet_db_path.exists() {
            return Err(napi_err(
                "WalletNotFound",
                format!("wallet db não encontrada ({})", path),
            ));
        }

        // não mexe no estado do agente (self.store). É uma verificação "stateless".
        let config_uri = format!("sqlite://{}", path);
        let sidecar_path = sidecar_path_for(&path);

        let sc = if std::path::Path::new(&sidecar_path).exists() {
            Some(read_sidecar(&sidecar_path)?)
        } else {
            None
        };

        let (raw_key_string, _opened_with_legacy) = if let Some(sc) = &sc {
            (derive_raw_key_from_sidecar(&pass, sc)?, false)
        } else {
            // tenta legacy (migração)
            (derive_raw_key_legacy(&pass, 128), true)
        };

        let store_res = Store::open(
            &config_uri,
            Some(StoreKeyMethod::RawKey),
            PassKey::from(raw_key_string),
            None,
        )
        .await;

        match store_res {
            Ok(s) => {
                // best-effort close (não altera UX se falhar)
                let _ = s.close().await;
                Ok(true)
            }
            Err(e) => {
                let emsg = e.to_string();

                if sc.is_none() {
                    // mesma política do wallet_open: sidecar obrigatório para wallets novas
                    return Err(napi_err(
                        "KdfParamsMissing",
                        format!(
                            "sidecar ausente ({}). Para wallets criadas nesta versão, o sidecar é obrigatório.",
                            sidecar_path
                        ),
                    ));
                }

                if is_wallet_auth_error(&emsg) {
                    return Ok(false);
                }

                Err(napi_err("WalletOpenFailed", emsg))
            }
        }
    }

    #[napi]
    pub async unsafe fn wallet_change_pass(
        &mut self,
        path: String,
        old_pass: String,
        new_pass: String,
    ) -> Result<bool> {
        if path.trim().is_empty() {
            return Err(napi_err("WalletPathInvalid", "wallet path vazio"));
        }

        if self.store.is_some() {
            return Err(napi_err(
                "WalletAlreadyOpen",
                "feche a wallet atual antes de trocar a senha (walletClose)",
            ));
        }

        let wallet_db_path = std::path::Path::new(&path);
        if !wallet_db_path.exists() {
            return Err(napi_err(
                "WalletNotFound",
                format!("wallet db não encontrada ({})", path),
            ));
        }

        let config_uri = format!("sqlite://{}", path);
        let sidecar_path = sidecar_path_for(&path);

        let sc_old = if std::path::Path::new(&sidecar_path).exists() {
            Some(read_sidecar(&sidecar_path)?)
        } else {
            None
        };

        // 1) Deriva chave antiga (sidecar ou legacy) e abre store
        let (raw_key_old, _opened_with_legacy) = if let Some(sc) = &sc_old {
            (derive_raw_key_from_sidecar(&old_pass, sc)?, false)
        } else {
            (derive_raw_key_legacy(&old_pass, 128), true)
        };

        let mut store = match Store::open(
            &config_uri,
            Some(StoreKeyMethod::RawKey),
            PassKey::from(raw_key_old),
            None,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                let emsg = e.to_string();

                if sc_old.is_none() {
                    return Err(napi_err(
                        "KdfParamsMissing",
                        format!(
                            "sidecar ausente ({}). Para wallets criadas nesta versão, o sidecar é obrigatório.",
                            sidecar_path
                        ),
                    ));
                }

                if is_wallet_auth_error(&emsg) {
                    return Err(napi_err(
                        "WalletAuthFailed",
                        "Senha atual incorreta (falha na decifragem da chave da wallet).",
                    ));
                }

                return Err(napi_err("WalletOpenFailed", emsg));
            }
        };

        // 2) Deriva chave nova (novo sidecar Argon2id)
        let (sc_new, salt_new) = default_argon2_sidecar();
        let raw_key_new = derive_raw_key_argon2id(
            &new_pass,
            &salt_new,
            sc_new.m_cost_kib.unwrap_or(65536),
            sc_new.t_cost.unwrap_or(3),
            sc_new.p_cost.unwrap_or(1),
        )?;

        // 3) Rekey no store (troca wrapping key)
        store
            .rekey(StoreKeyMethod::RawKey, PassKey::from(raw_key_new))
            .await
            .map_err(|e| napi_err("WalletRekeyFailed", e.to_string()))?;

        // 4) Persistir sidecar novo (após rekey ter dado certo)
        write_sidecar(&sidecar_path, &sc_new)?;

        // best-effort close
        let _ = store.close().await;

        Ok(true)
    }

    // ---------------------------------------------------------------------
    // EXPORT/IMPORT COMPLETO DA WALLET (DB + SIDECAR + WAL/SHM opcional)
    // Bundle criptografado: Argon2id + AES-256-GCM
    // ---------------------------------------------------------------------

    #[napi]
    pub fn wallet_export_bundle(
        &self,
        wallet_path: String,
        out_bundle_path: String,
        export_passphrase: String,
    ) -> Result<bool> {
        if wallet_path.trim().is_empty() {
            return Err(napi_err("WalletPathInvalid", "wallet_path vazio"));
        }
        if out_bundle_path.trim().is_empty() {
            return Err(napi_err("BundlePathInvalid", "out_bundle_path vazio"));
        }
        if export_passphrase.is_empty() {
            return Err(napi_err("BundlePassInvalid", "export_passphrase vazio"));
        }

        // Recomendação prática: export somente com wallet fechada no agente atual.
        // (Se quiser permitir export arbitrário mesmo com store aberto, remova este guard.)
        // Aqui mantemos conservador para não exportar DB em uso.
        // OBS: isso trava apenas se ESTA instância tiver store aberto (qualquer wallet).
        // Se você preferir, pode remover.
        // if self.store.is_some() { ... }
        // Eu prefiro manter:
        if self.store.is_some() {
            return Err(napi_err(
                "WalletAlreadyOpen",
                "feche a wallet antes de exportar (walletClose)",
            ));
        }

        let db_path = std::path::Path::new(&wallet_path);
        if !db_path.exists() {
            return Err(napi_err(
                "WalletNotFound",
                format!("wallet db não encontrada ({})", wallet_path),
            ));
        }

        let sidecar_path = sidecar_path_for(&wallet_path);
        if !std::path::Path::new(&sidecar_path).exists() {
            return Err(napi_err(
                "KdfParamsMissing",
                format!("sidecar ausente ({}). Export exige sidecar.", sidecar_path),
            ));
        }

        // Lê arquivos principais
        let db_bytes =
            fs::read(&wallet_path).map_err(|e| napi_err("BundleReadDbFailed", e.to_string()))?;
        let sidecar_bytes = fs::read(&sidecar_path)
            .map_err(|e| napi_err("BundleReadSidecarFailed", e.to_string()))?;

        // WAL/SHM são opcionais (se existirem)
        let wal_path = format!("{}-wal", wallet_path);
        let shm_path = format!("{}-shm", wallet_path);

        let wal_bytes = fs::read(&wal_path).ok();
        let shm_bytes = fs::read(&shm_path).ok();

        // Conteúdo interno (plaintext) em JSON
        let inner = serde_json::json!({
            "version": 1,
            "meta": {
                "wallet_path": wallet_path,
                "sidecar_path": sidecar_path,
            },
            "files": {
                "db_b64": B64.encode(db_bytes),
                "sidecar_json_utf8": String::from_utf8_lossy(&sidecar_bytes).to_string(),
                "wal_b64": wal_bytes.as_ref().map(|b| B64.encode(b)),
                "shm_b64": shm_bytes.as_ref().map(|b| B64.encode(b)),
            }
        });

        let inner_bytes = serde_json::to_vec(&inner)
            .map_err(|e| napi_err("BundleSerializeInnerFailed", e.to_string()))?;

        // KDF do bundle (Argon2id) -> chave 32 bytes (base58 -> bytes)
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        // Parâmetros padrão (iguais ao backup de senha)
        let m_cost_kib: u32 = 65536;
        let t_cost: u32 = 3;
        let p_cost: u32 = 1;

        let key_b58 =
            derive_raw_key_argon2id(&export_passphrase, &salt, m_cost_kib, t_cost, p_cost)?;
        let key_bytes = bs58::decode(key_b58)
            .into_vec()
            .map_err(|e| napi_err("BundleKeyDecodeFailed", e.to_string()))?;
        if key_bytes.len() != 32 {
            return Err(napi_err(
                "BundleKeyInvalid",
                "chave derivada não tem 32 bytes",
            ));
        }

        // AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| napi_err("BundleCipherInitFailed", e.to_string()))?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let ciphertext = cipher
            .encrypt((&nonce).into(), inner_bytes.as_ref())
            .map_err(|e| napi_err("BundleEncryptFailed", e.to_string()))?;

        // Payload final do bundle
        let payload = serde_json::json!({
            "version": 1,
            "kdf": "argon2id",
            "salt_b64": B64.encode(salt),
            "m_cost_kib": m_cost_kib,
            "t_cost": t_cost,
            "p_cost": p_cost,
            "nonce_b64": B64.encode(nonce),
            "ct_b64": B64.encode(ciphertext),
        });

        // Escrita atômica (tmp -> rename)
        let tmp = format!("{}.tmp", out_bundle_path);
        let bytes = serde_json::to_vec_pretty(&payload)
            .map_err(|e| napi_err("BundleSerializeOuterFailed", e.to_string()))?;
        fs::write(&tmp, bytes).map_err(|e| napi_err("BundleWriteFailed", e.to_string()))?;
        fs::rename(&tmp, &out_bundle_path)
            .map_err(|e| napi_err("BundleRenameFailed", e.to_string()))?;

        Ok(true)
    }

    #[napi]
    pub fn wallet_import_bundle(
        &self,
        in_bundle_path: String,
        dest_wallet_path: String,
        import_passphrase: String,
        overwrite: Option<bool>,
    ) -> Result<bool> {
        if in_bundle_path.trim().is_empty() {
            return Err(napi_err("BundlePathInvalid", "in_bundle_path vazio"));
        }
        if dest_wallet_path.trim().is_empty() {
            return Err(napi_err("WalletPathInvalid", "dest_wallet_path vazio"));
        }
        if import_passphrase.is_empty() {
            return Err(napi_err("BundlePassInvalid", "import_passphrase vazio"));
        }

        let overwrite = overwrite.unwrap_or(false);

        // Guard conservador
        if self.store.is_some() {
            return Err(napi_err(
                "WalletAlreadyOpen",
                "feche a wallet antes de importar bundle (walletClose)",
            ));
        }

        // Lê e parseia o bundle
        let bundle_bytes =
            fs::read(&in_bundle_path).map_err(|e| napi_err("BundleReadFailed", e.to_string()))?;
        let outer: Value = serde_json::from_slice(&bundle_bytes)
            .map_err(|e| napi_err("BundleParseFailed", e.to_string()))?;

        let salt_b64 = outer["salt_b64"]
            .as_str()
            .ok_or_else(|| napi_err("BundleFormatInvalid", "salt_b64 ausente"))?;
        let nonce_b64 = outer["nonce_b64"]
            .as_str()
            .ok_or_else(|| napi_err("BundleFormatInvalid", "nonce_b64 ausente"))?;
        let ct_b64 = outer["ct_b64"]
            .as_str()
            .ok_or_else(|| napi_err("BundleFormatInvalid", "ct_b64 ausente"))?;

        let m_cost_kib = outer["m_cost_kib"].as_u64().unwrap_or(65536) as u32;
        let t_cost = outer["t_cost"].as_u64().unwrap_or(3) as u32;
        let p_cost = outer["p_cost"].as_u64().unwrap_or(1) as u32;

        let salt = B64
            .decode(salt_b64)
            .map_err(|e| napi_err("BundleFormatInvalid", e.to_string()))?;
        let nonce = B64
            .decode(nonce_b64)
            .map_err(|e| napi_err("BundleFormatInvalid", e.to_string()))?;
        let ct = B64
            .decode(ct_b64)
            .map_err(|e| napi_err("BundleFormatInvalid", e.to_string()))?;

        if nonce.len() != 12 {
            return Err(napi_err("BundleNonceInvalid", "nonce deve ter 12 bytes"));
        }

        // Deriva chave e decripta
        let key_b58 =
            derive_raw_key_argon2id(&import_passphrase, &salt, m_cost_kib, t_cost, p_cost)?;
        let key_bytes = bs58::decode(key_b58)
            .into_vec()
            .map_err(|e| napi_err("BundleKeyDecodeFailed", e.to_string()))?;
        if key_bytes.len() != 32 {
            return Err(napi_err(
                "BundleKeyInvalid",
                "chave derivada não tem 32 bytes",
            ));
        }

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| napi_err("BundleCipherInitFailed", e.to_string()))?;

        let inner_bytes = cipher
            .decrypt((&nonce[..]).into(), ct.as_ref())
            .map_err(|e| napi_err("BundleDecryptFailed", e.to_string()))?;

        let inner: Value = serde_json::from_slice(&inner_bytes)
            .map_err(|e| napi_err("BundleInnerParseFailed", e.to_string()))?;

        let files = &inner["files"];
        let db_b64 = files["db_b64"]
            .as_str()
            .ok_or_else(|| napi_err("BundleInnerFormatInvalid", "files.db_b64 ausente"))?;
        let sidecar_json_utf8 = files["sidecar_json_utf8"].as_str().ok_or_else(|| {
            napi_err(
                "BundleInnerFormatInvalid",
                "files.sidecar_json_utf8 ausente",
            )
        })?;

        let db_bytes = B64
            .decode(db_b64)
            .map_err(|e| napi_err("BundleInnerFormatInvalid", e.to_string()))?;
        let wal_bytes = files["wal_b64"].as_str().and_then(|s| B64.decode(s).ok());
        let shm_bytes = files["shm_b64"].as_str().and_then(|s| B64.decode(s).ok());

        // Paths destino
        let dest_db_path = std::path::Path::new(&dest_wallet_path);
        let dest_sidecar_path = sidecar_path_for(&dest_wallet_path);

        // Garante diretório
        if let Some(parent) = dest_db_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| napi_err("WalletPathCreateDirFailed", e.to_string()))?;
            }
        }

        // Overwrite policy
        if !overwrite {
            if dest_db_path.exists() || std::path::Path::new(&dest_sidecar_path).exists() {
                return Err(napi_err(
                    "WalletAlreadyExists",
                    "destino já existe (db e/ou sidecar). Use overwrite=true para substituir.",
                ));
            }
        } else {
            // best-effort cleanup dos artefatos destino (db, wal, shm, sidecar)
            let _ = fs::remove_file(&dest_wallet_path);
            let _ = fs::remove_file(format!("{}-wal", dest_wallet_path));
            let _ = fs::remove_file(format!("{}-shm", dest_wallet_path));
            let _ = fs::remove_file(&dest_sidecar_path);
            let _ = fs::remove_file(format!("{}.tmp", dest_sidecar_path));
            let _ = fs::remove_file(format!("{}.tmp", dest_wallet_path));
        }

        // Escrita atômica DB
        let db_tmp = format!("{}.tmp", dest_wallet_path);
        fs::write(&db_tmp, &db_bytes)
            .map_err(|e| napi_err("BundleWriteDbFailed", e.to_string()))?;
        fs::rename(&db_tmp, &dest_wallet_path)
            .map_err(|e| napi_err("BundleRenameDbFailed", e.to_string()))?;

        // Escrita atômica sidecar
        let sidecar_tmp = format!("{}.tmp", dest_sidecar_path);
        fs::write(&sidecar_tmp, sidecar_json_utf8.as_bytes())
            .map_err(|e| napi_err("BundleWriteSidecarFailed", e.to_string()))?;
        fs::rename(&sidecar_tmp, &dest_sidecar_path)
            .map_err(|e| napi_err("BundleRenameSidecarFailed", e.to_string()))?;

        // WAL/SHM opcionais
        if let Some(wal) = wal_bytes {
            let wal_path = format!("{}-wal", dest_wallet_path);
            fs::write(&wal_path, wal)
                .map_err(|e| napi_err("BundleWriteWalFailed", e.to_string()))?;
        }
        if let Some(shm) = shm_bytes {
            let shm_path = format!("{}-shm", dest_wallet_path);
            fs::write(&shm_path, shm)
                .map_err(|e| napi_err("BundleWriteShmFailed", e.to_string()))?;
        }

        Ok(true)
    }

    #[napi]
    pub async unsafe fn wallet_rotate_kdf(
        &mut self,
        path: String,
        pass: String,
        m_cost_kib: Option<u32>,
        t_cost: Option<u32>,
        p_cost: Option<u32>,
    ) -> Result<bool> {
        if path.trim().is_empty() {
            return Err(napi_err("WalletPathInvalid", "wallet path vazio"));
        }

        if self.store.is_some() {
            return Err(napi_err(
                "WalletAlreadyOpen",
                "feche a wallet atual antes de rotacionar KDF (walletClose)",
            ));
        }

        let wallet_db_path = std::path::Path::new(&path);
        if !wallet_db_path.exists() {
            return Err(napi_err(
                "WalletNotFound",
                format!("wallet db não encontrada ({})", path),
            ));
        }

        // Parâmetros novos (defaults iguais ao seu default_argon2_sidecar)
        let m_new = m_cost_kib.unwrap_or(65536);
        let t_new = t_cost.unwrap_or(3);
        let p_new = p_cost.unwrap_or(1);

        if m_new < 1024 {
            return Err(napi_err(
                "KdfParamsInvalid",
                "m_cost_kib muito baixo (<1024 KiB)",
            ));
        }
        if t_new == 0 {
            return Err(napi_err("KdfParamsInvalid", "t_cost inválido (0)"));
        }
        if p_new == 0 {
            return Err(napi_err("KdfParamsInvalid", "p_cost inválido (0)"));
        }

        let config_uri = format!("sqlite://{}", path);
        let sidecar_path = sidecar_path_for(&path);

        // Sidecar é obrigatório para "wallets novas" — mantém sua política atual.
        // (E também permite upgrade de legacy, caso exista sidecar legacy gerado na migração.)
        if !std::path::Path::new(&sidecar_path).exists() {
            return Err(napi_err(
                "KdfParamsMissing",
                format!(
                    "sidecar ausente ({}). Para rotacionar KDF, o sidecar é obrigatório.",
                    sidecar_path
                ),
            ));
        }

        let sc_old = read_sidecar(&sidecar_path)?;

        // 1) Deriva chave atual via sidecar (argon2id ou legacy) e abre store
        let raw_key_old = derive_raw_key_from_sidecar(&pass, &sc_old)?;
        let mut store = match Store::open(
            &config_uri,
            Some(StoreKeyMethod::RawKey),
            PassKey::from(raw_key_old),
            None,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                let emsg = e.to_string();
                if is_wallet_auth_error(&emsg) {
                    return Err(napi_err(
                        "WalletAuthFailed",
                        "Senha incorreta (falha na decifragem da chave da wallet).",
                    ));
                }
                return Err(napi_err("WalletOpenFailed", emsg));
            }
        };

        // 2) Cria NOVO sidecar Argon2id com NOVO salt e params novos (mesma senha)
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        let sc_new = WalletKdfSidecar {
            version: 1,
            kdf: "argon2id".to_string(),
            salt_b64: Some(B64.encode(salt)),
            m_cost_kib: Some(m_new),
            t_cost: Some(t_new),
            p_cost: Some(p_new),
            dk_len: Some(32),
            rounds: None,
        };

        let raw_key_new = derive_raw_key_argon2id(&pass, &salt, m_new, t_new, p_new)?;

        // 3) Rekey no store (troca wrapping key, sem trocar senha)
        store
            .rekey(StoreKeyMethod::RawKey, PassKey::from(raw_key_new))
            .await
            .map_err(|e| napi_err("WalletRekeyFailed", e.to_string()))?;

        // 4) Atualiza sidecar APÓS rekey OK
        write_sidecar(&sidecar_path, &sc_new)?;

        // best-effort close
        let _ = store.close().await;

        Ok(true)
    }

    #[napi]
    pub fn wallet_info(&self, path: String) -> Result<String> {
        if path.trim().is_empty() {
            return Err(napi_err("WalletPathInvalid", "wallet path vazio"));
        }

        let db_path = std::path::Path::new(&path);
        let db_exists = db_path.exists();

        let sidecar_path = sidecar_path_for(&path);
        let sidecar_exists = std::path::Path::new(&sidecar_path).exists();

        // WAL/SHM (úteis pra debug/diagnóstico)
        let wal_path = format!("{}-wal", path);
        let shm_path = format!("{}-shm", path);
        let wal_exists = std::path::Path::new(&wal_path).exists();
        let shm_exists = std::path::Path::new(&shm_path).exists();

        // Status de “aberta nesta instância”
        let is_open_any = self.store.is_some();
        let expected_uri = format!("sqlite://{}", path);
        let current_uri = self.connection_uri.clone();
        let is_open_for_path = is_open_any && current_uri == expected_uri;

        // Sidecar parse (best-effort; não explode)
        let mut sidecar_parse_ok = false;
        let mut sidecar_error: Option<String> = None;
        let mut sc_json: Option<serde_json::Value> = None;

        if sidecar_exists {
            match read_sidecar(&sidecar_path) {
                Ok(sc) => {
                    sidecar_parse_ok = true;
                    sc_json = Some(serde_json::json!({
                        "version": sc.version,
                        "kdf": sc.kdf,
                        "salt_b64": sc.salt_b64,
                        "m_cost_kib": sc.m_cost_kib,
                        "t_cost": sc.t_cost,
                        "p_cost": sc.p_cost,
                        "dk_len": sc.dk_len,
                        "rounds": sc.rounds
                    }));
                }
                Err(e) => {
                    sidecar_parse_ok = false;
                    sidecar_error = Some(e.to_string());
                }
            }
        }

        // “Integridade” simples: DB e sidecar devem existir e sidecar deve parsear
        // (Você pode evoluir isso depois para checks mais fortes)
        let integrity_ok = if db_exists {
            // política atual: para wallets "novas", sidecar é obrigatório.
            // como não sabemos se é legacy ou não sem tentar abrir,
            // usamos um check suave: se não há sidecar, marcamos warning.
            sidecar_exists && sidecar_parse_ok
        } else {
            false
        };

        let warnings: Vec<String> = {
            let mut w = Vec::new();
            if db_exists && !sidecar_exists {
                w.push(format!(
                "Sidecar ausente ({}). Wallet pode ser legacy, mas nesta versão sidecar é recomendado/obrigatório para novas.",
                sidecar_path
            ));
            }
            if sidecar_exists && !sidecar_parse_ok {
                w.push("Sidecar existe mas não foi possível parsear (JSON inválido ou formato inesperado).".to_string());
            }
            if wal_exists || shm_exists {
                w.push("Arquivos -wal/-shm existem. Normal enquanto DB está em WAL mode; para backup/export, prefira wallet fechada.".to_string());
            }
            w
        };

        let out = serde_json::json!({
            "ok": true,
            "context": "ssi:walletInfo",
            "path": path,
            "connection_uri_current": current_uri,
            "expected_uri_for_path": expected_uri,

            "status": {
                "is_open_any": is_open_any,
                "is_open_for_path": is_open_for_path,
            },

            "files": {
                "db_exists": db_exists,
                "sidecar_exists": sidecar_exists,
                "sidecar_path": sidecar_path,
                "wal_exists": wal_exists,
                "shm_exists": shm_exists,
            },

            "sidecar": {
                "parse_ok": sidecar_parse_ok,
                "error": sidecar_error,
                "data": sc_json
            },

            "integrity": {
                "ok": integrity_ok
            },

            "warnings": warnings
        });

        Ok(out.to_string())
    }

    #[napi]
    pub async unsafe fn wallet_lock(&mut self) -> Result<bool> {
        // Alias: lock = close
        // Reaproveita a mesma semântica do wallet_close existente
        self.wallet_close().await?;
        Ok(true)
    }

    #[napi]
    pub async unsafe fn wallet_unlock(&mut self, path: String, pass: String) -> Result<bool> {
        // Alias: unlock = open
        self.wallet_open(path, pass).await?;
        Ok(true)
    }
}
