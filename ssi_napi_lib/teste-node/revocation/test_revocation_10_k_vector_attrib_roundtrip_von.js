/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
RESET_WALLET=1 \
WALLET_PASS="minha_senha_teste" \
GENESIS_FILE=./von_genesis.txn \
TRUSTEE_SEED="000000000000000000000000Trustee1" \
TRUSTEE_DID="V4SGRU86Z58d6TV7PBUe6f" \
node teste-node/revocation/test_revocation_10_k_vector_attrib_roundtrip_von.js
*/

/* eslint-disable no-console */
const fs = require("fs");
const path = require("path");

const { IndyAgent } = require(path.join(__dirname, "..", "..", "index.node"));

function rmIfExists(walletDbPath) {
  const sidecar = `${walletDbPath}.kdf.json`;

  try { fs.unlinkSync(walletDbPath); } catch (_) {}
  try { fs.unlinkSync(sidecar); } catch (_) {}
  try { fs.unlinkSync(`${sidecar}.tmp`); } catch (_) {}
  try { fs.unlinkSync(`${walletDbPath}-shm`); } catch (_) {}
  try { fs.unlinkSync(`${walletDbPath}-wal`); } catch (_) {}
}

function mustEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Env ${name} não definida.`);
  return v;
}

function safeJsonParse(s, label = "json") {
  try {
    return JSON.parse(s);
  } catch (e) {
    throw new Error(`Falha parse ${label}: ${e.message}\nConteúdo: ${String(s).slice(0, 500)}`);
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

(async () => {
  const GENESIS_FILE = mustEnv("GENESIS_FILE");
  const WALLET_PASS = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET_WALLET = String(process.env.RESET_WALLET || "0") === "1";
  const TRUSTEE_SEED = process.env.TRUSTEE_SEED || "000000000000000000000000Trustee1";
  const TRUSTEE_DID = process.env.TRUSTEE_DID || "V4SGRU86Z58d6TV7PBUe6f";

  const walletsDir = path.join(__dirname, "..", "wallets");
  fs.mkdirSync(walletsDir, { recursive: true });

  const issuerWalletPath = path.join(walletsDir, "issuer_revocation_k_vector_10.db");
  if (RESET_WALLET) rmIfExists(issuerWalletPath);

  const issuer = new IndyAgent();

  try {
    console.log("🚀 TESTE REVOGAÇÃO 10: K vector em múltiplos ATTRIBs na VON");

    await issuer.walletCreate(issuerWalletPath, WALLET_PASS);
    await issuer.walletOpen(issuerWalletPath, WALLET_PASS);
    await issuer.connectNetwork(GENESIS_FILE);
    await issuer.importDidFromSeed(TRUSTEE_SEED);

    const [issuerDid, issuerVerkey] = await issuer.createOwnDid();
    await issuer.registerDidOnLedger(
      GENESIS_FILE,
      TRUSTEE_DID,
      issuerDid,
      issuerVerkey,
      "ENDORSER"
    );

    const kVectorId = `k-vector-${Date.now()}`;
    console.log("1) Criando K vector local...");
    const setupJson = await issuer.revocationSetupCreateK(issuerDid, kVectorId);
    const setup = safeJsonParse(setupJson, "setup_k");

    if (!setup.ok) throw new Error("revocationSetupCreateK retornou ok=false");
    if (!Array.isArray(setup.k_vector.values) || setup.k_vector.values.length !== 1024) {
      throw new Error("K vector deveria ter 1024 valores");
    }
    if (!Array.isArray(setup.chunks) || setup.chunks.length < 2) {
      throw new Error("K vector deveria ter sido quebrado em múltiplos ATTRIBs");
    }
    if (!setup.ledger_anchor || setup.ledger_anchor.chunk_count !== 11) {
      throw new Error(`K vector otimizado deveria ocupar 11 ATTRIBs de dados, obteve ${setup.ledger_anchor?.chunk_count}`);
    }
    if (!String(setup.ledger_anchor.chunk_prefix || "").startsWith("REVOC_K_")) {
      throw new Error("chunk_prefix do K vector deveria usar namespace exclusivo REVOC_K_");
    }
    if (Array.isArray(setup.ledger_anchor.chunk_keys)) {
      throw new Error("KLedgerAnchor não deveria carregar chunk_keys explícitas");
    }
    console.log("ℹ️ Setup K otimizado:", {
      chunkCount: setup.ledger_anchor.chunk_count,
      chunkSizeBytes: setup.ledger_anchor.chunk_size_bytes,
      totalBytes: setup.ledger_anchor.total_bytes,
      chunkPrefix: setup.ledger_anchor.chunk_prefix,
      indexKey: setup.ledger_anchor.index_key,
      recommendedChunkSizeBytes: setup.recommended_chunk_size_bytes,
    });

    console.log("2) Publicando K vector no ledger...");
    const writeJson = await issuer.revocationWriteKVectorOnLedger(
      GENESIS_FILE,
      issuerDid,
      JSON.stringify(setup.k_vector)
    );
    const writeResp = safeJsonParse(writeJson, "write_k_vector");

    if (!writeResp.ok) throw new Error("revocationWriteKVectorOnLedger retornou ok=false");
    if (!writeResp.ledger_anchor || writeResp.ledger_anchor.chunk_count < 2) {
      throw new Error("ledger_anchor inválido após escrita do K");
    }
    if (writeResp.ledger_anchor.chunk_count !== 11) {
      throw new Error(`Escrita do K deveria manter 11 chunks, obteve ${writeResp.ledger_anchor.chunk_count}`);
    }
    console.log("ℹ️ K publicado no ledger:", {
      chunkCount: writeResp.ledger_anchor.chunk_count,
      chunkSizeBytes: writeResp.ledger_anchor.chunk_size_bytes,
      chunkPrefix: writeResp.ledger_anchor.chunk_prefix,
      writtenChunkKeys: writeResp.written_chunk_keys,
    });

    await sleep(350);

    console.log("3) Lendo K vector do ledger e reconstruindo...");
    const readJson = await issuer.revocationReadKVectorFromLedger(
      GENESIS_FILE,
      issuerDid,
      kVectorId
    );
    const readResp = safeJsonParse(readJson, "read_k_vector");

    if (!readResp.ok) throw new Error("revocationReadKVectorFromLedger retornou ok=false");
    if (readResp.k_vector.k_vector_id !== kVectorId) {
      throw new Error("k_vector_id lido diverge do esperado");
    }
    if (readResp.k_vector.vector_hash !== setup.k_vector.vector_hash) {
      throw new Error("vector_hash reconstruído diverge do original");
    }
    if (!Array.isArray(readResp.k_vector.values) || readResp.k_vector.values.length !== 1024) {
      throw new Error("K vector reconstruído não possui 1024 valores");
    }
    if (JSON.stringify(readResp.k_vector.values) !== JSON.stringify(setup.k_vector.values)) {
      throw new Error("Valores do K vector lido divergem dos valores publicados");
    }
    console.log("ℹ️ K reconstruído do ledger:", {
      chunkCount: readResp.ledger_anchor.chunk_count,
      chunkSizeBytes: readResp.ledger_anchor.chunk_size_bytes,
      totalBytes: readResp.ledger_anchor.total_bytes,
      chunkPrefix: readResp.ledger_anchor.chunk_prefix,
      indexKey: readResp.ledger_anchor.index_key,
    });

    console.log("✅ OK: TESTE REVOGAÇÃO 10 passou.");
  } finally {
    try { await issuer.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 10:", e && e.stack ? e.stack : e);
  process.exit(1);
});
