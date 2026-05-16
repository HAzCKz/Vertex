/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
RESET_WALLET=1 \
WALLET_PASS="minha_senha_teste" \
GENESIS_FILE=./von_genesis.txn \
TRUSTEE_SEED="000000000000000000000000Trustee1" \
TRUSTEE_DID="V4SGRU86Z58d6TV7PBUe6f" \
node teste-node/revocation/test_revocation_11_manifest_anchor_von.js
*/
/*
Teste de âncora de manifesto de revogação no ledger.

O fluxo:
- cria/abre a wallet do emissor;
- conecta à von-network;
- importa o DID Trustee;
- cria um DID próprio e registra esse DID no ledger;
- lê o manifesto real do bfilter e calcula seu hash;
- monta um manifest anchor com URL, hash e versão;
- publica esse manifesto no ledger;
- lê o manifesto de volta do ledger.

Depois valida:
- a escrita do manifesto foi aceita;
- a leitura retorna ok=true;
- issuer_did, manifest_url, manifest_hash e manifest_version
  lidos do ledger são iguais aos valores publicados.

Foco do teste:
validar o ciclo build -> write -> read da âncora de manifesto
de revogação na VON.
*/
/* eslint-disable no-console */
const crypto = require("crypto");
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
  const BFILTER_BASE_URL = process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080";

  const walletsDir = path.join(__dirname, "..", "wallets");
  fs.mkdirSync(walletsDir, { recursive: true });

  const issuerWalletPath = path.join(walletsDir, "issuer_revocation_manifest_11.db");
  if (RESET_WALLET) rmIfExists(issuerWalletPath);

  const issuer = new IndyAgent();

  try {
    console.log("🚀 TESTE REVOGAÇÃO 11: Manifest anchor na VON");

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

    console.log("1) Lendo o manifesto real do bfilter...");
    const manifestResp = await fetch(`${BFILTER_BASE_URL}/manifest`);
    if (!manifestResp.ok) {
      throw new Error(`Falha GET /manifest: ${manifestResp.status}`);
    }
    const manifestBodyText = await manifestResp.text();
    const manifestEnvelope = safeJsonParse(manifestBodyText, "manifest_body");
    if (manifestEnvelope.ok !== true) {
      throw new Error("manifesto Bloom deveria retornar ok=true");
    }

    console.log("2) Montando manifest anchor...");
    const manifestJson = await issuer.revocationBuildManifestAnchor(
      issuerDid,
      `${BFILTER_BASE_URL}/manifest`,
      crypto.createHash("sha256").update(manifestBodyText).digest("base64"),
      String(manifestEnvelope.manifest.version || 1)
    );
    const manifest = safeJsonParse(manifestJson, "manifest_anchor");

    console.log("3) Publicando manifest anchor...");
    const writeJson = await issuer.revocationWriteManifestAnchorOnLedger(
      GENESIS_FILE,
      issuerDid,
      manifestJson
    );
    const writeResp = safeJsonParse(writeJson, "write_manifest");
    if (!writeResp.ok) throw new Error("revocationWriteManifestAnchorOnLedger retornou ok=false");

    await sleep(250);

    console.log("4) Lendo manifest anchor do ledger...");
    const readJson = await issuer.revocationReadManifestAnchorFromLedger(
      GENESIS_FILE,
      issuerDid
    );
    const readResp = safeJsonParse(readJson, "read_manifest");

    if (!readResp.ok) throw new Error("revocationReadManifestAnchorFromLedger retornou ok=false");
    if (readResp.manifest.issuer_did !== issuerDid) {
      throw new Error("issuer_did do manifesto lido diverge");
    }
    if (readResp.manifest.manifest_url !== manifest.manifest_url) {
      throw new Error("manifest_url do manifesto lido diverge");
    }
    if (readResp.manifest.manifest_hash !== manifest.manifest_hash) {
      throw new Error("manifest_hash do manifesto lido diverge");
    }
    if (readResp.manifest.manifest_version !== manifest.manifest_version) {
      throw new Error("manifest_version do manifesto lido diverge");
    }

    console.log("✅ OK: TESTE REVOGAÇÃO 11 passou.");
  } finally {
    try { await issuer.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 11:", e && e.stack ? e.stack : e);
  process.exit(1);
});
