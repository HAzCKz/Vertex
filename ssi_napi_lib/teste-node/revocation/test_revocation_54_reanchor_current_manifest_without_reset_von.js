/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
RESET_WALLET=1 \
WALLET_PASS="minha_senha_teste" \
GENESIS_FILE=./von_genesis.txn \
BFILTER_BASE_URL="http://127.0.0.1:8080" \
TRUSTEE_SEED="000000000000000000000000Trustee1" \
TRUSTEE_DID="V4SGRU86Z58d6TV7PBUe6f" \
MANIFEST_ISSUER_DID="V4SGRU86Z58d6TV7PBUe6f" \
node teste-node/revocation/test_revocation_54_reanchor_current_manifest_without_reset_von.js
*/

/*
Reancora o manifesto atual do bfilter no ledger sem depender da API de testes.

O fluxo:
- conecta ao ledger;
- importa o DID autorizado a assinar o ATTRIB;
- lê o manifesto atual em /manifest;
- calcula o hash do corpo bruto do arquivo;
- escreve a âncora atualizada no ledger;
- lê a âncora de volta para confirmar o roundtrip.
*/

const crypto = require("crypto");
const path = require("path");
const {
  NETWORK_CONFIG,
  assert,
  downloadGenesisHttp,
  loadIndyAgent,
  fn,
  walletCreateOpenIdempotent,
  parseJsonSafe,
  cleanupWalletFamily,
  ensureWalletDir,
} = require("./_helpers");

function sha256Base64(input) {
  return crypto.createHash("sha256").update(input).digest("base64");
}

(async () => {
  const IndyAgent = loadIndyAgent();
  const pass = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET = process.env.RESET_WALLET === "1";
  const BFILTER_BASE_URL = process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080";
  const manifestIssuerDid =
    process.env.MANIFEST_ISSUER_DID ||
    process.env.TRUSTEE_DID ||
    NETWORK_CONFIG.trusteeDid;

  const walletDir = ensureWalletDir();
  const issuerDb =
    process.env.WALLET_ISSUER ||
    path.join(walletDir, "test_wallet_revocation_reanchor_manifest_issuer.db");

  const genesisAbs = path.join(
    process.cwd(),
    process.env.GENESIS_FILE || NETWORK_CONFIG.genesisFile
  );
  await downloadGenesisHttp(NETWORK_CONFIG.genesisUrl, genesisAbs);

  if (RESET) {
    cleanupWalletFamily(issuerDb);
  }

  const issuer = new IndyAgent();
  await walletCreateOpenIdempotent(issuer, issuerDb, pass);

  try {
    const importDidFromSeed = fn(issuer, "importDidFromSeed", "import_did_from_seed");
    const revocationBuildManifestAnchor = fn(
      issuer,
      "revocationBuildManifestAnchor",
      "revocation_build_manifest_anchor"
    );
    const revocationWriteManifestAnchorOnLedger = fn(
      issuer,
      "revocationWriteManifestAnchorOnLedger",
      "revocation_write_manifest_anchor_on_ledger"
    );
    const revocationReadManifestAnchorFromLedger = fn(
      issuer,
      "revocationReadManifestAnchorFromLedger",
      "revocation_read_manifest_anchor_from_ledger"
    );

    console.log("🚀 TESTE REVOGAÇÃO 54: reanchor do manifesto atual sem reset");

    console.log("1) Conectando ao ledger e importando o DID autor...");
    await issuer.connectNetwork(genesisAbs);
    const [authorDid] = await importDidFromSeed(
      process.env.TRUSTEE_SEED || NETWORK_CONFIG.trusteeSeed
    );
    assert(
      authorDid === manifestIssuerDid,
      `O DID importado (${authorDid}) diverge do MANIFEST_ISSUER_DID (${manifestIssuerDid})`
    );

    console.log("2) Lendo o manifesto atual do bfilter...");
    const manifestResp = await fetch(`${BFILTER_BASE_URL}/manifest`);
    assert(manifestResp.ok, `Falha GET /manifest: ${manifestResp.status}`);
    const manifestBodyText = await manifestResp.text();
    const manifestEnvelope = parseJsonSafe(manifestBodyText, "manifest_body");
    assert(manifestEnvelope.ok === true, "manifesto Bloom deveria retornar ok=true");
    const manifestHash = sha256Base64(manifestBodyText);

    console.log("3) Escrevendo a âncora correta no ledger...");
    const manifestAnchorJson = await revocationBuildManifestAnchor(
      manifestIssuerDid,
      `${BFILTER_BASE_URL}/manifest`,
      manifestHash,
      String(manifestEnvelope.manifest.version || 1)
    );
    const manifestAnchor = parseJsonSafe(manifestAnchorJson, "manifest_anchor");
    const writeJson = await revocationWriteManifestAnchorOnLedger(
      genesisAbs,
      manifestIssuerDid,
      manifestAnchorJson
    );
    const writeResp = parseJsonSafe(writeJson, "write_manifest");
    assert(writeResp.ok === true, "revocationWriteManifestAnchorOnLedger deveria retornar ok=true");

    console.log("4) Lendo a âncora do ledger para confirmar o roundtrip...");
    const readJson = await revocationReadManifestAnchorFromLedger(genesisAbs, manifestIssuerDid);
    const readResp = parseJsonSafe(readJson, "read_manifest");
    assert(readResp.ok === true, "revocationReadManifestAnchorFromLedger deveria retornar ok=true");
    assert(readResp.manifest.manifest_url === manifestAnchor.manifest_url, "manifest_url lido diverge");
    assert(readResp.manifest.manifest_hash === manifestHash, "manifest_hash lido diverge do hash do arquivo");

    console.log("✅ OK: TESTE REVOGAÇÃO 54 passou.");
    console.log("📌 Resumo final:", {
      issuer_did: manifestIssuerDid,
      manifest_url: manifestAnchor.manifest_url,
      manifest_version: manifestAnchor.manifest_version,
      manifest_hash: manifestHash,
    });
  } finally {
    try { await issuer.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 54:", e && e.stack ? e.stack : e);
  process.exit(1);
});
