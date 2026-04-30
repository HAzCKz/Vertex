/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
RESET_WALLET=1 \
AUTO_REANCHOR=1 \
WALLET_PASS="minha_senha_teste" \
GENESIS_FILE=./von_genesis.txn \
BFILTER_BASE_URL="http://127.0.0.1:8080" \
TRUSTEE_SEED="000000000000000000000000Trustee1" \
TRUSTEE_DID="V4SGRU86Z58d6TV7PBUe6f" \
MANIFEST_ISSUER_DID="V4SGRU86Z58d6TV7PBUe6f" \
node teste-node/revocation/test_revocation_53_manifest_attr_hash_matches_manifest_file_von.js

Uso típico:
- se o manifesto foi ancorado no DID trustee, basta usar TRUSTEE_DID;
- se o manifesto foi ancorado em outro emissor, informe MANIFEST_ISSUER_DID.
- se quiser que o teste reancore automaticamente antes da auditoria, use AUTO_REANCHOR=1.
*/

/*
Teste de integridade do manifesto ancorado no ledger.

O fluxo:
- abre uma wallet de leitura e conecta na VON;
- lê o ATTRIB de manifesto do ledger para um issuer DID;
- baixa o arquivo manifesto apontado por manifest_url;
- calcula o SHA-256 Base64 do conteúdo bruto retornado por /manifest;
- compara esse hash com manifest_hash gravado no ledger.

Foco do teste:
garantir que o ATTRIB ancorado no ledger referencia o hash do
conteúdo do arquivo manifesto, e não o hash da URL.

Importante:
este teste não reancora nada. Se o /manifest do bfilter mudou desde a
última ancoragem no ledger, o teste deve falhar. Nessa situação, rode
antes o test_revocation_54_reanchor_current_manifest_without_reset_von.js
e só depois repita este teste.

Atalho opcional:
com AUTO_REANCHOR=1, este próprio teste executa internamente o fluxo de
reanchor antes de fazer a auditoria final.
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

function sha256Base64Bytes(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("base64");
}

function sha256Base64(input) {
  return crypto.createHash("sha256").update(input).digest("base64");
}

(async () => {
  const IndyAgent = loadIndyAgent();
  const pass = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET = process.env.RESET_WALLET === "1";
  const AUTO_REANCHOR = process.env.AUTO_REANCHOR === "1";
  const BFILTER_BASE_URL = process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080";
  const issuerDid =
    process.env.MANIFEST_ISSUER_DID ||
    process.env.TRUSTEE_DID ||
    NETWORK_CONFIG.trusteeDid;

  const walletDir = ensureWalletDir();
  const readerDb =
    process.env.WALLET_READER ||
    path.join(walletDir, "test_wallet_revocation_manifest_hash_check_reader.db");
  const issuerDb =
    process.env.WALLET_ISSUER ||
    path.join(walletDir, "test_wallet_revocation_manifest_hash_check_issuer.db");

  const genesisAbs = path.join(
    process.cwd(),
    process.env.GENESIS_FILE || NETWORK_CONFIG.genesisFile
  );
  await downloadGenesisHttp(NETWORK_CONFIG.genesisUrl, genesisAbs);

  if (RESET) {
    cleanupWalletFamily(readerDb);
    if (AUTO_REANCHOR) {
      cleanupWalletFamily(issuerDb);
    }
  }

  const reader = new IndyAgent();
  await walletCreateOpenIdempotent(reader, readerDb, pass);
  let issuer = null;

  try {
    if (AUTO_REANCHOR) {
      issuer = new IndyAgent();
      await walletCreateOpenIdempotent(issuer, issuerDb, pass);

      const importDidFromSeed = fn(
        issuer,
        "importDidFromSeed",
        "import_did_from_seed"
      );
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

      console.log("0) AUTO_REANCHOR=1 ativo: reancorando o manifesto atual antes da auditoria...");
      await issuer.connectNetwork(genesisAbs);
      const [authorDid] = await importDidFromSeed(
        process.env.TRUSTEE_SEED || NETWORK_CONFIG.trusteeSeed
      );
      assert(
        authorDid === issuerDid,
        `O DID importado (${authorDid}) diverge do MANIFEST_ISSUER_DID (${issuerDid})`
      );

      const manifestResp = await fetch(`${BFILTER_BASE_URL}/manifest`);
      assert(manifestResp.ok, `Falha GET /manifest: ${manifestResp.status}`);
      const manifestBodyText = await manifestResp.text();
      const manifestEnvelope = parseJsonSafe(manifestBodyText, "manifest_body");
      assert(manifestEnvelope.ok === true, "manifesto Bloom deveria retornar ok=true");
      const manifestHash = sha256Base64(manifestBodyText);

      const manifestAnchorJson = await revocationBuildManifestAnchor(
        issuerDid,
        `${BFILTER_BASE_URL}/manifest`,
        manifestHash,
        String(manifestEnvelope.manifest.version || 1)
      );
      const writeJson = await revocationWriteManifestAnchorOnLedger(
        genesisAbs,
        issuerDid,
        manifestAnchorJson
      );
      const writeResp = parseJsonSafe(writeJson, "write_manifest_auto_reanchor");
      assert(writeResp.ok === true, "auto reanchor do manifesto falhou");
    }

    const revocationReadManifestAnchorFromLedger = fn(
      reader,
      "revocationReadManifestAnchorFromLedger",
      "revocation_read_manifest_anchor_from_ledger"
    );

    console.log("🚀 TESTE REVOGAÇÃO 53: hash do ATTRIB de manifesto vs arquivo manifesto");

    console.log(`1) Conectando ao ledger e lendo o manifesto do DID ${issuerDid}...`);
    await reader.connectNetwork(genesisAbs);
    const readJson = await revocationReadManifestAnchorFromLedger(genesisAbs, issuerDid);
    const readResp = parseJsonSafe(readJson, "read_manifest");
    assert(readResp.ok === true, "revocationReadManifestAnchorFromLedger deveria retornar ok=true");

    const anchor = readResp.manifest;
    assert(anchor, "resposta do ledger deveria conter manifest");
    assert(anchor.manifest_url, "manifest_url ausente no ATTRIB");
    assert(anchor.manifest_hash, "manifest_hash ausente no ATTRIB");

    console.log("2) Baixando o arquivo manifesto bruto apontado por manifest_url...");
    const response = await fetch(anchor.manifest_url);
    assert(response.ok, `Falha GET ${anchor.manifest_url}: ${response.status}`);
    const bodyArrayBuffer = await response.arrayBuffer();
    const bodyBytes = Buffer.from(bodyArrayBuffer);
    const bodyHash = sha256Base64Bytes(bodyBytes);

    const envelope = JSON.parse(bodyBytes.toString("utf8"));
    assert(envelope && envelope.ok === true, "o arquivo manifesto deveria retornar ok=true");
    assert(envelope.manifest, "o arquivo manifesto deveria conter o campo manifest");

    const manifestOnlyHash = sha256Base64Bytes(
      Buffer.from(JSON.stringify(envelope.manifest), "utf8")
    );
    const manifestUrlHash = sha256Base64Bytes(Buffer.from(anchor.manifest_url, "utf8"));

    console.log("3) Comparando o hash ancorado com o hash do conteúdo do arquivo manifesto...");
    assert(
      anchor.manifest_hash === bodyHash,
      [
        "manifest_hash ancorado no ledger não confere com o conteúdo bruto do arquivo manifesto.",
        `issuer_did=${issuerDid}`,
        `manifest_url=${anchor.manifest_url}`,
        `manifest_hash_ledger=${anchor.manifest_hash}`,
        `manifest_hash_body=${bodyHash}`,
        `manifest_hash_manifest_obj=${manifestOnlyHash}`,
        `manifest_hash_url=${manifestUrlHash}`,
        anchor.manifest_hash === manifestUrlHash
          ? "O hash ancorado coincide com o hash da URL, não com o hash do arquivo manifesto."
          : "O hash ancorado não coincide nem com o corpo bruto nem com a URL.",
        "O ledger parece estar stale em relação ao /manifest atual.",
        "Reancore o manifesto corrente e rode este teste novamente.",
        "Comando sugerido:",
        "RESET_WALLET=1 WALLET_PASS=\"minha_senha_teste\" GENESIS_FILE=./von_genesis.txn BFILTER_BASE_URL=\"http://127.0.0.1:8080\" TRUSTEE_SEED=\"000000000000000000000000Trustee1\" TRUSTEE_DID=\"V4SGRU86Z58d6TV7PBUe6f\" MANIFEST_ISSUER_DID=\"V4SGRU86Z58d6TV7PBUe6f\" node teste-node/revocation/test_revocation_54_reanchor_current_manifest_without_reset_von.js"
      ].join("\n")
    );

    console.log("✅ OK: TESTE REVOGAÇÃO 53 passou.");
    console.log("📌 Resumo final:", {
      issuer_did: issuerDid,
      manifest_url: anchor.manifest_url,
      manifest_version: anchor.manifest_version,
      manifest_hash_ledger: anchor.manifest_hash,
      manifest_hash_body: bodyHash,
    });
  } finally {
    try { await reader.walletClose(); } catch {}
    if (issuer) {
      try { await issuer.walletClose(); } catch {}
    }
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 53:", e && e.stack ? e.stack : e);
  process.exit(1);
});
