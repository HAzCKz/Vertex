/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
RESET_WALLET=1 \
WALLET_PASS="minha_senha_teste" \
GENESIS_FILE=./von_genesis.txn \
BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
TRUSTEE_SEED="000000000000000000000000Trustee1" \
TRUSTEE_DID="V4SGRU86Z58d6TV7PBUe6f" \
node teste-node/revocation/test_revocation_47_reset_bloom_to_default_and_reanchor_manifest_von.js

Equivalente manual do reset:
curl -X POST http://127.0.0.1:8080/test/reset \
  -H 'Authorization: Bearer dev-admin-token' \
  -H 'Content-Type: application/json' \
  -d '{}'

Para subir o bfilter em modo de testes:
cd /home/yugi/programacao/bfilter
BFILTER_ENABLE_TEST_API=1 \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
cargo run
*/

/*
Teste utilitário de reset do Bloom Filter para o tamanho padrão de produção
e reancoragem do manifesto atualizado no ledger.

O fluxo:
- chama /test/reset com payload vazio;
- confirma que o bfilter voltou ao filtro padrão de 2 MB;
- conecta à von-network;
- importa o DID trustee;
- reancora o manifesto atual do bfilter no ledger;
- lê o manifesto de volta do ledger para validar roundtrip.

Foco:
deixar o bfilter em estado limpo e padrão para os testes de produção,
com manifesto novamente ancorado no ledger.
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

const DEFAULT_FILTER_BYTES = 2 * 1024 * 1024;
const DEFAULT_M_BITS = DEFAULT_FILTER_BYTES * 8;

function sha256Base64(input) {
  return crypto.createHash("sha256").update(input).digest("base64");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function resetBfilterToDefault(baseUrl, adminToken) {
  let resp;
  try {
    resp = await fetch(`${baseUrl}/test/reset`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${adminToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({}),
    });
  } catch (e) {
    throw new Error(
      `Não foi possível acessar o bfilter em ${baseUrl}. ` +
      `Suba o serviço com BFILTER_ENABLE_TEST_API=1 e BFILTER_ADMIN_TOKEN configurado. ` +
      `Erro original: ${e?.message || e}`
    );
  }

  const bodyText = await resp.text();
  if (resp.status === 404) {
    throw new Error(
      "O endpoint /test/reset não está disponível. Suba o bfilter com BFILTER_ENABLE_TEST_API=1."
    );
  }

  assert(resp.ok, `Falha POST /test/reset: ${resp.status} ${bodyText}`);
  const body = JSON.parse(bodyText);
  assert(body.ok === true, "reset do bfilter deveria retornar ok=true");
  return body;
}

(async () => {
  const IndyAgent = loadIndyAgent();
  const pass = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET = process.env.RESET_WALLET === "1";
  const BFILTER_BASE_URL = process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080";
  const BFILTER_ADMIN_TOKEN = process.env.BFILTER_ADMIN_TOKEN || "dev-admin-token";

  const walletDir = ensureWalletDir();
  const issuerDb =
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_reset_default_manifest_issuer.db");

  const genesisAbs = path.join(process.cwd(), process.env.GENESIS_FILE || NETWORK_CONFIG.genesisFile);
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

    console.log("🚀 TESTE REVOGAÇÃO 47: reset default do bfilter + reanchor do manifesto");

    console.log("1) Resetando o bfilter com payload vazio...");
    const resetResp = await resetBfilterToDefault(BFILTER_BASE_URL, BFILTER_ADMIN_TOKEN);
    const resetManifest = resetResp.manifest || {};
    const activeFilterId = resetManifest.active_filter_id;
    const activeFilter = (resetManifest.filters || []).find((item) => item.filter_id === activeFilterId);
    assert(activeFilter, "filtro ativo deveria existir após o reset");
    assert(
      Number(activeFilter.m_bits) === DEFAULT_M_BITS,
      `m_bits do filtro ativo deveria voltar para ${DEFAULT_M_BITS}, recebido ${activeFilter.m_bits}`
    );
    assert(Number(activeFilter.inserted_count) === 0, "o filtro resetado deveria começar vazio");
    assert((resetManifest.filters || []).length === 1, "após reset deveria existir apenas um filtro no manifesto");

    console.log("2) Conectando ao ledger e importando o DID trustee...");
    await issuer.connectNetwork(genesisAbs);
    const [issuerDid] = await importDidFromSeed(
      process.env.TRUSTEE_SEED || NETWORK_CONFIG.trusteeSeed
    );
    assert(
      issuerDid === (process.env.TRUSTEE_DID || NETWORK_CONFIG.trusteeDid),
      `Trustee DID inesperado: ${issuerDid}`
    );

    console.log("3) Reancorando o manifesto atualizado no ledger...");
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
    const manifestAnchor = parseJsonSafe(manifestAnchorJson, "manifest_anchor");

    const writeJson = await revocationWriteManifestAnchorOnLedger(
      genesisAbs,
      issuerDid,
      manifestAnchorJson
    );
    const writeResp = parseJsonSafe(writeJson, "write_manifest");
    assert(writeResp.ok === true, "revocationWriteManifestAnchorOnLedger deveria retornar ok=true");

    await sleep(250);

    console.log("4) Lendo a âncora de manifesto de volta do ledger...");
    const readJson = await revocationReadManifestAnchorFromLedger(genesisAbs, issuerDid);
    const readResp = parseJsonSafe(readJson, "read_manifest");
    assert(readResp.ok === true, "revocationReadManifestAnchorFromLedger deveria retornar ok=true");
    assert(readResp.manifest.issuer_did === issuerDid, "issuer_did lido do ledger diverge");
    assert(readResp.manifest.manifest_url === manifestAnchor.manifest_url, "manifest_url lido diverge");
    assert(readResp.manifest.manifest_hash === manifestAnchor.manifest_hash, "manifest_hash lido diverge");
    assert(
      readResp.manifest.manifest_version === manifestAnchor.manifest_version,
      "manifest_version lido diverge"
    );

    console.log("✅ OK: TESTE REVOGAÇÃO 47 passou.");
    console.log("📌 Resumo final:", {
      active_filter_id: activeFilterId,
      m_bits: activeFilter.m_bits,
      inserted_count: activeFilter.inserted_count,
      manifest_url: manifestAnchor.manifest_url,
      manifest_version: manifestAnchor.manifest_version,
    });
  } finally {
    try { await issuer.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 47:", e && e.stack ? e.stack : e);
  process.exit(1);
});
