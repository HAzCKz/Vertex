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
node teste-node/revocation/test_revocation_42_issuer_operational_methods_von.js

Para subir o bfilter:
cd /home/yugi/programacao/bfilter
BFILTER_ADMIN_TOKEN="dev-admin-token" cargo run
*/

/*
Teste E2E de emissão e revogação de credencial revogável.

O fluxo:
- cria/abre wallets do emissor e holder;
- conecta ao ledger;
- cria e registra DID do emissor;
- consulta o manifesto de revogação no bfilter e ancora no ledger;
- cria Schema revogável e registra CredDef;
- garante Link Secret no holder;
- executa offer -> request -> issue da credencial revogável.

Depois valida:
- listagem da credencial emitida como ativa;
- resumo da emissão revogável;
- preflight da revogação;
- revogação efetiva;
- mudança de status para "revoked";
- bloqueio de nova revogação da mesma credencial.

Foco do teste:
validar os métodos operacionais de revogação do lado do emissor.
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
  extractNonce,
  cleanupWalletFamily,
  ensureWalletDir,
} = require("./_helpers");

const CONTROL_ATTRS = [
  "seed",
  "start_time",
  "unit_of_time",
  "time_window",
  "root_merkle_L",
];

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function sha256Base64(input) {
  return crypto.createHash("sha256").update(input).digest("base64");
}

async function tryRegisterDid(agent, genesisFile, submitterDid, did, verkey, role) {
  try {
    await agent.registerDidOnLedger(genesisFile, submitterDid, did, verkey, role);
  } catch (e) {
    const msg = e?.message || String(e);
    if (/already exists|exists|DID.*exist|NYM.*exist|Ledger/i.test(msg)) {
      console.log(`ℹ️ DID já estava no ledger, seguindo: ${did}`);
      return;
    }
    throw e;
  }
}

(async () => {
  const IndyAgent = loadIndyAgent();
  const pass = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET = process.env.RESET_WALLET === "1";
  const BFILTER_BASE_URL = process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080";
  const BFILTER_ADMIN_TOKEN = process.env.BFILTER_ADMIN_TOKEN || "dev-admin-token";
  const TRUSTEE_SEED = process.env.TRUSTEE_SEED || NETWORK_CONFIG.trusteeSeed;
  const TRUSTEE_DID = process.env.TRUSTEE_DID || NETWORK_CONFIG.trusteeDid;

  const walletDir = ensureWalletDir();
  const issuerDb =
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_ops_issuer.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_ops_holder.db");

  const genesisAbs = path.join(process.cwd(), process.env.GENESIS_FILE || NETWORK_CONFIG.genesisFile);
  await downloadGenesisHttp(NETWORK_CONFIG.genesisUrl, genesisAbs);

  if (RESET) {
    cleanupWalletFamily(issuerDb);
    cleanupWalletFamily(holderDb);
  }

  const issuer = new IndyAgent();
  const holder = new IndyAgent();

  await walletCreateOpenIdempotent(issuer, issuerDb, pass);
  await walletCreateOpenIdempotent(holder, holderDb, pass);

  try {
    await issuer.connectNetwork(genesisAbs);
    await holder.connectNetwork(genesisAbs);

    const importDidFromSeed = fn(issuer, "importDidFromSeed", "import_did_from_seed");
    const createAndRegisterSchema = fn(issuer, "createAndRegisterSchema", "create_and_register_schema");
    const creddefSaveLocal = fn(issuer, "creddefSaveLocal", "creddef_save_local");
    const creddefRegisterFromLocal = fn(issuer, "creddefRegisterFromLocal", "creddef_register_from_local");
    const fetchCredDefFromLedger = fn(issuer, "fetchCredDefFromLedger", "fetch_cred_def_from_ledger");
    const createCredentialOffer = fn(issuer, "createCredentialOffer", "create_credential_offer");
    const createLinkSecret = fn(holder, "createLinkSecret", "create_link_secret");
    const createCredentialRequest = fn(holder, "createCredentialRequest", "create_credential_request");
    const revocationBuildManifestAnchor = fn(issuer, "revocationBuildManifestAnchor", "revocation_build_manifest_anchor");
    const revocationWriteManifestAnchorOnLedger = fn(issuer, "revocationWriteManifestAnchorOnLedger", "revocation_write_manifest_anchor_on_ledger");
    const issueRevocableCredential = fn(issuer, "issueRevocableCredential", "issue_revocable_credential");
    const listIssuedRevocableCredentials = fn(
      issuer,
      "listIssuedRevocableCredentials",
      "list_issued_revocable_credentials"
    );
    const getIssuedRevocableCredentialSummary = fn(
      issuer,
      "getIssuedRevocableCredentialSummary",
      "get_issued_revocable_credential_summary"
    );
    const preflightRevokeIssuedCredential = fn(
      issuer,
      "preflightRevokeIssuedCredential",
      "preflight_revoke_issued_credential"
    );
    const revokeIssuedCredentialFromWindow = fn(
      issuer,
      "revokeIssuedCredentialFromWindow",
      "revoke_issued_credential_from_window"
    );

    console.log("🚀 TESTE REVOGAÇÃO 42: métodos operacionais do emissor");

    const [trusteeDid] = await importDidFromSeed(TRUSTEE_SEED);
    assert(trusteeDid === TRUSTEE_DID, `Trustee DID inesperado: ${trusteeDid}`);

    const [issuerDid, issuerVerkey] = await issuer.createOwnDid();
    const [holderDid] = await holder.createOwnDid();
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, issuerDid, issuerVerkey, "ENDORSER");

    const manifestResp = await fetch(`${BFILTER_BASE_URL}/manifest`);
    assert(manifestResp.ok, `Falha GET /manifest: ${manifestResp.status}`);
    const manifestBodyText = await manifestResp.text();
    const manifestEnvelope = JSON.parse(manifestBodyText);
    assert(manifestEnvelope.ok === true, "manifesto Bloom deveria retornar ok=true");
    const manifestHash = sha256Base64(manifestBodyText);

    const manifestJson = await revocationBuildManifestAnchor(
      issuerDid,
      `${BFILTER_BASE_URL}/manifest`,
      manifestHash,
      String(manifestEnvelope.manifest.version || 1)
    );
    const manifest = parseJsonSafe(manifestJson, "manifest_anchor");
    parseJsonSafe(
      await revocationWriteManifestAnchorOnLedger(genesisAbs, issuerDid, JSON.stringify(manifest)),
      "write_manifest"
    );

    const schemaId = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaRevOps_${Date.now()}`,
      `1.${nowSec()}`,
      ["nome", "cpf", ...CONTROL_ATTRS]
    );
    const localCredDefJson = await creddefSaveLocal(
      issuerDid,
      schemaId,
      `TAG_REV_OPS_${Date.now()}`,
      false,
      "prod"
    );
    const localCredDef = parseJsonSafe(localCredDefJson, "creddef_local");
    const credDefReg = await creddefRegisterFromLocal(genesisAbs, localCredDef.id_local, issuerDid);
    const credDefId = credDefReg.credDefId || credDefReg.cred_def_id;
    const credDefLedger = parseJsonSafe(
      await fetchCredDefFromLedger(genesisAbs, credDefId),
      "creddef_ledger"
    );

    try {
      await createLinkSecret("default");
    } catch (_) {}

    const offerJson = await createCredentialOffer(credDefId, `offer-ops-${Date.now()}`);
    const requestJson = await createCredentialRequest(
      "default",
      holderDid,
      JSON.stringify(credDefLedger),
      offerJson
    );
    const requestMetadataId = extractNonce(offerJson);
    assert(typeof requestMetadataId === "string" && requestMetadataId.length > 0, "nonce inválido");

    const startTime = nowSec();
    const validityEnd = startTime + 86400 * 30;
    const issuerLocalCredentialId = `issued-ops-${Date.now()}`;

    const issuedJson = await issueRevocableCredential(
      genesisAbs,
      issuerLocalCredentialId,
      holderDid,
      credDefId,
      schemaId,
      offerJson,
      requestJson,
      JSON.stringify({
        nome: "Alice Operacional",
        cpf: "12345678900",
      }),
      startTime,
      validityEnd,
      "days",
      1,
      10,
      JSON.stringify(manifest),
      null,
      null
    );
    const issued = parseJsonSafe(issuedJson, "issued_package");
    assert(issued.issuer_record.issuer_local_credential_id === issuerLocalCredentialId, "issuer_record inesperado");

    console.log("1) listIssuedRevocableCredentials...");
    const listBeforeJson = await listIssuedRevocableCredentials("active");
    const listBefore = parseJsonSafe(listBeforeJson, "list_before");
    assert(listBefore.ok === true, "listIssuedRevocableCredentials deveria retornar ok=true");
    assert(Array.isArray(listBefore.items), "items deveria ser array");
    const listedItem = listBefore.items.find(
      (item) => item.issuer_local_credential_id === issuerLocalCredentialId
    );
    assert(listedItem, "credencial emitida deveria aparecer na listagem");
    assert(listedItem.status === "active", "status inicial deveria ser active");

    console.log("2) getIssuedRevocableCredentialSummary...");
    const summaryJson = await getIssuedRevocableCredentialSummary(issuerLocalCredentialId);
    const summary = parseJsonSafe(summaryJson, "summary");
    assert(summary.ok === true, "summary deveria retornar ok=true");
    assert(summary.issuer_record.issuer_local_credential_id === issuerLocalCredentialId, "issuer_record incorreto");
    assert(summary.revocation_summary.window_count >= 1, "window_count deveria ser >= 1");
    assert(summary.revocation_summary.k_vector_id, "summary deveria trazer k_vector_id");
    assert(summary.revocation_summary.manifest_url === `${BFILTER_BASE_URL}/manifest`, "manifest_url inesperada");

    console.log("3) preflightRevokeIssuedCredential...");
    const preflightBeforeJson = await preflightRevokeIssuedCredential(
      issuerLocalCredentialId,
      0
    );
    const preflightBefore = parseJsonSafe(preflightBeforeJson, "preflight_before");
    assert(preflightBefore.ok === true, "preflight deveria retornar ok=true");
    assert(preflightBefore.can_revoke === true, "preflight deveria permitir revogação");
    assert(Array.isArray(preflightBefore.errors) && preflightBefore.errors.length === 0, "preflight não deveria ter erros");
    assert(preflightBefore.preflight.revocation_keys_to_write >= 1, "preflight deveria prever ao menos uma chave");

    console.log("4) revokeIssuedCredentialFromWindow...");
    const revokeJson = await revokeIssuedCredentialFromWindow(
      issuerLocalCredentialId,
      BFILTER_ADMIN_TOKEN,
      0,
      "revogacao-operacional",
      "teste-node"
    );
    const revoke = parseJsonSafe(revokeJson, "revoke");
    assert(revoke.ok === true, "revokeIssuedCredentialFromWindow deveria retornar ok=true");
    assert(revoke.bloom.ok === true, "o Bloom deveria aceitar a revogação");
    assert(revoke.issuer_record.status === "revoked", "status final deveria ser revoked");
    assert(revoke.preflight.can_revoke === true, "preflight embutido deveria estar ok antes da revogação");

    console.log("5) validando estado após a revogação...");
    const listAfterJson = await listIssuedRevocableCredentials("revoked");
    const listAfter = parseJsonSafe(listAfterJson, "list_after");
    const revokedItem = listAfter.items.find(
      (item) => item.issuer_local_credential_id === issuerLocalCredentialId
    );
    assert(revokedItem, "credencial revogada deveria aparecer na listagem filtrada");
    assert(revokedItem.status === "revoked", "listagem pós-revogação deveria refletir o status");

    const preflightAfterJson = await preflightRevokeIssuedCredential(
      issuerLocalCredentialId,
      0
    );
    const preflightAfter = parseJsonSafe(preflightAfterJson, "preflight_after");
    assert(preflightAfter.can_revoke === false, "preflight após revogação deveria bloquear nova revogação");
    assert(
      preflightAfter.errors.some((msg) => String(msg).includes("já está com status revoked")),
      "preflight após revogação deveria indicar status revoked"
    );

    console.log("✅ OK: TESTE REVOGAÇÃO 42 passou.");
  } finally {
    try { await issuer.walletClose(); } catch {}
    try { await holder.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 42:", e && e.stack ? e.stack : e);
  process.exit(1);
});
