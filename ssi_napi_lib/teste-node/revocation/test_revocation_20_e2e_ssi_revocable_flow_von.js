/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
RESET_WALLET=1 \
WALLET_PASS="minha_senha_teste" \
GENESIS_FILE=./von_genesis.txn \
TRUSTEE_SEED="000000000000000000000000Trustee1" \
TRUSTEE_DID="V4SGRU86Z58d6TV7PBUe6f" \
node teste-node/revocation/test_revocation_20_e2e_ssi_revocable_flow_von.js
*/
/*
Teste E2E de credencial SSI revogável com prova complementar de revogação.

O fluxo:
- cria/abre wallets de issuer, holder e verifier;
- conecta ao ledger;
- registra Schema revogável e CredDef;
- publica manifesto de revogação no ledger e reutiliza/cria K automaticamente;
- executa offer -> request -> issue da credencial revogável;
- holder armazena a credencial e o bundle revogável;
- holder cria uma apresentação SSI com atributos de controle revelados;
- holder gera a prova complementar de revogação;
- verifier valida a apresentação e a prova complementar.

Depois valida:
- resolução correta do vetor K no ledger;
- publicação do manifesto com sucesso;
- emissão e armazenamento da credencial revogável;
- apresentação SSI válida com os atributos de controle esperados;
- prova complementar válida e vinculada à âncora K correta;
- status final indicando prova verificada e credencial ainda não revogada.

Foco do teste:
validar o fluxo E2E de emissão, apresentação e verificação
de credencial revogável com prova complementar local.
*/

const path = require("path");
const crypto = require("crypto");
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
  sampleCredentialJson,
} = require("./_helpers");

const CONTROL_ATTRS = [
  "seed",
  "start_time",
  "unit_of_time",
  "time_window",
  "root_merkle_L",
];
const REQUIRED_EXTRA_WINDOWS_FOR_FP = 10;

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function sha256Base64(input) {
  return crypto.createHash("sha256").update(input).digest("base64");
}

(async () => {
  const IndyAgent = loadIndyAgent();
  const pass = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET = process.env.RESET_WALLET === "1";
  const BFILTER_BASE_URL = process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080";

  const walletDir = ensureWalletDir();
  const issuerDb =
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_e2e_issuer.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_e2e_holder.db");
  const verifierDb =
    process.env.WALLET_VERIFIER || path.join(walletDir, "test_wallet_revocation_e2e_verifier.db");

  const genesisAbs = path.join(process.cwd(), process.env.GENESIS_FILE || NETWORK_CONFIG.genesisFile);

  await downloadGenesisHttp(NETWORK_CONFIG.genesisUrl, genesisAbs);

  if (RESET) {
    cleanupWalletFamily(issuerDb);
    cleanupWalletFamily(holderDb);
    cleanupWalletFamily(verifierDb);
  }

  const issuer = new IndyAgent();
  const holder = new IndyAgent();
  const verifier = new IndyAgent();

  await walletCreateOpenIdempotent(issuer, issuerDb, pass);
  await walletCreateOpenIdempotent(holder, holderDb, pass);
  await walletCreateOpenIdempotent(verifier, verifierDb, pass);

  try {
    await issuer.connectNetwork(genesisAbs);
    await holder.connectNetwork(genesisAbs);
    await verifier.connectNetwork(genesisAbs);

    const importDidFromSeed = fn(issuer, "importDidFromSeed", "import_did_from_seed");
    const [issuerDid] = await importDidFromSeed(NETWORK_CONFIG.trusteeSeed);
    assert(issuerDid === NETWORK_CONFIG.trusteeDid, `Trustee DID inesperado: ${issuerDid}`);

    const createAndRegisterSchema = fn(issuer, "createAndRegisterSchema", "create_and_register_schema");
    const creddefSaveLocal = fn(issuer, "creddefSaveLocal", "creddef_save_local");
    const creddefRegisterFromLocal = fn(issuer, "creddefRegisterFromLocal", "creddef_register_from_local");
    const fetchSchemaFromLedger = fn(issuer, "fetchSchemaFromLedger", "fetch_schema_from_ledger");
    const fetchCredDefFromLedger = fn(issuer, "fetchCredDefFromLedger", "fetch_cred_def_from_ledger");
    const createCredentialOffer = fn(issuer, "createCredentialOffer", "create_credential_offer");
    const createCredential = fn(issuer, "createCredential", "create_credential");
    const createLinkSecret = fn(holder, "createLinkSecret", "create_link_secret");
    const createDidV2 = fn(holder, "createDidV2", "create_did_v2");
    const createCredentialRequest = fn(holder, "createCredentialRequest", "create_credential_request");
    const storeCredential = fn(holder, "storeCredential", "store_credential");
    const createPresentation = fn(holder, "createPresentation", "create_presentation");
    const verifyPresentation = fn(verifier, "verifyPresentation", "verify_presentation");
    const revocationBuildManifestAnchor = fn(issuer, "revocationBuildManifestAnchor", "revocation_build_manifest_anchor");
    const revocationWriteManifestAnchorOnLedger = fn(issuer, "revocationWriteManifestAnchorOnLedger", "revocation_write_manifest_anchor_on_ledger");
    const issueRevocableCredential = fn(issuer, "issueRevocableCredential", "issue_revocable_credential");
    const storeReceivedRevocableCredential = fn(holder, "storeReceivedRevocableCredential", "store_received_revocable_credential");
    const buildPresentationRevocationProof = fn(holder, "buildPresentationRevocationProof", "build_presentation_revocation_proof");
    const verifyPresentationRevocationProof = fn(verifier, "verifyPresentationRevocationProof", "verify_presentation_revocation_proof");

    console.log("🚀 TESTE REVOGAÇÃO 20: E2E SSI revogável + prova complementar");

    const schemaName = `SchemaRevocableE2E_${Date.now()}`;
    const schemaVersion = `1.${nowSec()}`;
    const businessAttrs = ["nome", "cpf", "idade"];
    const schemaAttrs = [...businessAttrs, ...CONTROL_ATTRS];

    console.log("1) Registrando Schema revogável com atributos de controle...");
    const schemaId = await createAndRegisterSchema(genesisAbs, issuerDid, schemaName, schemaVersion, schemaAttrs);
    assert(typeof schemaId === "string" && schemaId.includes(":2:"), "schemaId inválido");

    console.log("2) Registrando CredDef local/ledger para o schema...");
    const localCredDefJson = await creddefSaveLocal(
      issuerDid,
      schemaId,
      `TAG_REV_E2E_${nowSec()}`,
      false,
      "prod"
    );
    const localCredDef = parseJsonSafe(localCredDefJson, "creddef_local");
    const credDefRegObj = await creddefRegisterFromLocal(genesisAbs, localCredDef.id_local, issuerDid);
    const credDefId = credDefRegObj.credDefId || credDefRegObj.cred_def_id;
    assert(typeof credDefId === "string" && credDefId.includes(":3:CL:"), "credDefId inválido");

    const schemaLedgerJson = await fetchSchemaFromLedger(genesisAbs, schemaId);
    const schemaLedgerObj = parseJsonSafe(schemaLedgerJson, "schema_ledger");
    const credDefLedgerJson = await fetchCredDefFromLedger(genesisAbs, credDefId);
    const credDefLedgerObj = parseJsonSafe(credDefLedgerJson, "creddef_ledger");

    console.log("3) Lendo e publicando manifesto de revogação...");
    const manifestResp = await fetch(`${BFILTER_BASE_URL}/manifest`);
    assert(manifestResp.ok, `Falha GET /manifest: ${manifestResp.status}`);
    const manifestBodyText = await manifestResp.text();
    const manifestEnvelope = parseJsonSafe(manifestBodyText, "manifest_body");
    assert(manifestEnvelope.ok === true, "manifesto Bloom deveria retornar ok=true");
    const manifestHash = sha256Base64(manifestBodyText);

    const manifestJson = await revocationBuildManifestAnchor(
      issuerDid,
      `${BFILTER_BASE_URL}/manifest`,
      manifestHash,
      String(manifestEnvelope.manifest.version || 1)
    );
    const manifest = parseJsonSafe(manifestJson, "manifest_anchor");
    const writeManifestJson = await revocationWriteManifestAnchorOnLedger(
      genesisAbs,
      issuerDid,
      JSON.stringify(manifest)
    );
    const writeManifest = parseJsonSafe(writeManifestJson, "write_manifest");
    assert(writeManifest.ok === true, "write manifesto falhou");

    console.log("4) Offer/Request SSI...");
    const offerId = `offer-rev-e2e-${Date.now()}`;
    const offerJson = await createCredentialOffer(credDefId, offerId);

    try {
      await createLinkSecret("default");
    } catch (_) {}

    const didRaw = await createDidV2("{}");
    const didObj = typeof didRaw === "string" ? JSON.parse(didRaw) : didRaw;
    const holderDid = didObj.did || didObj.myDid || didObj.id;
    assert(typeof holderDid === "string" && holderDid.length > 10, "holderDid inválido");

    const requestJson = await createCredentialRequest(
      "default",
      holderDid,
      JSON.stringify(credDefLedgerObj),
      offerJson
    );
    const requestMetadataId = extractNonce(offerJson);

    console.log("5) Emitindo credencial revogável em método único...");
    const startTime = nowSec();
    const validityEnd = startTime + 86400 * 30;
    const issuePackageJson = await issueRevocableCredential(
      genesisAbs,
      `revocable-e2e-${Date.now()}`,
      holderDid,
      credDefId,
      schemaId,
      offerJson,
      requestJson,
      JSON.stringify({
        nome: "Alice Revogavel",
        cpf: "12345678900",
        idade: "29",
      }),
      startTime,
      validityEnd,
      "days",
      1,
      REQUIRED_EXTRA_WINDOWS_FOR_FP,
      JSON.stringify(manifest),
      null,
      null
    );
    const pkg = parseJsonSafe(issuePackageJson, "issue_revocable_credential");
    assert(pkg.type === "ssi.revocable_credential.package", "pacote emitido inválido");
    assert(pkg.control_values.extra_windows_for_fp === REQUIRED_EXTRA_WINDOWS_FOR_FP, "extra_windows_for_fp inválido");
    assert(
      pkg.control_values.confirmation_window_count === REQUIRED_EXTRA_WINDOWS_FOR_FP,
      "confirmation_window_count inválido"
    );
    assert(pkg.k_ledger_anchor && pkg.k_ledger_anchor.k_vector_id, "K ledger anchor ausente");
    assert(
      ["created_and_written", "ledger_active", "cache_local"].includes(pkg.k_resolution_source),
      `fonte de resolução de K inesperada: ${pkg.k_resolution_source}`
    );
    const credentialJson = pkg.credential_json;
    assert(typeof credentialJson === "string" && credentialJson.length > 100, "credential_json inválido");

    console.log("6) Holder armazenando credential + bundle revogável...");
    const credentialId = `cred-rev-e2e-${Date.now()}`;
    const storedCredentialId = await storeCredential(
      credentialId,
      credentialJson,
      requestMetadataId,
      JSON.stringify(credDefLedgerObj),
      null
    );
    assert(storedCredentialId === credentialId, "credential não armazenada corretamente");

    const bundleId = `bundle-rev-e2e-${Date.now()}`;
    const storeBundleJson = await storeReceivedRevocableCredential(
      bundleId,
      JSON.stringify(pkg.holder_bundle),
      credentialId
    );
    const storeBundle = parseJsonSafe(storeBundleJson, "store_bundle");
    assert(storeBundle.ok === true, "bundle revogável não armazenado");

    console.log("7) Holder criando apresentação com controles revelados...");
    const presReq = {
      nonce: String(Date.now() * 1000 + 98765),
      name: "ProofReqRevocableE2E",
      version: "0.1",
      requested_attributes: {
        attr_nome: { name: "nome" },
        attr_seed: { name: "seed" },
        attr_start_time: { name: "start_time" },
        attr_unit_of_time: { name: "unit_of_time" },
        attr_time_window: { name: "time_window" },
        attr_root_merkle_L: { name: "root_merkle_L" },
      },
      requested_predicates: {},
    };

    const reqCreds = {
      requested_attributes: {
        attr_nome: { cred_id: credentialId, revealed: true },
        attr_seed: { cred_id: credentialId, revealed: true },
        attr_start_time: { cred_id: credentialId, revealed: true },
        attr_unit_of_time: { cred_id: credentialId, revealed: true },
        attr_time_window: { cred_id: credentialId, revealed: true },
        attr_root_merkle_L: { cred_id: credentialId, revealed: true },
      },
      requested_predicates: {},
    };

    const schemasMap = { [schemaId]: schemaLedgerObj };
    const credDefsMap = { [credDefId]: credDefLedgerObj };
    const presentationJson = await createPresentation(
      JSON.stringify(presReq),
      JSON.stringify(reqCreds),
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap)
    );
    const presentation = parseJsonSafe(presentationJson, "presentation");
    assert(
      presentation.requested_proof.revealed_attrs.attr_seed.raw === pkg.control_attributes.seed,
      "presentation deveria revelar seed"
    );
    assert(
      presentation.requested_proof.revealed_attrs.attr_start_time.raw === pkg.control_attributes.start_time,
      "presentation deveria revelar start_time"
    );
    assert(
      presentation.requested_proof.revealed_attrs.attr_root_merkle_L.raw === pkg.control_attributes.root_merkle_L,
      "presentation deveria revelar root_merkle_L"
    );

    const verified = await verifyPresentation(
      JSON.stringify(presReq),
      presentationJson,
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap)
    );
    assert(verified === true, "verifyPresentation deveria retornar true");

    console.log("8) Holder criando prova complementar de revogação...");
    const proofJson = await buildPresentationRevocationProof(bundleId, 0, credentialId);
    const proofResponse = parseJsonSafe(proofJson, "revocation_proof");
    assert(
      proofResponse.proof.k_ledger_anchor.k_vector_id === pkg.k_ledger_anchor.k_vector_id,
      "prova deveria carregar a âncora de K"
    );

    console.log("9) Verificador validando a prova complementar local...");
    proofResponse.proof.manifest = null;
    const verifyRevJson = await verifyPresentationRevocationProof(
      JSON.stringify(proofResponse.proof)
    );
    const verifyRev = parseJsonSafe(verifyRevJson, "verify_revocation");
    assert(verifyRev.ok === true, "verifyPresentationRevocationProof deveria retornar ok=true");
    assert(verifyRev.status.verified === true, "prova complementar deveria verificar");
    assert(verifyRev.status.revoked === false, "sem Bloom ainda, revoked deveria ser false");

    console.log("✅ OK: TESTE REVOGAÇÃO 20 passou.");
  } finally {
    try { await issuer.walletClose(); } catch {}
    try { await holder.walletClose(); } catch {}
    try { await verifier.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 20:", e && e.stack ? e.stack : e);
  process.exit(1);
});
