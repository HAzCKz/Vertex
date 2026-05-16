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
node teste-node/revocation/test_revocation_22_bloom_service_integration_von.js

Para subir o bfilter:
cd /home/yugi/programacao/bfilter
BFILTER_ADMIN_TOKEN="dev-admin-token" cargo run
*/
/*
Teste E2E de integração real com o serviço Bloom para revogação.

O fluxo:
- cria/abre wallets de issuer, holder e verifier;
- conecta ao ledger e importa o DID Trustee;
- lê o manifesto atual do serviço Bloom;
- registra Schema/CredDef revogáveis;
- ancora o manifesto do serviço Bloom no ledger;
- executa offer -> request -> issue da credencial revogável;
- holder armazena a credencial e o bundle revogável;
- cria uma apresentação SSI normal;
- gera e verifica a prova complementar antes da revogação;
- revoga a credencial no serviço Bloom;
- verifica novamente a mesma prova após a revogação.

Depois valida:
- manifesto do Bloom acessível e ancorado no ledger;
- emissão correta da credencial revogável;
- armazenamento correto da credencial e do bundle;
- apresentação SSI válida;
- antes da revogação, a prova complementar verifica com revoked=false;
- após a revogação, o manifesto é reancorado no ledger;
- após a revogação, a prova continua válida localmente,
  mas passa a indicar revoked=true quando validada com a âncora atualizada.

Foco do teste:
validar a integração ponta a ponta entre ledger, credencial revogável
e serviço Bloom real no fluxo de verificação de revogação.
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

(async () => {
  const IndyAgent = loadIndyAgent();
  const pass = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET = process.env.RESET_WALLET === "1";
  const BFILTER_BASE_URL = process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080";
  const BFILTER_ADMIN_TOKEN = process.env.BFILTER_ADMIN_TOKEN || "dev-admin-token";

  const walletDir = ensureWalletDir();
  const issuerDb =
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_bloom_issuer.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_bloom_holder.db");
  const verifierDb =
    process.env.WALLET_VERIFIER || path.join(walletDir, "test_wallet_revocation_bloom_verifier.db");

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
    const revokeIssuedCredential = fn(issuer, "revokeIssuedCredential", "revoke_issued_credential");

    console.log("🚀 TESTE REVOGAÇÃO 22: integração real com serviço Bloom");

    console.log("1) Lendo manifesto atual do serviço Bloom...");
    const manifestResp = await fetch(`${BFILTER_BASE_URL}/manifest`);
    assert(manifestResp.ok, `Falha GET /manifest: ${manifestResp.status}`);
    const manifestBodyText = await manifestResp.text();
    const manifestEnvelope = JSON.parse(manifestBodyText);
    assert(manifestEnvelope.ok === true, "manifesto Bloom deveria retornar ok=true");
    const manifestHash = sha256Base64(manifestBodyText);

    const schemaName = `SchemaRevocableBloom_${Date.now()}`;
    const schemaVersion = `1.${nowSec()}`;
    const businessAttrs = ["nome", "cpf", "idade"];
    const schemaAttrs = [...businessAttrs, ...CONTROL_ATTRS];

    console.log("2) Registrando Schema/CredDef revogáveis...");
    const schemaId = await createAndRegisterSchema(genesisAbs, issuerDid, schemaName, schemaVersion, schemaAttrs);
    assert(typeof schemaId === "string" && schemaId.includes(":2:"), "schemaId inválido");

    const localCredDefJson = await creddefSaveLocal(
      issuerDid,
      schemaId,
      `TAG_REV_BLOOM_${nowSec()}`,
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

    console.log("3) Ancorando manifesto do serviço Bloom no ledger...");
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
    const offerId = `offer-rev-bloom-${Date.now()}`;
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
      `revocable-bloom-${Date.now()}`,
      holderDid,
      credDefId,
      schemaId,
      offerJson,
      requestJson,
      JSON.stringify({
        nome: "Alice Bloom",
        cpf: "12345678900",
        idade: "29",
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
    const pkg = parseJsonSafe(issuePackageJson, "issue_revocable_credential");
    assert(pkg.type === "ssi.revocable_credential.package", "pacote emitido inválido");
    assert(pkg.manifest.manifest_url === `${BFILTER_BASE_URL}/manifest`, "manifest_url não propagado");
    assert(pkg.k_ledger_anchor && pkg.k_ledger_anchor.k_vector_id, "K ledger anchor ausente");

    console.log("6) Holder armazenando credential + bundle...");
    const credentialId = `cred-rev-bloom-${Date.now()}`;
    const storedCredentialId = await storeCredential(
      credentialId,
      pkg.credential_json,
      requestMetadataId,
      JSON.stringify(credDefLedgerObj),
      null
    );
    assert(storedCredentialId === credentialId, "credential não armazenada corretamente");

    const bundleId = `bundle-rev-bloom-${Date.now()}`;
    const storeBundleJson = await storeReceivedRevocableCredential(
      bundleId,
      JSON.stringify(pkg.holder_bundle),
      credentialId
    );
    const storeBundle = parseJsonSafe(storeBundleJson, "store_bundle");
    assert(storeBundle.ok === true, "bundle revogável não armazenado");

    console.log("7) Criando apresentação SSI normal...");
    const presReq = {
      nonce: String(Date.now() * 1000 + 45678),
      name: "ProofReqRevocableBloom",
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
    const verified = await verifyPresentation(
      JSON.stringify(presReq),
      presentationJson,
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap)
    );
    assert(verified === true, "verifyPresentation deveria retornar true");

    console.log("8) Validando prova complementar antes da revogação...");
    const proofJson = await buildPresentationRevocationProof(bundleId, 0, credentialId);
    const proofResponse = parseJsonSafe(proofJson, "revocation_proof");
    const verifyBeforeJson = await verifyPresentationRevocationProof(
      JSON.stringify(proofResponse.proof)
    );
    const verifyBefore = parseJsonSafe(verifyBeforeJson, "verify_before");
    assert(verifyBefore.ok === true, "verify before deveria retornar ok=true");
    assert(verifyBefore.status.verified === true, "prova local deveria validar");
    assert(verifyBefore.status.revoked === false, "antes da revogação o Bloom deveria responder false");

    console.log("9) Revogando a credencial emitida no serviço Bloom...");
    const revokeJson = await revokeIssuedCredential(
      pkg.issuer_record.issuer_local_credential_id,
      BFILTER_ADMIN_TOKEN,
      0,
      "revogacao-e2e",
      "teste-node"
    );
    const revokeResponse = parseJsonSafe(revokeJson, "revoke_issued_credential");
    assert(revokeResponse.ok === true, "revokeIssuedCredential deveria retornar ok=true");
    assert(revokeResponse.bloom.ok === true, "serviço Bloom deveria confirmar a escrita");
    assert(revokeResponse.issuer_record.status === "revoked", "issuer_record deveria ficar revogado");

    console.log("10) Reancorando o manifesto atualizado após a revogação...");
    const manifestAfterResp = await fetch(`${BFILTER_BASE_URL}/manifest`);
    assert(manifestAfterResp.ok, `Falha GET /manifest após revogação: ${manifestAfterResp.status}`);
    const manifestAfterBodyText = await manifestAfterResp.text();
    const manifestAfterEnvelope = JSON.parse(manifestAfterBodyText);
    assert(manifestAfterEnvelope.ok === true, "manifesto Bloom pós-revogação deveria retornar ok=true");
    const manifestAfterHash = sha256Base64(manifestAfterBodyText);

    const manifestAfterJson = await revocationBuildManifestAnchor(
      issuerDid,
      `${BFILTER_BASE_URL}/manifest`,
      manifestAfterHash,
      String(manifestAfterEnvelope.manifest.version || 1)
    );
    const writeManifestAfterJson = await revocationWriteManifestAnchorOnLedger(
      genesisAbs,
      issuerDid,
      manifestAfterJson
    );
    const writeManifestAfter = parseJsonSafe(writeManifestAfterJson, "write_manifest_after");
    assert(writeManifestAfter.ok === true, "reanchor do manifesto após revogação falhou");

    console.log("11) Validando prova complementar após a revogação...");
    const proofAfterRevocation = {
      ...proofResponse.proof,
      manifest: writeManifestAfter.manifest,
    };
    const verifyAfterJson = await verifyPresentationRevocationProof(
      JSON.stringify(proofAfterRevocation)
    );
    const verifyAfter = parseJsonSafe(verifyAfterJson, "verify_after");
    assert(verifyAfter.ok === true, "verify after deveria retornar ok=true");
    assert(verifyAfter.status.verified === true, "prova local deveria continuar válida");
    assert(verifyAfter.status.revoked === true, "após a revogação o Bloom deveria responder true");

    console.log("✅ OK: TESTE REVOGAÇÃO 22 passou.");
  } finally {
    try { await issuer.walletClose(); } catch {}
    try { await holder.walletClose(); } catch {}
    try { await verifier.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 22:", e && e.stack ? e.stack : e);
  process.exit(1);
});
