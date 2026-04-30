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
node teste-node/revocation/test_revocation_41_create_presentation_package_with_revocation_von.js

Para subir o bfilter:
cd /home/yugi/programacao/bfilter
BFILTER_ADMIN_TOKEN="dev-admin-token" cargo run
*/

/*
Teste E2E de pacote de apresentação mista com revogação.

O fluxo:
- cria/abre wallets de issuer, holder e verifier;
- conecta ao ledger e registra DID do emissor;
- ancora o manifesto de revogação no ledger;
- cria 1 credencial normal e 2 credenciais revogáveis;
- holder monta um pacote único de apresentação com provas complementares de revogação;
- verifier valida o pacote antes da revogação;
- emissor revoga uma das credenciais revogáveis;
- verifier valida novamente o mesmo pacote.

Depois valida:
- o pacote agregado é criado corretamente;
- antes da revogação a apresentação é aceita;
- após a revogação, o manifesto atualizado do Bloom é reancorado no ledger;
- após a revogação, a prova criptográfica continua válida,
  mas a apresentação passa a ser rejeitada por status de revogação.

Foco do teste:
validar createPresentationPackageWithRevocation e
verifyMixedPresentationPackage em cenário misto
(credenciais normais + revogáveis).
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
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_pkg_holder_issuer.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_pkg_holder_holder.db");
  const verifierDb =
    process.env.WALLET_VERIFIER || path.join(walletDir, "test_wallet_revocation_pkg_holder_verifier.db");

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
    const createPresentationPackageWithRevocation = fn(
      holder,
      "createPresentationPackageWithRevocation",
      "create_presentation_package_with_revocation"
    );
    const verifyMixedPresentationPackage = fn(
      verifier,
      "verifyMixedPresentationPackage",
      "verify_mixed_presentation_package"
    );
    const revocationBuildManifestAnchor = fn(issuer, "revocationBuildManifestAnchor", "revocation_build_manifest_anchor");
    const revocationWriteManifestAnchorOnLedger = fn(issuer, "revocationWriteManifestAnchorOnLedger", "revocation_write_manifest_anchor_on_ledger");
    const issueRevocableCredential = fn(issuer, "issueRevocableCredential", "issue_revocable_credential");
    const storeReceivedRevocableCredential = fn(holder, "storeReceivedRevocableCredential", "store_received_revocable_credential");
    const revokeIssuedCredential = fn(issuer, "revokeIssuedCredential", "revoke_issued_credential");

    console.log("🚀 TESTE REVOGAÇÃO 41: createPresentationPackageWithRevocation + verifyMixedPresentationPackage");

    const [trusteeDid] = await importDidFromSeed(TRUSTEE_SEED);
    assert(trusteeDid === TRUSTEE_DID, `Trustee DID inesperado: ${trusteeDid}`);

    const [issuerDid, issuerVerkey] = await issuer.createOwnDid();
    const didRaw = await createDidV2("{}");
    const didObj = typeof didRaw === "string" ? JSON.parse(didRaw) : didRaw;
    const holderDid = didObj.did || didObj.myDid || didObj.id;
    assert(typeof holderDid === "string" && holderDid.length > 10, "holderDid inválido");

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
    const writeManifestJson = await revocationWriteManifestAnchorOnLedger(
      genesisAbs,
      issuerDid,
      JSON.stringify(manifest)
    );
    const writeManifest = parseJsonSafe(writeManifestJson, "write_manifest");
    assert(writeManifest.ok === true, "write manifesto falhou");

    const schemaIdNormal = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaNormalPkg_${Date.now()}`,
      `1.${nowSec()}`,
      ["nome", "matricula", "curso"]
    );
    const schemaIdRev1 = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaRevPkg1_${Date.now()}`,
      `1.${nowSec() + 1}`,
      ["nome", "cpf", "idade", ...CONTROL_ATTRS]
    );
    const schemaIdRev2 = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaRevPkg2_${Date.now()}`,
      `1.${nowSec() + 2}`,
      ["email", "telefone", ...CONTROL_ATTRS]
    );

    async function registerCredDef(schemaId, tag) {
      const localJson = await creddefSaveLocal(issuerDid, schemaId, tag, false, "prod");
      const local = parseJsonSafe(localJson, `creddef_local_${tag}`);
      const reg = await creddefRegisterFromLocal(genesisAbs, local.id_local, issuerDid);
      return reg.credDefId || reg.cred_def_id;
    }

    const credDefIdNormal = await registerCredDef(schemaIdNormal, `TAG_NORMAL_HOLDER_${Date.now()}`);
    const credDefIdRev1 = await registerCredDef(schemaIdRev1, `TAG_REV1_HOLDER_${Date.now()}`);
    const credDefIdRev2 = await registerCredDef(schemaIdRev2, `TAG_REV2_HOLDER_${Date.now()}`);

    const schemaNormalLedger = parseJsonSafe(await fetchSchemaFromLedger(genesisAbs, schemaIdNormal), "schema_normal");
    const schemaRev1Ledger = parseJsonSafe(await fetchSchemaFromLedger(genesisAbs, schemaIdRev1), "schema_rev1");
    const schemaRev2Ledger = parseJsonSafe(await fetchSchemaFromLedger(genesisAbs, schemaIdRev2), "schema_rev2");
    const credDefNormalLedger = parseJsonSafe(await fetchCredDefFromLedger(genesisAbs, credDefIdNormal), "creddef_normal");
    const credDefRev1Ledger = parseJsonSafe(await fetchCredDefFromLedger(genesisAbs, credDefIdRev1), "creddef_rev1");
    const credDefRev2Ledger = parseJsonSafe(await fetchCredDefFromLedger(genesisAbs, credDefIdRev2), "creddef_rev2");

    try {
      await createLinkSecret("default");
    } catch (_) {}

    const offerNormalJson = await createCredentialOffer(credDefIdNormal, `offer-normal-${Date.now()}`);
    const requestNormalJson = await createCredentialRequest(
      "default",
      holderDid,
      JSON.stringify(credDefNormalLedger),
      offerNormalJson
    );
    const requestNormalMetadataId = extractNonce(offerNormalJson);
    const normalCredentialJson = await createCredential(
      credDefIdNormal,
      offerNormalJson,
      requestNormalJson,
      JSON.stringify({
        nome: "Alice Normal",
        matricula: "2026001",
        curso: "Computacao",
      })
    );
    const normalCredentialId = `cred-normal-${Date.now()}`;
    await storeCredential(
      normalCredentialId,
      normalCredentialJson,
      requestNormalMetadataId,
      JSON.stringify(credDefNormalLedger),
      null
    );

    const startTime = nowSec();
    const validityEnd = startTime + 86400 * 30;

    const offerRev1Json = await createCredentialOffer(credDefIdRev1, `offer-rev1-${Date.now()}`);
    const offerRev2Json = await createCredentialOffer(credDefIdRev2, `offer-rev2-${Date.now()}`);
    const requestRev1Json = await createCredentialRequest(
      "default",
      holderDid,
      JSON.stringify(credDefRev1Ledger),
      offerRev1Json
    );
    const requestRev2Json = await createCredentialRequest(
      "default",
      holderDid,
      JSON.stringify(credDefRev2Ledger),
      offerRev2Json
    );
    const requestRev1MetadataId = extractNonce(offerRev1Json);
    const requestRev2MetadataId = extractNonce(offerRev2Json);

    const issueRev1 = parseJsonSafe(
      await issueRevocableCredential(
        genesisAbs,
        `issued-rev1-${Date.now()}`,
        holderDid,
        credDefIdRev1,
        schemaIdRev1,
        offerRev1Json,
        requestRev1Json,
        JSON.stringify({
          nome: "Alice Rev One",
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
      ),
      "issue_rev1"
    );

    const issueRev2 = parseJsonSafe(
      await issueRevocableCredential(
        genesisAbs,
        `issued-rev2-${Date.now()}`,
        holderDid,
        credDefIdRev2,
        schemaIdRev2,
        offerRev2Json,
        requestRev2Json,
        JSON.stringify({
          email: "alice@example.org",
          telefone: "+5511999999999",
        }),
        startTime,
        validityEnd,
        "days",
        1,
        10,
        JSON.stringify(manifest),
        null,
        null
      ),
      "issue_rev2"
    );

    const revocableCredential1Id = `cred-rev1-${Date.now()}`;
    const revocableCredential2Id = `cred-rev2-${Date.now()}`;
    await storeCredential(
      revocableCredential1Id,
      issueRev1.credential_json,
      requestRev1MetadataId,
      JSON.stringify(credDefRev1Ledger),
      null
    );
    await storeCredential(
      revocableCredential2Id,
      issueRev2.credential_json,
      requestRev2MetadataId,
      JSON.stringify(credDefRev2Ledger),
      null
    );

    parseJsonSafe(
      await storeReceivedRevocableCredential(
        `bundle-rev1-${Date.now()}`,
        JSON.stringify(issueRev1.holder_bundle),
        revocableCredential1Id
      ),
      "store_bundle_rev1"
    );
    parseJsonSafe(
      await storeReceivedRevocableCredential(
        `bundle-rev2-${Date.now()}`,
        JSON.stringify(issueRev2.holder_bundle),
        revocableCredential2Id
      ),
      "store_bundle_rev2"
    );

    const presReq = {
      nonce: String(Date.now() * 1000 + 67890),
      name: "ProofReqMixedRevocationPackageHolder",
      version: "0.1",
      requested_attributes: {
        attr_matricula: { name: "matricula", restrictions: [{ cred_def_id: credDefIdNormal }] },
        attr_curso: { name: "curso", restrictions: [{ cred_def_id: credDefIdNormal }] },
        attr_cpf: { name: "cpf", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_email: { name: "email", restrictions: [{ cred_def_id: credDefIdRev2 }] },
        attr_seed_rev1: { name: "seed", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_start_rev1: { name: "start_time", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_unit_rev1: { name: "unit_of_time", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_window_rev1: { name: "time_window", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_root_rev1: { name: "root_merkle_L", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_seed_rev2: { name: "seed", restrictions: [{ cred_def_id: credDefIdRev2 }] },
        attr_start_rev2: { name: "start_time", restrictions: [{ cred_def_id: credDefIdRev2 }] },
        attr_unit_rev2: { name: "unit_of_time", restrictions: [{ cred_def_id: credDefIdRev2 }] },
        attr_window_rev2: { name: "time_window", restrictions: [{ cred_def_id: credDefIdRev2 }] },
        attr_root_rev2: { name: "root_merkle_L", restrictions: [{ cred_def_id: credDefIdRev2 }] },
      },
      requested_predicates: {},
    };

    const reqCreds = {
      requested_attributes: {
        attr_matricula: { cred_id: normalCredentialId, revealed: true },
        attr_curso: { cred_id: normalCredentialId, revealed: true },
        attr_cpf: { cred_id: revocableCredential1Id, revealed: true },
        attr_email: { cred_id: revocableCredential2Id, revealed: true },
        attr_seed_rev1: { cred_id: revocableCredential1Id, revealed: true },
        attr_start_rev1: { cred_id: revocableCredential1Id, revealed: true },
        attr_unit_rev1: { cred_id: revocableCredential1Id, revealed: true },
        attr_window_rev1: { cred_id: revocableCredential1Id, revealed: true },
        attr_root_rev1: { cred_id: revocableCredential1Id, revealed: true },
        attr_seed_rev2: { cred_id: revocableCredential2Id, revealed: true },
        attr_start_rev2: { cred_id: revocableCredential2Id, revealed: true },
        attr_unit_rev2: { cred_id: revocableCredential2Id, revealed: true },
        attr_window_rev2: { cred_id: revocableCredential2Id, revealed: true },
        attr_root_rev2: { cred_id: revocableCredential2Id, revealed: true },
      },
      requested_predicates: {},
    };

    const schemasMap = {
      [schemaIdNormal]: schemaNormalLedger,
      [schemaIdRev1]: schemaRev1Ledger,
      [schemaIdRev2]: schemaRev2Ledger,
    };
    const credDefsMap = {
      [credDefIdNormal]: credDefNormalLedger,
      [credDefIdRev1]: credDefRev1Ledger,
      [credDefIdRev2]: credDefRev2Ledger,
    };

    console.log("6) Holder criando o pacote agregado de apresentação + revogação...");
    const packageJson = await createPresentationPackageWithRevocation(
      JSON.stringify(presReq),
      JSON.stringify(reqCreds),
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap),
      JSON.stringify([
        { credential_id_local: revocableCredential1Id, window_index: 0 },
        { credential_id_local: revocableCredential2Id, window_index: 0 },
      ])
    );
    const presentationPackage = parseJsonSafe(packageJson, "presentation_package");
    assert(presentationPackage.ok === true, "createPresentationPackageWithRevocation deveria retornar ok=true");
    assert(typeof presentationPackage.presentation_json === "string", "presentation_json deveria ser string");
    assert(Array.isArray(presentationPackage.used_credentials), "used_credentials deveria ser array");
    assert(Array.isArray(presentationPackage.revocation_proofs), "revocation_proofs deveria ser array");
    assert(presentationPackage.used_credentials.length === 3, "o pacote deveria listar 3 credenciais usadas");
    assert(presentationPackage.revocation_proofs.length === 2, "o pacote deveria incluir 2 provas complementares");
    assert(presentationPackage.revocable_credentials_count === 2, "o pacote deveria contar 2 credenciais revogáveis");

    const normalEntry = presentationPackage.used_credentials.find((item) => item.credential_id_local === normalCredentialId);
    assert(normalEntry && normalEntry.revocable === false, "a credencial normal deveria aparecer como não revogável");
    const revocationProofsBeforeJson = JSON.stringify(
      presentationPackage.revocation_proofs.map((item) => ({
        credential_id_local: item.credential_id_local,
        proof: item.proof,
      }))
    );

    const beforeJson = await verifyMixedPresentationPackage(
      JSON.stringify(presReq),
      presentationPackage.presentation_json,
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap),
      revocationProofsBeforeJson,
      null
    );
    const before = parseJsonSafe(beforeJson, "verify_mixed_before");
    assert(before.ok === true, "verifyMixedPresentationPackage deveria retornar ok=true");
    assert(before.cryptographic_valid === true, "a apresentação mista deveria ser criptograficamente válida");
    assert(before.proofs_verified === true, "as provas complementares deveriam verificar");
    assert(before.revoked === false, "antes da revogação nenhuma credencial deveria estar revogada");
    assert(before.accepted === true, "antes da revogação a apresentação deveria ser aceita");

    console.log("7) Revogando uma das credenciais revogáveis e revalidando o pacote...");
    const revokeJson = await revokeIssuedCredential(
      issueRev1.issuer_record.issuer_local_credential_id,
      BFILTER_ADMIN_TOKEN,
      0,
      "revogacao-usando-presentation-package",
      "teste-node"
    );
    const revokeResponse = parseJsonSafe(revokeJson, "revoke_rev1");
    assert(revokeResponse.ok === true, "revokeIssuedCredential deveria retornar ok=true");

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

    const revocationProofsAfterJson = JSON.stringify(
      presentationPackage.revocation_proofs.map((item) => ({
        credential_id_local: item.credential_id_local,
        proof: {
          ...item.proof,
          manifest: writeManifestAfter.manifest,
        },
      }))
    );

    const afterJson = await verifyMixedPresentationPackage(
      JSON.stringify(presReq),
      presentationPackage.presentation_json,
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap),
      revocationProofsAfterJson,
      null
    );
    const after = parseJsonSafe(afterJson, "verify_mixed_after");
    assert(after.cryptographic_valid === true, "criptograficamente a apresentação deve continuar válida");
    assert(after.proofs_verified === true, "as provas complementares devem continuar verificando");
    assert(after.revoked === true, "o consolidado deve indicar revogação");
    assert(after.accepted === false, "a apresentação não deve ser aceita após revogação");

    console.log("✅ OK: TESTE REVOGAÇÃO 41 passou.");
  } finally {
    try { await issuer.walletClose(); } catch {}
    try { await holder.walletClose(); } catch {}
    try { await verifier.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 41:", e && e.stack ? e.stack : e);
  process.exit(1);
});
