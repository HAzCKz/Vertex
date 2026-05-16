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
node teste-node/revocation/test_revocation_43_daily_windows_multi_day_packages_von.js

Para subir o bfilter:
cd /home/yugi/programacao/bfilter
BFILTER_ADMIN_TOKEN="dev-admin-token" cargo run
*/

/*
Teste E2E de apresentação mista com 2 credenciais revogáveis em 365 janelas diárias.

O fluxo:
- cria/abre wallets de issuer, holder e verifier;
- conecta ao ledger e registra os 3 DIDs;
- ancora o manifesto do Bloom no ledger;
- cria 1 credencial normal e 2 revogáveis;
- emite as 2 revogáveis com 365 janelas válidas de 1 dia e 10 extras de confirmação;
- holder monta pacotes de apresentação para dias arbitrários (5, 10, 30, 90);
- verifier valida cada pacote;
- issuer revoga uma das credenciais a partir da janela 30;
- verifier revalida os pacotes para confirmar que:
  - dias anteriores à revogação continuam válidos;
  - a partir da janela revogada, a apresentação passa a ser rejeitada;
  - o Bloom recebeu uma entrada para cada janela posterior/inclusiva.

Foco do teste:
validar múltiplas janelas diárias, efeito cumulativo da revogação
e contagem de entradas no Bloom filter.

Depois da revogação, o teste reancora o manifesto atualizado do Bloom
antes de revalidar os pacotes.
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

const WINDOW_DAYS = [5, 10, 30, 90];
const REQUIRED_EXTRA_WINDOWS_FOR_FP = 10;
const TOTAL_WINDOW_COUNT = 365 + REQUIRED_EXTRA_WINDOWS_FOR_FP;

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

async function fetchManifestEnvelope(baseUrl) {
  const resp = await fetch(`${baseUrl}/manifest`);
  assert(resp.ok, `Falha GET /manifest: ${resp.status}`);
  const manifestBodyText = await resp.text();
  const envelope = JSON.parse(manifestBodyText);
  assert(envelope.ok === true, "manifesto Bloom deveria retornar ok=true");
  envelope.manifest_hash_body = sha256Base64(manifestBodyText);
  return envelope;
}

function getActiveInsertedCount(manifestEnvelope) {
  const manifest = manifestEnvelope.manifest || {};
  const activeId = manifest.active_filter_id;
  const filters = Array.isArray(manifest.filters) ? manifest.filters : [];
  const active = filters.find((item) => item.filter_id === activeId) || filters[filters.length - 1];
  return Number(active?.inserted_count || 0);
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
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_daily_windows_issuer.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_daily_windows_holder.db");
  const verifierDb =
    process.env.WALLET_VERIFIER || path.join(walletDir, "test_wallet_revocation_daily_windows_verifier.db");

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
    const createCredentialRequest = fn(holder, "createCredentialRequest", "create_credential_request");
    const createLinkSecret = fn(holder, "createLinkSecret", "create_link_secret");
    const storeCredential = fn(holder, "storeCredential", "store_credential");
    const revocationBuildManifestAnchor = fn(issuer, "revocationBuildManifestAnchor", "revocation_build_manifest_anchor");
    const revocationWriteManifestAnchorOnLedger = fn(issuer, "revocationWriteManifestAnchorOnLedger", "revocation_write_manifest_anchor_on_ledger");
    const issueRevocableCredential = fn(issuer, "issueRevocableCredential", "issue_revocable_credential");
    const storeReceivedRevocableCredential = fn(holder, "storeReceivedRevocableCredential", "store_received_revocable_credential");
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

    console.log("🚀 TESTE REVOGAÇÃO 43: janelas diárias arbitrárias + delta do Bloom");

    console.log("1) Criando e registrando os 3 atores SSI...");
    const [trusteeDid] = await importDidFromSeed(TRUSTEE_SEED);
    assert(trusteeDid === TRUSTEE_DID, `Trustee DID inesperado: ${trusteeDid}`);

    const [issuerDid, issuerVerkey] = await issuer.createOwnDid();
    const [holderDid, holderVerkey] = await holder.createOwnDid();
    const [verifierDid, verifierVerkey] = await verifier.createOwnDid();

    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, issuerDid, issuerVerkey, "ENDORSER");
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, holderDid, holderVerkey, "ENDORSER");
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, verifierDid, verifierVerkey, "ENDORSER");

    console.log("2) Ancorando manifesto do Bloom no ledger...");
    const manifestEnvelopeBefore = await fetchManifestEnvelope(BFILTER_BASE_URL);
    const manifestHash = manifestEnvelopeBefore.manifest_hash_body;
    const manifestJson = await revocationBuildManifestAnchor(
      issuerDid,
      `${BFILTER_BASE_URL}/manifest`,
      manifestHash,
      String(manifestEnvelopeBefore.manifest.version || 1)
    );
    const manifest = parseJsonSafe(manifestJson, "manifest_anchor");
    const writeManifestJson = await revocationWriteManifestAnchorOnLedger(
      genesisAbs,
      issuerDid,
      JSON.stringify(manifest)
    );
    const writeManifest = parseJsonSafe(writeManifestJson, "write_manifest");
    assert(writeManifest.ok === true, "write manifesto falhou");

    console.log("3) Registrando 1 schema normal e 2 revogáveis...");
    const schemaIdNormal = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaNormalDays_${Date.now()}`,
      `1.${nowSec()}`,
      ["nome", "matricula", "curso"]
    );
    const schemaIdRev1 = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaRevDays1_${Date.now()}`,
      `1.${nowSec() + 1}`,
      ["nome", "cpf", "idade", ...CONTROL_ATTRS]
    );
    const schemaIdRev2 = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaRevDays2_${Date.now()}`,
      `1.${nowSec() + 2}`,
      ["email", "telefone", ...CONTROL_ATTRS]
    );

    async function registerCredDef(schemaId, tag) {
      const localJson = await creddefSaveLocal(issuerDid, schemaId, tag, false, "prod");
      const local = parseJsonSafe(localJson, `creddef_local_${tag}`);
      const reg = await creddefRegisterFromLocal(genesisAbs, local.id_local, issuerDid);
      return reg.credDefId || reg.cred_def_id;
    }

    const credDefIdNormal = await registerCredDef(schemaIdNormal, `TAG_NORMAL_DAYS_${Date.now()}`);
    const credDefIdRev1 = await registerCredDef(schemaIdRev1, `TAG_REV1_DAYS_${Date.now()}`);
    const credDefIdRev2 = await registerCredDef(schemaIdRev2, `TAG_REV2_DAYS_${Date.now()}`);

    const schemaNormalLedger = parseJsonSafe(await fetchSchemaFromLedger(genesisAbs, schemaIdNormal), "schema_normal");
    const schemaRev1Ledger = parseJsonSafe(await fetchSchemaFromLedger(genesisAbs, schemaIdRev1), "schema_rev1");
    const schemaRev2Ledger = parseJsonSafe(await fetchSchemaFromLedger(genesisAbs, schemaIdRev2), "schema_rev2");
    const credDefNormalLedger = parseJsonSafe(await fetchCredDefFromLedger(genesisAbs, credDefIdNormal), "creddef_normal");
    const credDefRev1Ledger = parseJsonSafe(await fetchCredDefFromLedger(genesisAbs, credDefIdRev1), "creddef_rev1");
    const credDefRev2Ledger = parseJsonSafe(await fetchCredDefFromLedger(genesisAbs, credDefIdRev2), "creddef_rev2");

    try {
      await createLinkSecret("default");
    } catch (_) {}

    console.log("4) Emitindo a credencial normal...");
    const offerNormalJson = await createCredentialOffer(credDefIdNormal, `offer-normal-days-${Date.now()}`);
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
    const normalCredentialId = `cred-normal-days-${Date.now()}`;
    await storeCredential(
      normalCredentialId,
      normalCredentialJson,
      requestNormalMetadataId,
      JSON.stringify(credDefNormalLedger),
      null
    );

    console.log("5) Emitindo 2 credenciais revogáveis com 365 janelas diárias...");
    const startTime = nowSec();
    const validityEnd = startTime + 86400 * 364;

    async function issueAndStoreRevocable({
      issuerLocalCredentialId,
      credentialId,
      bundleId,
      credDefId,
      schemaId,
      credDefLedger,
      values,
    }) {
      const offerJson = await createCredentialOffer(credDefId, `offer-${issuerLocalCredentialId}`);
      const requestJson = await createCredentialRequest(
        "default",
        holderDid,
        JSON.stringify(credDefLedger),
        offerJson
      );
      const requestMetadataId = extractNonce(offerJson);

      const issuedJson = await issueRevocableCredential(
        genesisAbs,
        issuerLocalCredentialId,
        holderDid,
        credDefId,
        schemaId,
        offerJson,
        requestJson,
        JSON.stringify(values),
        startTime,
        validityEnd,
        "days",
        1,
        REQUIRED_EXTRA_WINDOWS_FOR_FP,
        JSON.stringify(manifest),
        null,
        null
      );
      const issued = parseJsonSafe(issuedJson, `issued_${issuerLocalCredentialId}`);
      assert(issued.ok === true || issued.type === "ssi.revocable_credential.package", "pacote revogável inválido");

      const storedCredentialId = await storeCredential(
        credentialId,
        issued.credential_json,
        requestMetadataId,
        JSON.stringify(credDefLedger),
        null
      );
      assert(storedCredentialId === credentialId, "credential revogável não armazenada corretamente");

      const storeBundleJson = await storeReceivedRevocableCredential(
        bundleId,
        JSON.stringify(issued.holder_bundle),
        credentialId
      );
      const storeBundle = parseJsonSafe(storeBundleJson, `store_bundle_${issuerLocalCredentialId}`);
      assert(storeBundle.ok === true, "bundle revogável não armazenado");

      return issued;
    }

    const rev1CredentialId = `cred-rev1-days-${Date.now()}`;
    const rev2CredentialId = `cred-rev2-days-${Date.now()}`;
    const rev1BundleId = `bundle-rev1-days-${Date.now()}`;
    const rev2BundleId = `bundle-rev2-days-${Date.now()}`;
    const rev1IssuerLocalId = `issued-rev1-days-${Date.now()}`;
    const rev2IssuerLocalId = `issued-rev2-days-${Date.now()}`;

    await issueAndStoreRevocable({
      issuerLocalCredentialId: rev1IssuerLocalId,
      credentialId: rev1CredentialId,
      bundleId: rev1BundleId,
      credDefId: credDefIdRev1,
      schemaId: schemaIdRev1,
      credDefLedger: credDefRev1Ledger,
      values: {
        nome: "Alice Revogavel 1",
        cpf: "12345678900",
        idade: "29",
      },
    });

    await issueAndStoreRevocable({
      issuerLocalCredentialId: rev2IssuerLocalId,
      credentialId: rev2CredentialId,
      bundleId: rev2BundleId,
      credDefId: credDefIdRev2,
      schemaId: schemaIdRev2,
      credDefLedger: credDefRev2Ledger,
      values: {
        email: "alice@example.org",
        telefone: "+5511999999999",
      },
    });

    const summaryRev1 = parseJsonSafe(
      await getIssuedRevocableCredentialSummary(rev1IssuerLocalId),
      "summary_rev1"
    );
    const summaryRev2 = parseJsonSafe(
      await getIssuedRevocableCredentialSummary(rev2IssuerLocalId),
      "summary_rev2"
    );
    assert(summaryRev1.revocation_summary.window_count === TOTAL_WINDOW_COUNT, `rev1 deveria ter ${TOTAL_WINDOW_COUNT} janelas`);
    assert(summaryRev2.revocation_summary.window_count === TOTAL_WINDOW_COUNT, `rev2 deveria ter ${TOTAL_WINDOW_COUNT} janelas`);

    const presReq = {
      nonce: String(Date.now() * 1000 + 43123),
      name: "ProofReqDailyWindows",
      version: "0.1",
      requested_attributes: {
        attr_normal_nome: { name: "nome", restrictions: [{ cred_def_id: credDefIdNormal }] },
        attr_rev1_nome: { name: "nome", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_rev1_seed: { name: "seed", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_rev1_start: { name: "start_time", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_rev1_unit: { name: "unit_of_time", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_rev1_window: { name: "time_window", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_rev1_root: { name: "root_merkle_L", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_rev2_email: { name: "email", restrictions: [{ cred_def_id: credDefIdRev2 }] },
        attr_rev2_seed: { name: "seed", restrictions: [{ cred_def_id: credDefIdRev2 }] },
        attr_rev2_start: { name: "start_time", restrictions: [{ cred_def_id: credDefIdRev2 }] },
        attr_rev2_unit: { name: "unit_of_time", restrictions: [{ cred_def_id: credDefIdRev2 }] },
        attr_rev2_window: { name: "time_window", restrictions: [{ cred_def_id: credDefIdRev2 }] },
        attr_rev2_root: { name: "root_merkle_L", restrictions: [{ cred_def_id: credDefIdRev2 }] },
      },
      requested_predicates: {},
    };

    const reqCreds = {
      requested_attributes: {
        attr_normal_nome: { cred_id: normalCredentialId, revealed: true },
        attr_rev1_nome: { cred_id: rev1CredentialId, revealed: true },
        attr_rev1_seed: { cred_id: rev1CredentialId, revealed: true },
        attr_rev1_start: { cred_id: rev1CredentialId, revealed: true },
        attr_rev1_unit: { cred_id: rev1CredentialId, revealed: true },
        attr_rev1_window: { cred_id: rev1CredentialId, revealed: true },
        attr_rev1_root: { cred_id: rev1CredentialId, revealed: true },
        attr_rev2_email: { cred_id: rev2CredentialId, revealed: true },
        attr_rev2_seed: { cred_id: rev2CredentialId, revealed: true },
        attr_rev2_start: { cred_id: rev2CredentialId, revealed: true },
        attr_rev2_unit: { cred_id: rev2CredentialId, revealed: true },
        attr_rev2_window: { cred_id: rev2CredentialId, revealed: true },
        attr_rev2_root: { cred_id: rev2CredentialId, revealed: true },
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

    async function buildAndVerifyForDay(dayIndex, manifestOverride = null) {
      const packageJson = await createPresentationPackageWithRevocation(
        JSON.stringify(presReq),
        JSON.stringify(reqCreds),
        JSON.stringify(schemasMap),
        JSON.stringify(credDefsMap),
        JSON.stringify([
          { credential_id_local: rev1CredentialId, window_index: dayIndex },
          { credential_id_local: rev2CredentialId, window_index: dayIndex },
        ])
      );
      const presentationPackage = parseJsonSafe(packageJson, `presentation_package_day_${dayIndex}`);
      assert(presentationPackage.ok === true, "createPresentationPackageWithRevocation deveria retornar ok=true");
      assert(presentationPackage.revocation_proofs.length === 2, "o pacote deveria conter 2 provas revogáveis");
      assert(
        presentationPackage.revocation_proofs.every((item) => item.window_index === dayIndex),
        `todas as provas deveriam ser da janela ${dayIndex}`
      );
      const revocationProofsForVerification = presentationPackage.revocation_proofs.map((item) => ({
        credential_id_local: item.credential_id_local,
        proof: manifestOverride
          ? {
              ...item.proof,
              manifest: manifestOverride,
            }
          : item.proof,
      }));

      const verifiedJson = await verifyMixedPresentationPackage(
        JSON.stringify(presReq),
        presentationPackage.presentation_json,
        JSON.stringify(schemasMap),
        JSON.stringify(credDefsMap),
        JSON.stringify(revocationProofsForVerification),
        null
      );
      return {
        presentationPackage,
        verification: parseJsonSafe(verifiedJson, `verify_day_${dayIndex}`),
      };
    }

    console.log("6) Verificando pacotes para dias arbitrários antes da revogação...");
    for (const dayIndex of WINDOW_DAYS) {
      const { presentationPackage, verification } = await buildAndVerifyForDay(dayIndex);
      assert(verification.ok === true, `verifyMixedPresentationPackage deveria retornar ok=true no dia ${dayIndex}`);
      assert(verification.cryptographic_valid === true, `apresentação deveria ser criptograficamente válida no dia ${dayIndex}`);
      assert(verification.proofs_verified === true, `provas complementares deveriam verificar no dia ${dayIndex}`);
      assert(verification.revoked === false, `antes da revogação não deveria haver status revoked no dia ${dayIndex}`);
      assert(verification.accepted === true, `antes da revogação o pacote deveria ser aceito no dia ${dayIndex}`);
      assert(
        presentationPackage.used_credentials.filter((item) => item.revocable).every((item) => item.window_index === dayIndex),
        `used_credentials deveria refletir a janela ${dayIndex} para as credenciais revogáveis`
      );
    }

    console.log("7) Medindo contagem do Bloom antes da revogação...");
    const manifestBeforeRevoke = await fetchManifestEnvelope(BFILTER_BASE_URL);
    const insertedCountBefore = getActiveInsertedCount(manifestBeforeRevoke);

    console.log("8) Revogando a primeira credencial revogável a partir da janela 30...");
    const preflightJson = await preflightRevokeIssuedCredential(rev1IssuerLocalId, 30);
    const preflight = parseJsonSafe(preflightJson, "preflight_rev1_day30");
    assert(preflight.ok === true, "preflight deveria retornar ok=true");
    assert(preflight.can_revoke === true, "preflight deveria permitir revogação");
    assert(preflight.preflight.revocation_keys_to_write === 345, "deveria haver 345 chaves da janela 30 até a 374");

    const revokeJson = await revokeIssuedCredentialFromWindow(
      rev1IssuerLocalId,
      BFILTER_ADMIN_TOKEN,
      30,
      "revogacao-janela-30",
      "teste-node"
    );
    const revoke = parseJsonSafe(revokeJson, "revoke_from_day30");
    assert(revoke.ok === true, "revokeIssuedCredentialFromWindow deveria retornar ok=true");
    assert(revoke.revoke_from_window === 30, "a revogação deveria iniciar na janela 30");
    assert(revoke.revocation_keys_written === 345, "deveriam ser gravadas 345 chaves no Bloom");
    assert(revoke.window_starts_written.length === 345, "deveriam ser gravados 345 window_starts");
    assert(revoke.bloom.ok === true, "o Bloom deveria aceitar a revogação");

    console.log("9) Validando o delta de entradas no Bloom...");
    const manifestAfterRevoke = await fetchManifestEnvelope(BFILTER_BASE_URL);
    const insertedCountAfter = getActiveInsertedCount(manifestAfterRevoke);
    const insertedDelta = insertedCountAfter - insertedCountBefore;
    assert(
      insertedDelta === revoke.revocation_keys_written,
      `delta de entradas no Bloom deveria ser ${revoke.revocation_keys_written}, mas foi ${insertedDelta}`
    );

    const manifestAfterJson = await revocationBuildManifestAnchor(
      issuerDid,
      `${BFILTER_BASE_URL}/manifest`,
      manifestAfterRevoke.manifest_hash_body,
      String(manifestAfterRevoke.manifest.version || 1)
    );
    const writeManifestAfterJson = await revocationWriteManifestAnchorOnLedger(
      genesisAbs,
      issuerDid,
      manifestAfterJson
    );
    const writeManifestAfter = parseJsonSafe(writeManifestAfterJson, "write_manifest_after");
    assert(writeManifestAfter.ok === true, "reanchor do manifesto após revogação falhou");

    console.log("10) Revalidando os pacotes após a revogação...");
    for (const dayIndex of WINDOW_DAYS) {
      const { verification } = await buildAndVerifyForDay(dayIndex, writeManifestAfter.manifest);
      assert(verification.cryptographic_valid === true, `a prova criptográfica deve continuar válida no dia ${dayIndex}`);
      assert(verification.proofs_verified === true, `as provas complementares devem continuar verificando no dia ${dayIndex}`);

      const rev1Status = verification.per_credential_status.find(
        (item) => item.credential_id_local === rev1CredentialId
      );
      const rev2Status = verification.per_credential_status.find(
        (item) => item.credential_id_local === rev2CredentialId
      );
      assert(rev1Status, `status da credencial rev1 deveria existir no dia ${dayIndex}`);
      assert(rev2Status, `status da credencial rev2 deveria existir no dia ${dayIndex}`);
      assert(rev2Status.revoked === false, `rev2 não deveria ser revogada no dia ${dayIndex}`);

      if (dayIndex < 30) {
        assert(verification.revoked === false, `o consolidado não deveria indicar revogação no dia ${dayIndex}`);
        assert(verification.accepted === true, `o pacote deveria continuar aceito no dia ${dayIndex}`);
        assert(rev1Status.revoked === false, `rev1 não deveria estar revogada no dia ${dayIndex}`);
      } else {
        assert(verification.revoked === true, `o consolidado deveria indicar revogação no dia ${dayIndex}`);
        assert(verification.accepted === false, `o pacote deveria ser rejeitado no dia ${dayIndex}`);
        assert(rev1Status.revoked === true, `rev1 deveria estar revogada no dia ${dayIndex}`);
      }
    }

    console.log("✅ OK: TESTE REVOGAÇÃO 43 passou.");
  } finally {
    try { await issuer.walletClose(); } catch {}
    try { await holder.walletClose(); } catch {}
    try { await verifier.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 43:", e && e.stack ? e.stack : e);
  process.exit(1);
});
