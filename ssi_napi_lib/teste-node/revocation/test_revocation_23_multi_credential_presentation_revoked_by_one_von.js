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
node teste-node/revocation/test_revocation_23_multi_credential_presentation_revoked_by_one_von.js

Para subir o bfilter:
cd /home/yugi/programacao/bfilter
BFILTER_ADMIN_TOKEN="dev-admin-token" cargo run
*/

/*
Teste E2E de apresentação com duas credenciais revogáveis,
em que apenas uma delas é revogada.

O fluxo:
- cria/abre wallets de issuer e holder;
- conecta ao ledger e registra os DIDs;
- lê e ancora o manifesto do serviço Bloom no ledger;
- cria dois Schemas/CredDefs revogáveis;
- emite duas credenciais revogáveis para o holder usando o mesmo vetor K;
- holder armazena as credenciais e seus bundles;
- holder monta uma apresentação única com dados das duas credenciais;
- emissor verifica a apresentação e as provas complementares;
- revoga apenas uma das credenciais;
- verifica novamente a apresentação após a revogação.

Depois valida:
- as duas emissões reutilizam o mesmo K do emissor;
- a apresentação é criptograficamente válida antes e depois da revogação;
- antes da revogação, as duas provas complementares verificam com revoked=false;
- após a revogação, o manifesto atualizado do Bloom é reancorado no ledger;
- após a revogação, apenas uma credencial fica com revoked=true;
- a apresentação final deixa de ser aceita quando uma das credenciais foi revogada.

Foco do teste:
validar que uma apresentação com múltiplas credenciais
deve ser rejeitada se ao menos uma delas estiver revogada.
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

function aggregatePresentationStatus(cryptographicValid, proofStatuses) {
  const proofsVerified = proofStatuses.every((item) => item.verified === true);
  const revoked = proofStatuses.some((item) => item.revoked === true);
  return {
    cryptographic_valid: cryptographicValid === true,
    proofs_verified: proofsVerified,
    revoked,
    accepted: cryptographicValid === true && proofsVerified === true && revoked === false,
  };
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
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_multi_issuer.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_multi_holder.db");

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
    const fetchSchemaFromLedger = fn(issuer, "fetchSchemaFromLedger", "fetch_schema_from_ledger");
    const fetchCredDefFromLedger = fn(issuer, "fetchCredDefFromLedger", "fetch_cred_def_from_ledger");
    const createCredentialOffer = fn(issuer, "createCredentialOffer", "create_credential_offer");
    const createCredentialRequest = fn(holder, "createCredentialRequest", "create_credential_request");
    const createLinkSecret = fn(holder, "createLinkSecret", "create_link_secret");
    const storeCredential = fn(holder, "storeCredential", "store_credential");
    const createPresentation = fn(holder, "createPresentation", "create_presentation");
    const verifyPresentation = fn(issuer, "verifyPresentation", "verify_presentation");
    const revocationBuildManifestAnchor = fn(issuer, "revocationBuildManifestAnchor", "revocation_build_manifest_anchor");
    const revocationWriteManifestAnchorOnLedger = fn(issuer, "revocationWriteManifestAnchorOnLedger", "revocation_write_manifest_anchor_on_ledger");
    const issueRevocableCredential = fn(issuer, "issueRevocableCredential", "issue_revocable_credential");
    const storeReceivedRevocableCredential = fn(holder, "storeReceivedRevocableCredential", "store_received_revocable_credential");
    const buildPresentationRevocationProof = fn(holder, "buildPresentationRevocationProof", "build_presentation_revocation_proof");
    const verifyPresentationRevocationProof = fn(issuer, "verifyPresentationRevocationProof", "verify_presentation_revocation_proof");
    const revokeIssuedCredential = fn(issuer, "revokeIssuedCredential", "revoke_issued_credential");

    console.log("🚀 TESTE REVOGAÇÃO 23: apresentação com 2 credenciais e revogação por uma delas");

    console.log("1) Importando trustee e criando DIDs reais de emissor/holder...");
    const [trusteeDid] = await importDidFromSeed(TRUSTEE_SEED);
    assert(trusteeDid === TRUSTEE_DID, `Trustee DID inesperado: ${trusteeDid}`);

    const [issuerDid, issuerVerkey] = await issuer.createOwnDid();
    const [holderDid, holderVerkey] = await holder.createOwnDid();
    assert(typeof issuerDid === "string" && issuerDid.length > 10, "issuerDid inválido");
    assert(typeof holderDid === "string" && holderDid.length > 10, "holderDid inválido");

    console.log("2) Registrando emissor e holder na VON...");
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, issuerDid, issuerVerkey, "ENDORSER");
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, holderDid, holderVerkey, null);

    console.log("3) Lendo manifesto atual do serviço Bloom...");
    const manifestResp = await fetch(`${BFILTER_BASE_URL}/manifest`);
    assert(manifestResp.ok, `Falha GET /manifest: ${manifestResp.status}`);
    const manifestBodyText = await manifestResp.text();
    const manifestEnvelope = JSON.parse(manifestBodyText);
    assert(manifestEnvelope.ok === true, "manifesto Bloom deveria retornar ok=true");
    const manifestHash = sha256Base64(manifestBodyText);

    console.log("4) Ancorando manifesto do serviço Bloom no ledger do emissor...");
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

    console.log("5) Registrando dois Schemas/CredDefs revogáveis...");
    const schemaIdIdentidade = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaRevocableIdentidade_${Date.now()}`,
      `1.${nowSec()}`,
      ["nome", "cpf", "idade", ...CONTROL_ATTRS]
    );
    const localCredDefIdentidadeJson = await creddefSaveLocal(
      issuerDid,
      schemaIdIdentidade,
      `TAG_REV_IDENT_${nowSec()}`,
      false,
      "prod"
    );
    const localCredDefIdentidade = parseJsonSafe(localCredDefIdentidadeJson, "creddef_local_identidade");
    const credDefRegIdentidade = await creddefRegisterFromLocal(
      genesisAbs,
      localCredDefIdentidade.id_local,
      issuerDid
    );
    const credDefIdIdentidade =
      credDefRegIdentidade.credDefId || credDefRegIdentidade.cred_def_id;

    const schemaIdContato = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaRevocableContato_${Date.now()}`,
      `1.${nowSec() + 1}`,
      ["email", "telefone", ...CONTROL_ATTRS]
    );
    const localCredDefContatoJson = await creddefSaveLocal(
      issuerDid,
      schemaIdContato,
      `TAG_REV_CONT_${nowSec()}`,
      false,
      "prod"
    );
    const localCredDefContato = parseJsonSafe(localCredDefContatoJson, "creddef_local_contato");
    const credDefRegContato = await creddefRegisterFromLocal(
      genesisAbs,
      localCredDefContato.id_local,
      issuerDid
    );
    const credDefIdContato = credDefRegContato.credDefId || credDefRegContato.cred_def_id;

    const schemaIdentidadeLedger = parseJsonSafe(
      await fetchSchemaFromLedger(genesisAbs, schemaIdIdentidade),
      "schema_identidade_ledger"
    );
    const credDefIdentidadeLedger = parseJsonSafe(
      await fetchCredDefFromLedger(genesisAbs, credDefIdIdentidade),
      "creddef_identidade_ledger"
    );
    const schemaContatoLedger = parseJsonSafe(
      await fetchSchemaFromLedger(genesisAbs, schemaIdContato),
      "schema_contato_ledger"
    );
    const credDefContatoLedger = parseJsonSafe(
      await fetchCredDefFromLedger(genesisAbs, credDefIdContato),
      "creddef_contato_ledger"
    );

    console.log("6) Criando link secret e requests das duas credenciais...");
    try {
      await createLinkSecret("default");
    } catch (_) {}

    const offerIdentidadeId = `offer-identidade-${Date.now()}`;
    const offerContatoId = `offer-contato-${Date.now()}`;
    const offerIdentidadeJson = await createCredentialOffer(credDefIdIdentidade, offerIdentidadeId);
    const offerContatoJson = await createCredentialOffer(credDefIdContato, offerContatoId);

    const requestIdentidadeJson = await createCredentialRequest(
      "default",
      holderDid,
      JSON.stringify(credDefIdentidadeLedger),
      offerIdentidadeJson
    );
    const requestContatoJson = await createCredentialRequest(
      "default",
      holderDid,
      JSON.stringify(credDefContatoLedger),
      offerContatoJson
    );
    const requestMetadataIdentidadeId = extractNonce(offerIdentidadeJson);
    const requestMetadataContatoId = extractNonce(offerContatoJson);

    console.log("7) Emitindo duas credenciais revogáveis usando o mesmo K do emissor...");
    const startTime = nowSec();
    const validityEnd = startTime + 86400 * 30;

    const issueIdentidadeJson = await issueRevocableCredential(
      genesisAbs,
      `issued-identidade-${Date.now()}`,
      holderDid,
      credDefIdIdentidade,
      schemaIdIdentidade,
      offerIdentidadeJson,
      requestIdentidadeJson,
      JSON.stringify({
        nome: "Alice Multi",
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
    const pkgIdentidade = parseJsonSafe(issueIdentidadeJson, "issue_identidade");

    const issueContatoJson = await issueRevocableCredential(
      genesisAbs,
      `issued-contato-${Date.now()}`,
      holderDid,
      credDefIdContato,
      schemaIdContato,
      offerContatoJson,
      requestContatoJson,
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
    );
    const pkgContato = parseJsonSafe(issueContatoJson, "issue_contato");

    assert(
      pkgIdentidade.k_ledger_anchor.k_vector_id === pkgContato.k_ledger_anchor.k_vector_id,
      "as duas credenciais deveriam reutilizar o mesmo K do emissor"
    );

    console.log("8) Holder armazenando as duas credenciais e seus bundles...");
    const credentialIdIdentidade = `cred-identidade-${Date.now()}`;
    const credentialIdContato = `cred-contato-${Date.now()}`;
    const storedCredentialIdIdentidade = await storeCredential(
      credentialIdIdentidade,
      pkgIdentidade.credential_json,
      requestMetadataIdentidadeId,
      JSON.stringify(credDefIdentidadeLedger),
      null
    );
    const storedCredentialIdContato = await storeCredential(
      credentialIdContato,
      pkgContato.credential_json,
      requestMetadataContatoId,
      JSON.stringify(credDefContatoLedger),
      null
    );
    assert(storedCredentialIdIdentidade === credentialIdIdentidade, "credencial identidade não armazenada");
    assert(storedCredentialIdContato === credentialIdContato, "credencial contato não armazenada");

    const bundleIdIdentidade = `bundle-identidade-${Date.now()}`;
    const bundleIdContato = `bundle-contato-${Date.now()}`;
    const storeBundleIdentidade = parseJsonSafe(
      await storeReceivedRevocableCredential(
        bundleIdIdentidade,
        JSON.stringify(pkgIdentidade.holder_bundle),
        credentialIdIdentidade
      ),
      "store_bundle_identidade"
    );
    const storeBundleContato = parseJsonSafe(
      await storeReceivedRevocableCredential(
        bundleIdContato,
        JSON.stringify(pkgContato.holder_bundle),
        credentialIdContato
      ),
      "store_bundle_contato"
    );
    assert(storeBundleIdentidade.ok === true, "bundle identidade não armazenado");
    assert(storeBundleContato.ok === true, "bundle contato não armazenado");

    console.log("9) Holder criando apresentação com duas credenciais...");
    const presReq = {
      nonce: String(Date.now() * 1000 + 24680),
      name: "ProofReqRevocableMultiCredential",
      version: "0.1",
      requested_attributes: {
        attr_nome: { name: "nome", restrictions: [{ cred_def_id: credDefIdIdentidade }] },
        attr_cpf: { name: "cpf", restrictions: [{ cred_def_id: credDefIdIdentidade }] },
        attr_email: { name: "email", restrictions: [{ cred_def_id: credDefIdContato }] },
        attr_telefone: { name: "telefone", restrictions: [{ cred_def_id: credDefIdContato }] },
        attr_seed_identidade: { name: "seed", restrictions: [{ cred_def_id: credDefIdIdentidade }] },
        attr_start_time_identidade: { name: "start_time", restrictions: [{ cred_def_id: credDefIdIdentidade }] },
        attr_unit_of_time_identidade: { name: "unit_of_time", restrictions: [{ cred_def_id: credDefIdIdentidade }] },
        attr_time_window_identidade: { name: "time_window", restrictions: [{ cred_def_id: credDefIdIdentidade }] },
        attr_root_merkle_identidade: { name: "root_merkle_L", restrictions: [{ cred_def_id: credDefIdIdentidade }] },
        attr_seed_contato: { name: "seed", restrictions: [{ cred_def_id: credDefIdContato }] },
        attr_start_time_contato: { name: "start_time", restrictions: [{ cred_def_id: credDefIdContato }] },
        attr_unit_of_time_contato: { name: "unit_of_time", restrictions: [{ cred_def_id: credDefIdContato }] },
        attr_time_window_contato: { name: "time_window", restrictions: [{ cred_def_id: credDefIdContato }] },
        attr_root_merkle_contato: { name: "root_merkle_L", restrictions: [{ cred_def_id: credDefIdContato }] },
      },
      requested_predicates: {},
    };

    const reqCreds = {
      requested_attributes: {
        attr_nome: { cred_id: credentialIdIdentidade, revealed: true },
        attr_cpf: { cred_id: credentialIdIdentidade, revealed: true },
        attr_email: { cred_id: credentialIdContato, revealed: true },
        attr_telefone: { cred_id: credentialIdContato, revealed: true },
        attr_seed_identidade: { cred_id: credentialIdIdentidade, revealed: true },
        attr_start_time_identidade: { cred_id: credentialIdIdentidade, revealed: true },
        attr_unit_of_time_identidade: { cred_id: credentialIdIdentidade, revealed: true },
        attr_time_window_identidade: { cred_id: credentialIdIdentidade, revealed: true },
        attr_root_merkle_identidade: { cred_id: credentialIdIdentidade, revealed: true },
        attr_seed_contato: { cred_id: credentialIdContato, revealed: true },
        attr_start_time_contato: { cred_id: credentialIdContato, revealed: true },
        attr_unit_of_time_contato: { cred_id: credentialIdContato, revealed: true },
        attr_time_window_contato: { cred_id: credentialIdContato, revealed: true },
        attr_root_merkle_contato: { cred_id: credentialIdContato, revealed: true },
      },
      requested_predicates: {},
    };

    const schemasMap = {
      [schemaIdIdentidade]: schemaIdentidadeLedger,
      [schemaIdContato]: schemaContatoLedger,
    };
    const credDefsMap = {
      [credDefIdIdentidade]: credDefIdentidadeLedger,
      [credDefIdContato]: credDefContatoLedger,
    };

    const presentationJson = await createPresentation(
      JSON.stringify(presReq),
      JSON.stringify(reqCreds),
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap)
    );
    const presentation = parseJsonSafe(presentationJson, "presentation_multi");
    assert(
      Array.isArray(presentation.identifiers) && presentation.identifiers.length >= 2,
      "a apresentação deveria usar pelo menos duas credenciais"
    );

    console.log("10) Emissor verificando a validade criptográfica da apresentação...");
    const cryptoBefore = await verifyPresentation(
      JSON.stringify(presReq),
      presentationJson,
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap)
    );
    assert(cryptoBefore === true, "a apresentação deveria ser criptograficamente válida antes da revogação");

    console.log("11) Emissor verificando as provas complementares das duas credenciais...");
    const proofIdentidade = parseJsonSafe(
      await buildPresentationRevocationProof(bundleIdIdentidade, 0, credentialIdIdentidade),
      "proof_identidade"
    );
    const proofContato = parseJsonSafe(
      await buildPresentationRevocationProof(bundleIdContato, 0, credentialIdContato),
      "proof_contato"
    );

    const verifyProofIdentidadeBefore = parseJsonSafe(
      await verifyPresentationRevocationProof(JSON.stringify(proofIdentidade.proof)),
      "verify_proof_identidade_before"
    );
    const verifyProofContatoBefore = parseJsonSafe(
      await verifyPresentationRevocationProof(JSON.stringify(proofContato.proof)),
      "verify_proof_contato_before"
    );

    const beforeAggregate = aggregatePresentationStatus(cryptoBefore, [
      verifyProofIdentidadeBefore.status,
      verifyProofContatoBefore.status,
    ]);
    assert(beforeAggregate.cryptographic_valid === true, "a validade criptográfica deveria continuar true");
    assert(beforeAggregate.proofs_verified === true, "as duas provas complementares deveriam verificar");
    assert(beforeAggregate.revoked === false, "antes da revogação nenhuma credencial deveria estar revogada");
    assert(beforeAggregate.accepted === true, "antes da revogação a apresentação deveria ser aceita");

    console.log("12) Revogando apenas a credencial de identidade...");
    const revokeJson = await revokeIssuedCredential(
      pkgIdentidade.issuer_record.issuer_local_credential_id,
      BFILTER_ADMIN_TOKEN,
      0,
      "revogacao-de-uma-das-credenciais",
      "teste-node"
    );
    const revokeResponse = parseJsonSafe(revokeJson, "revoke_identidade");
    assert(revokeResponse.ok === true, "revokeIssuedCredential deveria retornar ok=true");
    assert(revokeResponse.bloom.ok === true, "o serviço Bloom deveria aceitar a revogação");
    assert(revokeResponse.issuer_record.status === "revoked", "issuer_record da identidade deveria ficar revogado");

    console.log("13) Reancorando o manifesto atualizado e revalidando a apresentação...");
    const cryptoAfter = await verifyPresentation(
      JSON.stringify(presReq),
      presentationJson,
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap)
    );
    assert(cryptoAfter === true, "criptograficamente a apresentação deveria continuar válida após revogação");

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

    const proofIdentidadeAfter = {
      ...proofIdentidade.proof,
      manifest: writeManifestAfter.manifest,
    };
    const proofContatoAfter = {
      ...proofContato.proof,
      manifest: writeManifestAfter.manifest,
    };

    const verifyProofIdentidadeAfter = parseJsonSafe(
      await verifyPresentationRevocationProof(JSON.stringify(proofIdentidadeAfter)),
      "verify_proof_identidade_after"
    );
    const verifyProofContatoAfter = parseJsonSafe(
      await verifyPresentationRevocationProof(JSON.stringify(proofContatoAfter)),
      "verify_proof_contato_after"
    );

    assert(
      verifyProofIdentidadeAfter.status.verified === true,
      "a prova complementar da identidade deveria continuar criptograficamente válida"
    );
    assert(
      verifyProofContatoAfter.status.verified === true,
      "a prova complementar do contato deveria continuar criptograficamente válida"
    );
    assert(
      verifyProofIdentidadeAfter.status.revoked === true,
      "a credencial de identidade deveria estar revogada no Bloom"
    );
    assert(
      verifyProofContatoAfter.status.revoked === false,
      "a credencial de contato não deveria estar revogada"
    );

    const afterAggregate = aggregatePresentationStatus(cryptoAfter, [
      verifyProofIdentidadeAfter.status,
      verifyProofContatoAfter.status,
    ]);
    assert(afterAggregate.cryptographic_valid === true, "a apresentação deveria continuar criptograficamente correta");
    assert(afterAggregate.proofs_verified === true, "as provas complementares deveriam continuar verificando");
    assert(afterAggregate.revoked === true, "a apresentação deve ser considerada revogada se uma credencial foi revogada");
    assert(afterAggregate.accepted === false, "a apresentação não deve ser aceita quando uma das credenciais está revogada");

    console.log("✅ OK: TESTE REVOGAÇÃO 23 passou.");
    console.log("📌 Resumo final:", afterAggregate);
  } finally {
    try { await issuer.walletClose(); } catch {}
    try { await holder.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 23:", e && e.stack ? e.stack : e);
  process.exit(1);
});
