/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
RESET_WALLET=1 \
WALLET_PASS="minha_senha_teste" \
GENESIS_FILE=./von_genesis.txn \
TRUSTEE_SEED="000000000000000000000000Trustee1" \
TRUSTEE_DID="V4SGRU86Z58d6TV7PBUe6f" \
node teste-node/revocation/test_revocation_21_issue_revocable_reuses_k_von.js
*/

/*
Teste E2E de emissão de credencial revogável com reuso automático do vetor K.

O fluxo:
- cria/abre wallets de issuer, holder e verifier;
- conecta ao ledger e importa o DID Trustee;
- cria Schema revogável e registra a CredDef;
- holder cria Link Secret e DID;
- emissor emite a primeira credencial revogável;
- holder armazena a credencial e o bundle revogável;
- holder cria uma apresentação SSI e a prova complementar de revogação;
- verifier valida a apresentação e a prova complementar;
- emissor emite uma segunda credencial revogável com a mesma base.

Depois valida:
- a primeira emissão cria ou reutiliza o K ativo do ledger;
- a credencial revogável é emitida e armazenada corretamente;
- a apresentação SSI e a prova complementar verificam com sucesso;
- a segunda emissão reutiliza automaticamente o mesmo vetor K;
- o k_vector_id e o vector_hash permanecem iguais nas duas emissões.

Foco do teste:
validar issueRevocableCredential com reuso automático
do vetor K já resolvido/publicado.
*/

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
const REQUIRED_EXTRA_WINDOWS_FOR_FP = 10;

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

(async () => {
  const IndyAgent = loadIndyAgent();
  const pass = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET = process.env.RESET_WALLET === "1";

  const walletDir = ensureWalletDir();
  const issuerDb =
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_issue_issuer.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_issue_holder.db");
  const verifierDb =
    process.env.WALLET_VERIFIER || path.join(walletDir, "test_wallet_revocation_issue_verifier.db");

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
    assert(issuerDid === NETWORK_CONFIG.trusteeDid, "issuerDid inesperado");

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
    const issueRevocableCredential = fn(issuer, "issueRevocableCredential", "issue_revocable_credential");
    const storeReceivedRevocableCredential = fn(holder, "storeReceivedRevocableCredential", "store_received_revocable_credential");
    const buildPresentationRevocationProof = fn(holder, "buildPresentationRevocationProof", "build_presentation_revocation_proof");
    const verifyPresentationRevocationProof = fn(verifier, "verifyPresentationRevocationProof", "verify_presentation_revocation_proof");

    console.log("🚀 TESTE REVOGAÇÃO 21: issueRevocableCredential + reuso automático de K");

    const schemaId = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaRevocableIssue_${Date.now()}`,
      `1.${nowSec()}`,
      ["nome", "cpf", "idade", ...CONTROL_ATTRS]
    );

    const localCredDefJson = await creddefSaveLocal(
      issuerDid,
      schemaId,
      `TAG_REV_ISSUE_${nowSec()}`,
      false,
      "prod"
    );
    const localCredDef = parseJsonSafe(localCredDefJson, "creddef_local");
    const credDefRegObj = await creddefRegisterFromLocal(genesisAbs, localCredDef.id_local, issuerDid);
    const credDefId = credDefRegObj.credDefId || credDefRegObj.cred_def_id;
    assert(typeof credDefId === "string" && credDefId.includes(":3:CL:"), "credDefId inválido");

    const schemaLedgerObj = parseJsonSafe(
      await fetchSchemaFromLedger(genesisAbs, schemaId),
      "schema_ledger"
    );
    const credDefLedgerObj = parseJsonSafe(
      await fetchCredDefFromLedger(genesisAbs, credDefId),
      "creddef_ledger"
    );

    try {
      await createLinkSecret("default");
    } catch (_) {}
    const holderDidRaw = await createDidV2("{}");
    const holderDidObj = typeof holderDidRaw === "string" ? JSON.parse(holderDidRaw) : holderDidRaw;
    const holderDid = holderDidObj.did || holderDidObj.myDid || holderDidObj.id;
    assert(typeof holderDid === "string" && holderDid.length > 10, "holderDid inválido");

    const offer1Json = await createCredentialOffer(credDefId, `offer-issue-1-${Date.now()}`);
    const req1Json = await createCredentialRequest(
      "default",
      holderDid,
      JSON.stringify(credDefLedgerObj),
      offer1Json
    );

    const issue1Json = await issueRevocableCredential(
      genesisAbs,
      `issued-revocable-1-${Date.now()}`,
      holderDid,
      credDefId,
      schemaId,
      offer1Json,
      req1Json,
      JSON.stringify({
        nome: "Alice Reuso K",
        cpf: "11111111111",
        idade: "30",
      }),
      nowSec(),
      nowSec() + 86400 * 30,
      "days",
      1,
      REQUIRED_EXTRA_WINDOWS_FOR_FP,
      "",
      null,
      null
    );
    const issue1 = parseJsonSafe(issue1Json, "issue1");
    assert(issue1.version === 2, "issueRevocableCredential deveria retornar version 2");
    assert(issue1.control_values.extra_windows_for_fp === REQUIRED_EXTRA_WINDOWS_FOR_FP, "issue1.extra_windows_for_fp inválido");
    assert(
      issue1.control_values.confirmation_window_count === REQUIRED_EXTRA_WINDOWS_FOR_FP,
      "issue1.confirmation_window_count inválido"
    );
    assert(
      issue1.k_resolution_source === "created_and_written" ||
        issue1.k_resolution_source === "ledger_active",
      "primeira emissão deveria criar K ou reaproveitar o K ativo já publicado no ledger"
    );
    assert(issue1.k_ledger_anchor && issue1.k_ledger_anchor.k_vector_id, "primeira emissão sem k_ledger_anchor");
    const issuedValues1 = parseJsonSafe(issue1.issued_values_json, "issued_values_1");
    assert(issuedValues1.seed === issue1.control_attributes.seed, "issued_values_json deveria conter seed");
    assert(issuedValues1.root_merkle_L === issue1.control_attributes.root_merkle_L, "issued_values_json deveria conter root_merkle_L");

    const credentialId = `cred-issue-rev-1-${Date.now()}`;
    const storedCredentialId = await storeCredential(
      credentialId,
      issue1.credential_json,
      extractNonce(offer1Json),
      JSON.stringify(credDefLedgerObj),
      null
    );
    assert(storedCredentialId === credentialId, "storeCredential falhou");

    const bundleId = `bundle-issue-rev-1-${Date.now()}`;
    const storeBundleJson = await storeReceivedRevocableCredential(
      bundleId,
      JSON.stringify(issue1.holder_bundle),
      credentialId
    );
    const storeBundle = parseJsonSafe(storeBundleJson, "store_bundle");
    assert(storeBundle.ok === true, "storeReceivedRevocableCredential falhou");

    const presReq = {
      nonce: String(Date.now() * 1000 + 54321),
      name: "ProofReqIssueRevocable",
      version: "0.1",
      requested_attributes: {
        attr_nome: { name: "nome" },
        attr_seed: { name: "seed" },
        attr_root_merkle_L: { name: "root_merkle_L" },
      },
      requested_predicates: {},
    };
    const reqCreds = {
      requested_attributes: {
        attr_nome: { cred_id: credentialId, revealed: true },
        attr_seed: { cred_id: credentialId, revealed: true },
        attr_root_merkle_L: { cred_id: credentialId, revealed: true },
      },
      requested_predicates: {},
    };
    const presentationJson = await createPresentation(
      JSON.stringify(presReq),
      JSON.stringify(reqCreds),
      JSON.stringify({ [schemaId]: schemaLedgerObj }),
      JSON.stringify({ [credDefId]: credDefLedgerObj })
    );
    const presentation = parseJsonSafe(presentationJson, "presentation");
    assert(
      presentation.requested_proof.revealed_attrs.attr_seed.raw === issue1.control_attributes.seed,
      "presentation deveria revelar seed"
    );
    const verified = await verifyPresentation(
      JSON.stringify(presReq),
      presentationJson,
      JSON.stringify({ [schemaId]: schemaLedgerObj }),
      JSON.stringify({ [credDefId]: credDefLedgerObj })
    );
    assert(verified === true, "verifyPresentation deveria retornar true");

    const proof1Json = await buildPresentationRevocationProof(bundleId, 0, credentialId);
    const proof1 = parseJsonSafe(proof1Json, "proof1");
    proof1.proof.manifest = null;
    const verifyProof1Json = await verifyPresentationRevocationProof(JSON.stringify(proof1.proof));
    const verifyProof1 = parseJsonSafe(verifyProof1Json, "verify_proof1");
    assert(verifyProof1.status.verified === true, "primeira prova complementar deveria verificar");

    const offer2Json = await createCredentialOffer(credDefId, `offer-issue-2-${Date.now()}`);
    const req2Json = await createCredentialRequest(
      "default",
      holderDid,
      JSON.stringify(credDefLedgerObj),
      offer2Json
    );
    const issue2Json = await issueRevocableCredential(
      genesisAbs,
      `issued-revocable-2-${Date.now()}`,
      holderDid,
      credDefId,
      schemaId,
      offer2Json,
      req2Json,
      JSON.stringify({
        nome: "Bruno Reuso K",
        cpf: "22222222222",
        idade: "31",
      }),
      nowSec(),
      nowSec() + 86400 * 60,
      "days",
      1,
      REQUIRED_EXTRA_WINDOWS_FOR_FP,
      "",
      null,
      null
    );
    const issue2 = parseJsonSafe(issue2Json, "issue2");
    assert(issue2.control_values.extra_windows_for_fp === REQUIRED_EXTRA_WINDOWS_FOR_FP, "issue2.extra_windows_for_fp inválido");
    assert(
      issue2.control_values.confirmation_window_count === REQUIRED_EXTRA_WINDOWS_FOR_FP,
      "issue2.confirmation_window_count inválido"
    );
    assert(issue2.k_resolution_source === "cache_local", "segunda emissão deveria reutilizar K do cache local");
    assert(
      issue2.k_ledger_anchor.k_vector_id === issue1.k_ledger_anchor.k_vector_id,
      "segunda emissão deveria reutilizar o mesmo k_vector_id"
    );
    assert(
      issue2.k_ledger_anchor.vector_hash === issue1.k_ledger_anchor.vector_hash,
      "segunda emissão deveria reutilizar o mesmo vector_hash"
    );

    console.log("✅ OK: TESTE REVOGAÇÃO 21 passou.");
  } finally {
    try { await issuer.walletClose(); } catch {}
    try { await holder.walletClose(); } catch {}
    try { await verifier.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 21:", e && e.stack ? e.stack : e);
  process.exit(1);
});
