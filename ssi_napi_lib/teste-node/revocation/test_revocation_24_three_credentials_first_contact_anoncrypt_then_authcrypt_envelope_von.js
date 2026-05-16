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
node teste-node/revocation/test_revocation_24_three_credentials_first_contact_anoncrypt_then_authcrypt_envelope_von.js

Para subir o bfilter:
cd /home/yugi/programacao/bfilter
BFILTER_ADMIN_TOKEN="dev-admin-token" cargo run
*/

/*
Teste E2E com 3 credenciais revogáveis trocadas por envelopes,
com primeiro contato em anoncrypt e fluxo principal em authcrypt.

O fluxo:
- cria/abre wallets de issuer, holder e verifier;
- conecta ao ledger e registra os DIDs;
- holder faz o primeiro contato com issuer e verifier via anoncrypt;
- emissor lê o manifesto do bfilter e ancora no ledger;
- cria 3 Schemas/CredDefs revogáveis (CPF, endereço e contato);
- emite 3 credenciais revogáveis via envelopes authcrypt;
- holder armazena as credenciais e os bundles revogáveis;
- verifier envia proof request por envelope;
- holder responde com apresentação + 3 provas complementares;
- verifier valida tudo antes e depois da revogação de uma credencial.

Depois valida:
- a apresentação é criptograficamente válida;
- antes da revogação, as 3 provas complementares verificam e a apresentação é aceita;
- após a revogação, o manifesto atualizado do Bloom é reancorado no ledger;
- após revogar apenas a credencial CPF, a apresentação continua válida
  criptograficamente, mas passa a ser rejeitada;
- somente a prova da credencial revogada fica com revoked=true.

Foco do teste:
validar envelopes anoncrypt/authcrypt no fluxo E2E com múltiplas
credenciais revogáveis e rejeição final quando uma delas é revogada.
*/

/* eslint-disable no-console */
const fs = require("fs");
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

function writeFileAtomic(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, data, "utf8");
}

function readFileUtf8(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function pExchange(dir, name) {
  return path.join(dir, name);
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function sha256Base64(input) {
  return crypto.createHash("sha256").update(input).digest("base64");
}

async function packAuthcrypt(agent, senderDid, recipientVerkey, kind, threadId, plaintext, expiresAtMs = null, meta = null) {
  return agent.envelopePackAuthcrypt(
    senderDid,
    recipientVerkey,
    kind,
    threadId,
    plaintext,
    expiresAtMs,
    meta ? JSON.stringify(meta) : null
  );
}

async function packAnoncrypt(agent, recipientVerkey, kind, threadId, plaintext, expiresAtMs = null, meta = null) {
  return agent.envelopePackAnoncrypt(
    recipientVerkey,
    kind,
    threadId,
    plaintext,
    expiresAtMs,
    meta ? JSON.stringify(meta) : null
  );
}

async function writeEnvFile(filePath, envJson) {
  writeFileAtomic(filePath, envJson);
}

async function readAndUnpackEnvFile(receiverAgent, receiverDid, filePath) {
  const envJson = readFileUtf8(filePath);
  const plaintext = await receiverAgent.envelopeUnpackAuto(receiverDid, envJson);
  return { envJson, plaintext };
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

async function firstContactHello(senderAgent, senderDid, senderVerkey, recipientAgent, recipientDid, recipientVerkey, threadId, filePath, note) {
  const helloPayload = JSON.stringify({
    type: "hello/anoncrypt",
    did: senderDid,
    verkey: senderVerkey,
    note,
    ts: Date.now(),
  });

  const helloEnv = await packAnoncrypt(
    senderAgent,
    recipientVerkey,
    "contact/hello",
    threadId,
    helloPayload,
    null,
    { step: "hello", phase: "first-contact" }
  );
  await writeEnvFile(filePath, helloEnv);

  const { plaintext } = await readAndUnpackEnvFile(recipientAgent, recipientDid, filePath);
  const obj = JSON.parse(plaintext);
  return { did: obj.did, verkey: obj.verkey };
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
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_24_issuer.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_24_holder.db");
  const verifierDb =
    process.env.WALLET_VERIFIER || path.join(walletDir, "test_wallet_revocation_24_verifier.db");

  const rootExchangeDir = path.join(
    __dirname,
    "exchange_revocation_3creds_first_anon_then_auth_env_v1"
  );
  fs.mkdirSync(rootExchangeDir, { recursive: true });

  const threadId = `th_revocation_3creds_first_anon_then_auth_${Date.now()}`;
  const exchangeDir = path.join(rootExchangeDir, threadId);
  fs.mkdirSync(exchangeDir, { recursive: true });

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
    const createCredentialOffer = fn(issuer, "createCredentialOffer", "create_credential_offer");
    const createCredentialRequest = fn(holder, "createCredentialRequest", "create_credential_request");
    const createLinkSecret = fn(holder, "createLinkSecret", "create_link_secret");
    const storeCredential = fn(holder, "storeCredential", "store_credential");
    const createPresentation = fn(holder, "createPresentation", "create_presentation");
    const verifyPresentation = fn(verifier, "verifyPresentation", "verify_presentation");
    const fetchSchemaFromLedger = fn(verifier, "fetchSchemaFromLedger", "fetch_schema_from_ledger");
    const fetchCredDefFromLedger = fn(verifier, "fetchCredDefFromLedger", "fetch_cred_def_from_ledger");
    const revocationBuildManifestAnchor = fn(issuer, "revocationBuildManifestAnchor", "revocation_build_manifest_anchor");
    const revocationWriteManifestAnchorOnLedger = fn(issuer, "revocationWriteManifestAnchorOnLedger", "revocation_write_manifest_anchor_on_ledger");
    const issueRevocableCredential = fn(issuer, "issueRevocableCredential", "issue_revocable_credential");
    const storeReceivedRevocableCredential = fn(holder, "storeReceivedRevocableCredential", "store_received_revocable_credential");
    const buildPresentationRevocationProof = fn(holder, "buildPresentationRevocationProof", "build_presentation_revocation_proof");
    const verifyPresentationRevocationProof = fn(verifier, "verifyPresentationRevocationProof", "verify_presentation_revocation_proof");
    const revokeIssuedCredential = fn(issuer, "revokeIssuedCredential", "revoke_issued_credential");

    console.log("🚀 TESTE REVOGAÇÃO 24: 3 credenciais + envelopes + revogação de uma credencial");

    console.log("1) Importando Trustee e criando DIDs...");
    const [trusteeDid] = await importDidFromSeed(TRUSTEE_SEED);
    assert(trusteeDid === TRUSTEE_DID, `Trustee DID inesperado: ${trusteeDid}`);

    const [issuerDid, issuerVerkey] = await issuer.createOwnDid();
    const [holderDid, holderVerkey] = await holder.createOwnDid();
    const [verifierDid, verifierVerkey] = await verifier.createOwnDid();

    console.log("2) Registrando emissor, holder e verifier na VON...");
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, issuerDid, issuerVerkey, "ENDORSER");
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, holderDid, holderVerkey, null);
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, verifierDid, verifierVerkey, null);

    console.log("3) First contact anoncrypt do holder com emissor e verifier...");
    const issuerLearned = await firstContactHello(
      holder,
      holderDid,
      holderVerkey,
      issuer,
      issuerDid,
      issuerVerkey,
      threadId,
      pExchange(exchangeDir, "00_hello_holder_to_issuer_anoncrypt.env.json"),
      "bootstrap holder -> issuer"
    );
    const verifierLearned = await firstContactHello(
      holder,
      holderDid,
      holderVerkey,
      verifier,
      verifierDid,
      verifierVerkey,
      threadId,
      pExchange(exchangeDir, "00_hello_holder_to_verifier_anoncrypt.env.json"),
      "bootstrap holder -> verifier"
    );
    assert(issuerLearned.did === holderDid && issuerLearned.verkey === holderVerkey, "issuer deveria aprender DID/verkey do holder");
    assert(verifierLearned.did === holderDid && verifierLearned.verkey === holderVerkey, "verifier deveria aprender DID/verkey do holder");

    console.log("4) Lendo manifesto do bfilter e ancorando no ledger do emissor...");
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

    console.log("5) Registrando 3 Schemas/CredDefs revogáveis...");
    const schemaCpfId = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `cpf_rev_${Date.now()}`,
      `1.0.${Date.now()}`,
      ["nome", "cpf", "idade", ...CONTROL_ATTRS]
    );
    const schemaEndId = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `endereco_rev_${Date.now()}`,
      `1.0.${Date.now() + 1}`,
      ["nome", "endereco", "cidade", "estado", ...CONTROL_ATTRS]
    );
    const schemaContatoId = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `contato_rev_${Date.now()}`,
      `1.0.${Date.now() + 2}`,
      ["nome", "email", "telefone", ...CONTROL_ATTRS]
    );

    async function registerCredDef(schemaId, tag) {
      const localJson = await creddefSaveLocal(issuerDid, schemaId, tag, false, "prod");
      const local = parseJsonSafe(localJson, `creddef_local_${tag}`);
      const reg = await creddefRegisterFromLocal(genesisAbs, local.id_local, issuerDid);
      return reg.credDefId || reg.cred_def_id;
    }

    const credDefCpfId = await registerCredDef(schemaCpfId, `TAG_CPF_REV_${Date.now()}`);
    const credDefEndId = await registerCredDef(schemaEndId, `TAG_END_REV_${Date.now()}`);
    const credDefContatoId = await registerCredDef(schemaContatoId, `TAG_CONT_REV_${Date.now()}`);

    try { await createLinkSecret("default"); } catch (_) {}

    async function issueRevocableCredentialViaEnvelope({
      kind,
      schemaId,
      credDefId,
      businessValues,
      credentialIdInWallet,
      bundleId,
      issuedId,
    }) {
      const offerId = `offer-${kind}-${Date.now()}`;
      const offerJson = await createCredentialOffer(credDefId, offerId);
      const offerFile = pExchange(exchangeDir, `${kind}_01_offer.env.json`);
      await writeEnvFile(
        offerFile,
        await packAuthcrypt(
          issuer,
          issuerDid,
          holderVerkey,
          "ssi/cred/offer",
          threadId,
          offerJson,
          null,
          { step: `${kind}.offer` }
        )
      );

      const { plaintext: offerPlain } = await readAndUnpackEnvFile(holder, holderDid, offerFile);
      const offerObj = JSON.parse(offerPlain);
      const reqMetaId = offerObj?.nonce;
      assert(reqMetaId, `${kind}: Offer sem nonce (reqMetaId)`);

      const credDefJsonLedger = await holder.fetchCredDefFromLedger(genesisAbs, credDefId);
      const requestJson = await createCredentialRequest(
        "default",
        holderDid,
        credDefJsonLedger,
        offerPlain
      );

      const reqFile = pExchange(exchangeDir, `${kind}_02_request.env.json`);
      await writeEnvFile(
        reqFile,
        await packAuthcrypt(
          holder,
          holderDid,
          issuerVerkey,
          "ssi/cred/request",
          threadId,
          requestJson,
          null,
          { step: `${kind}.request` }
        )
      );

      const { plaintext: reqPlain } = await readAndUnpackEnvFile(issuer, issuerDid, reqFile);
      const startTime = nowSec();
      const validityEnd = startTime + 86400 * 30;
      const issuePackageJson = await issueRevocableCredential(
        genesisAbs,
        issuedId,
        holderDid,
        credDefId,
        schemaId,
        offerJson,
        reqPlain,
        JSON.stringify(businessValues),
        startTime,
        validityEnd,
        "days",
        1,
        10,
        JSON.stringify(manifest),
        null,
        null
      );
      const pkg = parseJsonSafe(issuePackageJson, `issue_package_${kind}`);

      const credentialFile = pExchange(exchangeDir, `${kind}_03_revocable_package.env.json`);
      await writeEnvFile(
        credentialFile,
        await packAuthcrypt(
          issuer,
          issuerDid,
          holderVerkey,
          "ssi/revocation/credential_package",
          threadId,
          JSON.stringify(pkg),
          null,
          { step: `${kind}.credential_package` }
        )
      );

      const { plaintext: pkgPlain } = await readAndUnpackEnvFile(holder, holderDid, credentialFile);
      const receivedPkg = parseJsonSafe(pkgPlain, `received_package_${kind}`);
      await storeCredential(
        credentialIdInWallet,
        receivedPkg.credential_json,
        reqMetaId,
        credDefJsonLedger,
        null
      );
      const storeBundle = parseJsonSafe(
        await storeReceivedRevocableCredential(
          bundleId,
          JSON.stringify(receivedPkg.holder_bundle),
          credentialIdInWallet
        ),
        `store_bundle_${kind}`
      );
      assert(storeBundle.ok === true, `${kind}: bundle revogável não armazenado`);

      const receiptFile = pExchange(exchangeDir, `${kind}_04_store_receipt.env.json`);
      await writeEnvFile(
        receiptFile,
        await packAuthcrypt(
          holder,
          holderDid,
          issuerVerkey,
          "ssi/cred/store_receipt",
          threadId,
          JSON.stringify({
            ok: true,
            kind,
            credential_id: credentialIdInWallet,
            bundle_id: bundleId,
            issuer_local_credential_id: receivedPkg.issuer_record.issuer_local_credential_id,
          }),
          null,
          { step: `${kind}.receipt` }
        )
      );
      const { plaintext: receiptPlain } = await readAndUnpackEnvFile(issuer, issuerDid, receiptFile);
      assert(JSON.parse(receiptPlain).ok === true, `${kind}: receipt inválido`);

      return {
        package: receivedPkg,
        credentialIdInWallet,
        bundleId,
      };
    }

    console.log("6) Emitindo 3 credenciais revogáveis via envelopes authcrypt...");
    const cpfFlow = await issueRevocableCredentialViaEnvelope({
      kind: "cpf",
      schemaId: schemaCpfId,
      credDefId: credDefCpfId,
      businessValues: { nome: "Edimar Verissimo", cpf: "12345678909", idade: "35" },
      credentialIdInWallet: "cred-cpf-rev-env",
      bundleId: "bundle-cpf-rev-env",
      issuedId: `issued-cpf-${Date.now()}`,
    });
    const endFlow = await issueRevocableCredentialViaEnvelope({
      kind: "end",
      schemaId: schemaEndId,
      credDefId: credDefEndId,
      businessValues: {
        nome: "Edimar Verissimo",
        endereco: "Rua Exemplo, 123",
        cidade: "Sao Paulo",
        estado: "SP",
      },
      credentialIdInWallet: "cred-end-rev-env",
      bundleId: "bundle-end-rev-env",
      issuedId: `issued-end-${Date.now()}`,
    });
    const contatoFlow = await issueRevocableCredentialViaEnvelope({
      kind: "contato",
      schemaId: schemaContatoId,
      credDefId: credDefContatoId,
      businessValues: {
        nome: "Edimar Verissimo",
        email: "edimar@example.com",
        telefone: "+5511999999999",
      },
      credentialIdInWallet: "cred-contato-rev-env",
      bundleId: "bundle-contato-rev-env",
      issuedId: `issued-contato-${Date.now()}`,
    });

    console.log("7) Verifier criando Proof Request por envelope authcrypt...");
    const proofRequest = {
      nonce: String(Date.now()),
      name: "proof-3creds-revocation-zkp18",
      version: "1.0",
      requested_attributes: {
        attr_nome: { name: "nome", restrictions: [{ cred_def_id: credDefCpfId }] },
        attr_cpf: { name: "cpf", restrictions: [{ cred_def_id: credDefCpfId }] },
        attr_endereco: { name: "endereco", restrictions: [{ cred_def_id: credDefEndId }] },
        attr_email: { name: "email", restrictions: [{ cred_def_id: credDefContatoId }] },
        attr_telefone: { name: "telefone", restrictions: [{ cred_def_id: credDefContatoId }] },
        attr_seed_cpf: { name: "seed", restrictions: [{ cred_def_id: credDefCpfId }] },
        attr_start_cpf: { name: "start_time", restrictions: [{ cred_def_id: credDefCpfId }] },
        attr_unit_cpf: { name: "unit_of_time", restrictions: [{ cred_def_id: credDefCpfId }] },
        attr_window_cpf: { name: "time_window", restrictions: [{ cred_def_id: credDefCpfId }] },
        attr_root_cpf: { name: "root_merkle_L", restrictions: [{ cred_def_id: credDefCpfId }] },
        attr_seed_end: { name: "seed", restrictions: [{ cred_def_id: credDefEndId }] },
        attr_start_end: { name: "start_time", restrictions: [{ cred_def_id: credDefEndId }] },
        attr_unit_end: { name: "unit_of_time", restrictions: [{ cred_def_id: credDefEndId }] },
        attr_window_end: { name: "time_window", restrictions: [{ cred_def_id: credDefEndId }] },
        attr_root_end: { name: "root_merkle_L", restrictions: [{ cred_def_id: credDefEndId }] },
        attr_seed_contato: { name: "seed", restrictions: [{ cred_def_id: credDefContatoId }] },
        attr_start_contato: { name: "start_time", restrictions: [{ cred_def_id: credDefContatoId }] },
        attr_unit_contato: { name: "unit_of_time", restrictions: [{ cred_def_id: credDefContatoId }] },
        attr_window_contato: { name: "time_window", restrictions: [{ cred_def_id: credDefContatoId }] },
        attr_root_contato: { name: "root_merkle_L", restrictions: [{ cred_def_id: credDefContatoId }] },
      },
      requested_predicates: {
        pred_idade_ge_18: {
          name: "idade",
          p_type: ">=",
          p_value: 18,
          restrictions: [{ cred_def_id: credDefCpfId }],
        },
      },
    };

    const proofReqFile = pExchange(exchangeDir, "proof_01_request.env.json");
    await writeEnvFile(
      proofReqFile,
      await packAuthcrypt(
        verifier,
        verifierDid,
        holderVerkey,
        "ssi/proof/request",
        threadId,
        JSON.stringify(proofRequest),
        null,
        { step: "proof.request" }
      )
    );

    console.log("8) Holder criando apresentação + provas complementares por envelopes...");
    const { plaintext: proofReqPlain } = await readAndUnpackEnvFile(holder, holderDid, proofReqFile);
    const proofReqObj = JSON.parse(proofReqPlain);

    const requestedCreds = {
      requested_attributes: {
        attr_nome: { cred_id: cpfFlow.credentialIdInWallet, revealed: true },
        attr_cpf: { cred_id: cpfFlow.credentialIdInWallet, revealed: true },
        attr_endereco: { cred_id: endFlow.credentialIdInWallet, revealed: true },
        attr_email: { cred_id: contatoFlow.credentialIdInWallet, revealed: true },
        attr_telefone: { cred_id: contatoFlow.credentialIdInWallet, revealed: true },
        attr_seed_cpf: { cred_id: cpfFlow.credentialIdInWallet, revealed: true },
        attr_start_cpf: { cred_id: cpfFlow.credentialIdInWallet, revealed: true },
        attr_unit_cpf: { cred_id: cpfFlow.credentialIdInWallet, revealed: true },
        attr_window_cpf: { cred_id: cpfFlow.credentialIdInWallet, revealed: true },
        attr_root_cpf: { cred_id: cpfFlow.credentialIdInWallet, revealed: true },
        attr_seed_end: { cred_id: endFlow.credentialIdInWallet, revealed: true },
        attr_start_end: { cred_id: endFlow.credentialIdInWallet, revealed: true },
        attr_unit_end: { cred_id: endFlow.credentialIdInWallet, revealed: true },
        attr_window_end: { cred_id: endFlow.credentialIdInWallet, revealed: true },
        attr_root_end: { cred_id: endFlow.credentialIdInWallet, revealed: true },
        attr_seed_contato: { cred_id: contatoFlow.credentialIdInWallet, revealed: true },
        attr_start_contato: { cred_id: contatoFlow.credentialIdInWallet, revealed: true },
        attr_unit_contato: { cred_id: contatoFlow.credentialIdInWallet, revealed: true },
        attr_window_contato: { cred_id: contatoFlow.credentialIdInWallet, revealed: true },
        attr_root_contato: { cred_id: contatoFlow.credentialIdInWallet, revealed: true },
      },
      requested_predicates: {
        pred_idade_ge_18: { cred_id: cpfFlow.credentialIdInWallet },
      },
    };

    const schemaCpfJsonLedger = await holder.fetchSchemaFromLedger(genesisAbs, schemaCpfId);
    const schemaEndJsonLedger = await holder.fetchSchemaFromLedger(genesisAbs, schemaEndId);
    const schemaContatoJsonLedger = await holder.fetchSchemaFromLedger(genesisAbs, schemaContatoId);
    const credDefCpfJsonLedger = await holder.fetchCredDefFromLedger(genesisAbs, credDefCpfId);
    const credDefEndJsonLedger = await holder.fetchCredDefFromLedger(genesisAbs, credDefEndId);
    const credDefContatoJsonLedger = await holder.fetchCredDefFromLedger(genesisAbs, credDefContatoId);

    const schemasMap = JSON.stringify({
      [schemaCpfId]: JSON.parse(schemaCpfJsonLedger),
      [schemaEndId]: JSON.parse(schemaEndJsonLedger),
      [schemaContatoId]: JSON.parse(schemaContatoJsonLedger),
    });
    const credDefsMap = JSON.stringify({
      [credDefCpfId]: JSON.parse(credDefCpfJsonLedger),
      [credDefEndId]: JSON.parse(credDefEndJsonLedger),
      [credDefContatoId]: JSON.parse(credDefContatoJsonLedger),
    });

    const presentationJson = await createPresentation(
      JSON.stringify(proofReqObj),
      JSON.stringify(requestedCreds),
      schemasMap,
      credDefsMap
    );
    const presentationFile = pExchange(exchangeDir, "proof_02_presentation.env.json");
    await writeEnvFile(
      presentationFile,
      await packAuthcrypt(
        holder,
        holderDid,
        verifierVerkey,
        "ssi/proof/presentation",
        threadId,
        presentationJson,
        null,
        { step: "proof.presentation" }
      )
    );

    const revocationProofsPayload = {
      proofs: [
        parseJsonSafe(
          await buildPresentationRevocationProof(cpfFlow.bundleId, 0, cpfFlow.credentialIdInWallet),
          "cpf_revocation_proof"
        ).proof,
        parseJsonSafe(
          await buildPresentationRevocationProof(endFlow.bundleId, 0, endFlow.credentialIdInWallet),
          "end_revocation_proof"
        ).proof,
        parseJsonSafe(
          await buildPresentationRevocationProof(contatoFlow.bundleId, 0, contatoFlow.credentialIdInWallet),
          "contato_revocation_proof"
        ).proof,
      ],
    };
    const revocationProofsFile = pExchange(exchangeDir, "proof_03_revocation_payloads.env.json");
    await writeEnvFile(
      revocationProofsFile,
      await packAuthcrypt(
        holder,
        holderDid,
        verifierVerkey,
        "ssi/proof/revocation_payloads",
        threadId,
        JSON.stringify(revocationProofsPayload),
        null,
        { step: "proof.revocation_payloads" }
      )
    );

    console.log("9) Verifier validando apresentação e provas complementares antes da revogação...");
    const { plaintext: presentationPlain } = await readAndUnpackEnvFile(verifier, verifierDid, presentationFile);
    const { plaintext: revocationProofsPlain } = await readAndUnpackEnvFile(verifier, verifierDid, revocationProofsFile);
    const revocationProofsObj = JSON.parse(revocationProofsPlain);

    const verifierSchemasMap = JSON.stringify({
      [schemaCpfId]: parseJsonSafe(await fetchSchemaFromLedger(genesisAbs, schemaCpfId), "schemaCpfVerifier"),
      [schemaEndId]: parseJsonSafe(await fetchSchemaFromLedger(genesisAbs, schemaEndId), "schemaEndVerifier"),
      [schemaContatoId]: parseJsonSafe(await fetchSchemaFromLedger(genesisAbs, schemaContatoId), "schemaContatoVerifier"),
    });
    const verifierCredDefsMap = JSON.stringify({
      [credDefCpfId]: parseJsonSafe(await fetchCredDefFromLedger(genesisAbs, credDefCpfId), "credDefCpfVerifier"),
      [credDefEndId]: parseJsonSafe(await fetchCredDefFromLedger(genesisAbs, credDefEndId), "credDefEndVerifier"),
      [credDefContatoId]: parseJsonSafe(await fetchCredDefFromLedger(genesisAbs, credDefContatoId), "credDefContatoVerifier"),
    });

    const cryptoBefore = await verifyPresentation(
      JSON.stringify(proofReqObj),
      presentationPlain,
      verifierSchemasMap,
      verifierCredDefsMap
    );
    assert(cryptoBefore === true, "a apresentação deveria ser criptograficamente válida antes da revogação");

    const proofStatusesBefore = [];
    for (const proof of revocationProofsObj.proofs) {
      const verifyJson = await verifyPresentationRevocationProof(JSON.stringify(proof));
      const verifyObj = parseJsonSafe(verifyJson, "verify_revocation_before");
      proofStatusesBefore.push(verifyObj.status);
    }

    const beforeAggregate = aggregatePresentationStatus(cryptoBefore, proofStatusesBefore);
    assert(beforeAggregate.accepted === true, "antes da revogação a apresentação deveria ser aceita");

    console.log("10) Emissor revogando apenas a credencial CPF...");
    const revokeJson = await revokeIssuedCredential(
      cpfFlow.package.issuer_record.issuer_local_credential_id,
      BFILTER_ADMIN_TOKEN,
      0,
      "revogacao-do-cpf",
      "teste-node"
    );
    const revokeResponse = parseJsonSafe(revokeJson, "revoke_cpf");
    assert(revokeResponse.ok === true, "revokeIssuedCredential deveria retornar ok=true");
    assert(revokeResponse.bloom.ok === true, "o serviço Bloom deveria aceitar a revogação");

    console.log("11) Reancorando o manifesto atualizado e revalidando a mesma apresentação...");
    const cryptoAfter = await verifyPresentation(
      JSON.stringify(proofReqObj),
      presentationPlain,
      verifierSchemasMap,
      verifierCredDefsMap
    );
    assert(cryptoAfter === true, "criptograficamente a apresentação deveria continuar válida após a revogação");

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

    const revocationProofsAfter = revocationProofsObj.proofs.map((proof) => ({
      ...proof,
      manifest: writeManifestAfter.manifest,
    }));

    const proofStatusesAfter = [];
    for (const proof of revocationProofsAfter) {
      const verifyJson = await verifyPresentationRevocationProof(JSON.stringify(proof));
      const verifyObj = parseJsonSafe(verifyJson, "verify_revocation_after");
      proofStatusesAfter.push(verifyObj.status);
    }

    assert(proofStatusesAfter[0].revoked === true, "a credencial CPF deveria estar revogada");
    assert(proofStatusesAfter[1].revoked === false, "a credencial de endereco não deveria estar revogada");
    assert(proofStatusesAfter[2].revoked === false, "a credencial de contato não deveria estar revogada");

    const afterAggregate = aggregatePresentationStatus(cryptoAfter, proofStatusesAfter);
    assert(afterAggregate.cryptographic_valid === true, "a apresentação deveria continuar criptograficamente correta");
    assert(afterAggregate.proofs_verified === true, "as três provas complementares deveriam continuar verificando");
    assert(afterAggregate.revoked === true, "a apresentação deve ser considerada revogada quando uma das credenciais é revogada");
    assert(afterAggregate.accepted === false, "a apresentação não deve ser aceita após a revogação de uma das credenciais");

    const presentationObj = JSON.parse(presentationPlain);
    console.log("✅ OK: TESTE REVOGAÇÃO 24 passou.");
    console.log("📝 Revealed:", presentationObj.requested_proof?.revealed_attrs);
    console.log("🧮 Predicates:", presentationObj.requested_proof?.predicates);
    console.log("📌 Resumo final:", afterAggregate);
    console.log(`📁 Arquivos gerados em: ${exchangeDir}`);
  } finally {
    try { await issuer.walletClose(); } catch (_) {}
    try { await holder.walletClose(); } catch (_) {}
    try { await verifier.walletClose(); } catch (_) {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 24:", e?.message || e);
  console.error(e?.stack || "");
  process.exit(1);
});
