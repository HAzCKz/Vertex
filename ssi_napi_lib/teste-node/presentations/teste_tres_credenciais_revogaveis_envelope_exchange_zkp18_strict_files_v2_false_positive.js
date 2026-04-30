/*
PARA RODAR ESTE TESTE:
cd /home/yugi/programacao/ssi_napi_lib
TRUSTEE_SEED="000000000000000000000000Trustee1" \
TRUSTEE_DID="V4SGRU86Z58d6TV7PBUe6f" \
WALLET_PASS="minha_senha_teste" \
GENESIS_FILE=./von_genesis.txn \
BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
node teste-node/presentations/teste_tres_credenciais_revogaveis_envelope_exchange_zkp18_strict_files_v2_false_positive.js

Para subir o bfilter em modo de testes:
cd /home/yugi/programacao/bfilter
BFILTER_ENABLE_TEST_API=1 \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
cargo run

O QUE ESTE TESTE FAZ:
- Replica o fluxo strict files com 3 credenciais revogáveis;
- O issuer envia ao holder o pacote revogável completo por envelope authcrypt;
- O holder guarda todas as janelas do holder_bundle;
- O verifier primeiro recebe apenas 1 janela por credencial;
- Um falso positivo controlado é induzido na credencial CPF;
- Sem contraprova adicional, o verifier pede mais janelas para a credencial com hit;
- O verifier envia um pedido authcrypt por mais 2 janelas só da credencial CPF;
- O holder responde com um novo pacote v2 contendo 3 janelas para CPF e 1 janela para as demais;
- O verifier reclassifica o caso como false_positive_confirmed e volta a aceitar a apresentação.
*/

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const { IndyAgent } = require(path.join(__dirname, "..", "..", "index.node"));

const CONTROL_ATTRS = [
  "seed",
  "start_time",
  "unit_of_time",
  "time_window",
  "root_merkle_L",
];

const PRIMARY_WINDOW_INDEX = 10;
const DEFAULT_EXTRA_WINDOWS_FOR_FP = 10;
const ADDITIONAL_CONFIRMATION_WINDOWS = 2;
const TEST_FILTER_M_BITS = 256;
const TEST_FILTER_K = 3;
const DUMMY_BATCH_SIZE = 32;
const MAX_FP_BATCHES = 200;

function rmIfExists(walletDbPath) {
  const sidecar = `${walletDbPath}.kdf.json`;
  try { fs.unlinkSync(walletDbPath); } catch (_) {}
  try { fs.unlinkSync(sidecar); } catch (_) {}
  try { fs.unlinkSync(`${sidecar}.tmp`); } catch (_) {}
  try { fs.unlinkSync(`${walletDbPath}-shm`); } catch (_) {}
  try { fs.unlinkSync(`${walletDbPath}-wal`); } catch (_) {}
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg || "assert falhou");
}

function mustEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Env ${name} não definida.`);
  return v;
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function sha256Base64(input) {
  return crypto.createHash("sha256").update(input).digest("base64");
}

function writeFileAtomic(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, data, "utf8");
}

function readFileUtf8(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function pExchange(exchangeDir, name) {
  return path.join(exchangeDir, name);
}

function writeJson(filePath, obj) {
  writeFileAtomic(filePath, JSON.stringify(obj, null, 2));
}

function readJson(filePath) {
  return JSON.parse(readFileUtf8(filePath));
}

function parseJsonSafe(raw, label) {
  try {
    return typeof raw === "string" ? JSON.parse(raw) : raw;
  } catch (e) {
    throw new Error(`${label}: JSON inválido: ${e.message}`);
  }
}

function call(agent, camel, snake) {
  if (typeof agent[camel] === "function") return agent[camel].bind(agent);
  if (snake && typeof agent[snake] === "function") return agent[snake].bind(agent);
  throw new Error(`Método não encontrado: ${camel}${snake ? ` / ${snake}` : ""}`);
}

function withManifestOnProofSequence(proofSequence, manifestAnchor) {
  return {
    ...proofSequence,
    primary_proof: {
      ...proofSequence.primary_proof,
      manifest: manifestAnchor,
    },
    confirmation_proofs: Array.isArray(proofSequence.confirmation_proofs)
      ? proofSequence.confirmation_proofs.map((item) => ({
          ...item,
          manifest: manifestAnchor,
        }))
      : [],
  };
}

async function packEnvelopeToFile(
  senderAgent,
  senderDid,
  recipientVerkey,
  kind,
  threadIdOpt,
  plaintext,
  expiresAtMsOpt,
  metaObjOpt,
  filePath
) {
  const envelopeJson = await senderAgent.envelopePackAuthcrypt(
    senderDid,
    recipientVerkey,
    kind,
    threadIdOpt ?? null,
    plaintext,
    expiresAtMsOpt ?? null,
    metaObjOpt ? JSON.stringify(metaObjOpt) : null
  );
  writeFileAtomic(filePath, envelopeJson);
}

async function unpackEnvelopeFromFile(receiverAgent, receiverDid, filePath) {
  const envelopeJson = readFileUtf8(filePath);
  return receiverAgent.envelopeUnpackAuto(receiverDid, envelopeJson);
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

async function resetBfilterForTests(baseUrl, adminToken, mBits, k) {
  const resp = await fetch(`${baseUrl}/test/reset`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${adminToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      filter_id: `test-presentations-v2-fp-${Date.now()}`,
      m_bits: mBits,
      k,
    }),
  });

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

async function writeDummyRevocations({
  baseUrl,
  adminToken,
  issuerDid,
  targetWindowStart,
  count,
}) {
  const revocationKeys = Array.from({ length: count }, (_, idx) =>
    `dummy-presentations-v2-fp-${Date.now()}-${process.pid}-${idx}-${Math.random()}`
  );
  const windowStarts = Array.from({ length: count }, () => targetWindowStart);

  const resp = await fetch(`${baseUrl}/admin/revocations/v2`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${adminToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      issuer_did: issuerDid,
      credential_record_id: `dummy-presentations-v2-fp-batch-${Date.now()}`,
      revocation_keys: revocationKeys,
      window_starts: windowStarts,
      reason: "force-false-positive-for-presentations-v2-test",
      requested_by: "teste-node-presentations-v2-fp",
    }),
  });

  const bodyText = await resp.text();
  assert(resp.ok, `Falha POST /admin/revocations/v2: ${resp.status} ${bodyText}`);
  const body = JSON.parse(bodyText);
  assert(body.ok === true, "escrita dummy no Bloom deveria retornar ok=true");
  return body;
}

(async () => {
  const GENESIS_FILE = mustEnv("GENESIS_FILE");
  const WALLET_PASS = process.env.WALLET_PASS || "minha_senha_teste";
  const TRUSTEE_SEED = mustEnv("TRUSTEE_SEED");
  const TRUSTEE_DID = mustEnv("TRUSTEE_DID");
  const BFILTER_BASE_URL = mustEnv("BFILTER_BASE_URL");
  const BFILTER_ADMIN_TOKEN = mustEnv("BFILTER_ADMIN_TOKEN");

  const walletsDir = path.join(__dirname, "..", "wallets");
  fs.mkdirSync(walletsDir, { recursive: true });

  const exchangeDir = path.join(
    __dirname,
    "exchange_3revocable_creds_zkp18_envelope_strict_files_v2_false_positive"
  );
  fs.mkdirSync(exchangeDir, { recursive: true });

  const issuerWalletPath = path.join(walletsDir, "issuer_3revocable_creds_zkp18_envelope_v2_fp.db");
  const holderWalletPath = path.join(walletsDir, "holder_3revocable_creds_zkp18_envelope_v2_fp.db");
  const verifierWalletPath = path.join(walletsDir, "verifier_3revocable_creds_zkp18_envelope_v2_fp.db");
  rmIfExists(issuerWalletPath);
  rmIfExists(holderWalletPath);
  rmIfExists(verifierWalletPath);

  const issuer = new IndyAgent();
  const holder = new IndyAgent();
  const verifier = new IndyAgent();

  const issuerPubFile = pExchange(exchangeDir, "pub_issuer.json");
  const holderPubFile = pExchange(exchangeDir, "pub_holder.json");
  const verifierPubFile = pExchange(exchangeDir, "pub_verifier.json");
  const ledgerIdsFile = pExchange(exchangeDir, "ledger_ids.json");

  try {
    const createAndRegisterSchema = call(issuer, "createAndRegisterSchema", "create_and_register_schema");
    const creddefSaveLocal = call(issuer, "creddefSaveLocal", "creddef_save_local");
    const creddefRegisterFromLocal = call(issuer, "creddefRegisterFromLocal", "creddef_register_from_local");
    const createCredentialOffer = call(issuer, "createCredentialOffer", "create_credential_offer");
    const createCredentialRequest = call(holder, "createCredentialRequest", "create_credential_request");
    const createLinkSecret = call(holder, "createLinkSecret", "create_link_secret");
    const storeCredential = call(holder, "storeCredential", "store_credential");
    const createPresentationPackageWithRevocationV2 = call(
      holder,
      "createPresentationPackageWithRevocationV2",
      "create_presentation_package_with_revocation_v2"
    );
    const verifyMixedPresentationPackageV2 = call(
      verifier,
      "verifyMixedPresentationPackageV2",
      "verify_mixed_presentation_package_v2"
    );
    const revocationBuildManifestAnchor = call(
      issuer,
      "revocationBuildManifestAnchor",
      "revocation_build_manifest_anchor"
    );
    const revocationWriteManifestAnchorOnLedger = call(
      issuer,
      "revocationWriteManifestAnchorOnLedger",
      "revocation_write_manifest_anchor_on_ledger"
    );
    const issueRevocableCredential = call(issuer, "issueRevocableCredential", "issue_revocable_credential");
    const storeReceivedRevocableCredential = call(
      holder,
      "storeReceivedRevocableCredential",
      "store_received_revocable_credential"
    );

    console.log("1) Resetando o bfilter em modo de testes com filtro pequeno...");
    await resetBfilterForTests(BFILTER_BASE_URL, BFILTER_ADMIN_TOKEN, TEST_FILTER_M_BITS, TEST_FILTER_K);

    console.log("2) Criando wallets...");
    await issuer.walletCreate(issuerWalletPath, WALLET_PASS);
    await holder.walletCreate(holderWalletPath, WALLET_PASS);
    await verifier.walletCreate(verifierWalletPath, WALLET_PASS);

    console.log("3) Abrindo wallets...");
    await issuer.walletOpen(issuerWalletPath, WALLET_PASS);
    await holder.walletOpen(holderWalletPath, WALLET_PASS);
    await verifier.walletOpen(verifierWalletPath, WALLET_PASS);

    console.log("4) Conectando na rede...");
    await issuer.connectNetwork(GENESIS_FILE);
    await holder.connectNetwork(GENESIS_FILE);
    await verifier.connectNetwork(GENESIS_FILE);

    console.log("5) Importando Trustee DID no issuer...");
    await issuer.importDidFromSeed(TRUSTEE_SEED);

    console.log("6) Criando DIDs e publicando bootstrap dos 3 atores...");
    const [issuerDid, issuerVerkey] = await issuer.createOwnDid();
    const [holderDid, holderVerkey] = await holder.createOwnDid();
    const [verifierDid, verifierVerkey] = await verifier.createOwnDid();
    writeJson(issuerPubFile, { did: issuerDid, verkey: issuerVerkey });
    writeJson(holderPubFile, { did: holderDid, verkey: holderVerkey });
    writeJson(verifierPubFile, { did: verifierDid, verkey: verifierVerkey });

    console.log("7) Registrando DIDs no ledger...");
    await tryRegisterDid(issuer, GENESIS_FILE, TRUSTEE_DID, issuerDid, issuerVerkey, "ENDORSER");
    await tryRegisterDid(issuer, GENESIS_FILE, TRUSTEE_DID, holderDid, holderVerkey, null);
    await tryRegisterDid(issuer, GENESIS_FILE, TRUSTEE_DID, verifierDid, verifierVerkey, null);

    console.log("8) Lendo manifesto do Bloom e ancorando no ledger...");
    const manifestEnvelope = await fetchManifestEnvelope(BFILTER_BASE_URL);
    const manifestHash = manifestEnvelope.manifest_hash_body;
    const manifestJson = await revocationBuildManifestAnchor(
      issuerDid,
      `${BFILTER_BASE_URL}/manifest`,
      manifestHash,
      String(manifestEnvelope.manifest.version || 1)
    );
    const manifest = parseJsonSafe(manifestJson, "manifest_anchor");
    const writeManifestJson = await revocationWriteManifestAnchorOnLedger(
      GENESIS_FILE,
      issuerDid,
      JSON.stringify(manifest)
    );
    const writeManifest = parseJsonSafe(writeManifestJson, "write_manifest");
    assert(writeManifest.ok === true, "write manifesto falhou");

    console.log("9) Criando 3 Schemas revogáveis...");
    const schemaCpfId = await createAndRegisterSchema(
      GENESIS_FILE,
      issuerDid,
      "cpf_revogavel_strict_v2_fp",
      `1.0.${Date.now()}`,
      ["nome", "cpf", "idade", ...CONTROL_ATTRS]
    );
    const schemaEndId = await createAndRegisterSchema(
      GENESIS_FILE,
      issuerDid,
      "endereco_revogavel_strict_v2_fp",
      `1.0.${Date.now() + 1}`,
      ["nome", "endereco", "cidade", "estado", ...CONTROL_ATTRS]
    );
    const schemaContatoId = await createAndRegisterSchema(
      GENESIS_FILE,
      issuerDid,
      "contato_revogavel_strict_v2_fp",
      `1.0.${Date.now() + 2}`,
      ["nome", "email", "telefone", ...CONTROL_ATTRS]
    );

    async function registerRevocableCredDef(schemaId, tag) {
      const localJson = await creddefSaveLocal(issuerDid, schemaId, tag, false, "prod");
      const local = parseJsonSafe(localJson, `creddef_local_${tag}`);
      const reg = await creddefRegisterFromLocal(GENESIS_FILE, local.id_local, issuerDid);
      return reg.credDefId || reg.cred_def_id;
    }

    console.log("10) Criando 3 CredDefs revogáveis...");
    const credDefCpfId = await registerRevocableCredDef(schemaCpfId, `TAG_CPF_REV_STRICT_V2_FP_${Date.now()}`);
    const credDefEndId = await registerRevocableCredDef(schemaEndId, `TAG_END_REV_STRICT_V2_FP_${Date.now()}`);
    const credDefContatoId = await registerRevocableCredDef(
      schemaContatoId,
      `TAG_CONTATO_REV_STRICT_V2_FP_${Date.now()}`
    );

    writeJson(ledgerIdsFile, {
      schemaCpfId,
      schemaEndId,
      schemaContatoId,
      credDefCpfId,
      credDefEndId,
      credDefContatoId,
    });

    console.log("11) Garantindo Link Secret no holder...");
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
      await packEnvelopeToFile(
        issuer,
        issuerDid,
        holderVerkey,
        "ssi/cred/offer",
        null,
        offerJson,
        null,
        { step: `${kind}.offer` },
        offerFile
      );

      const offerPlain = await unpackEnvelopeFromFile(holder, holderDid, offerFile);
      const offerObj = JSON.parse(offerPlain);
      const reqMetaId = offerObj?.nonce;
      assert(reqMetaId, `${kind}: offer sem nonce`);

      const credDefJsonLedger = await holder.fetchCredDefFromLedger(GENESIS_FILE, credDefId);
      const requestJson = await createCredentialRequest(
        "default",
        holderDid,
        credDefJsonLedger,
        offerPlain
      );

      const reqFile = pExchange(exchangeDir, `${kind}_02_request.env.json`);
      await packEnvelopeToFile(
        holder,
        holderDid,
        issuerVerkey,
        "ssi/cred/request",
        null,
        requestJson,
        null,
        { step: `${kind}.request` },
        reqFile
      );

      const reqPlain = await unpackEnvelopeFromFile(issuer, issuerDid, reqFile);

      const startTime = nowSec();
      const validityEnd = startTime + 86400 * 29;
      const issuePackageJson = await issueRevocableCredential(
        GENESIS_FILE,
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
        DEFAULT_EXTRA_WINDOWS_FOR_FP,
        JSON.stringify(manifest),
        null,
        null
      );
      const issuedPkg = parseJsonSafe(issuePackageJson, `issued_pkg_${kind}`);

      const credentialPackageFile = pExchange(exchangeDir, `${kind}_03_revocable_package.env.json`);
      await packEnvelopeToFile(
        issuer,
        issuerDid,
        holderVerkey,
        "ssi/revocation/credential_package",
        null,
        JSON.stringify(issuedPkg),
        null,
        {
          step: `${kind}.credential_package`,
          note: "issuer->holder envia credential_json + holder_bundle completo",
        },
        credentialPackageFile
      );

      const pkgPlain = await unpackEnvelopeFromFile(holder, holderDid, credentialPackageFile);
      const receivedPkg = parseJsonSafe(pkgPlain, `received_pkg_${kind}`);

      await storeCredential(
        credentialIdInWallet,
        receivedPkg.credential_json,
        reqMetaId,
        credDefJsonLedger,
        null
      );

      const storedBundleJson = await storeReceivedRevocableCredential(
        bundleId,
        JSON.stringify(receivedPkg.holder_bundle),
        credentialIdInWallet
      );
      const storedBundle = parseJsonSafe(storedBundleJson, `store_bundle_${kind}`);
      assert(storedBundle.ok === true, `${kind}: bundle não armazenado`);
      assert(
        storedBundle.holder_bundle.control.confirmation_window_count === DEFAULT_EXTRA_WINDOWS_FOR_FP,
        `${kind}: confirmation_window_count deveria ser ${DEFAULT_EXTRA_WINDOWS_FOR_FP}`
      );
      assert(
        storedBundle.holder_bundle.control.window_count > PRIMARY_WINDOW_INDEX,
        `${kind}: bundle deveria conter a janela primária configurada`
      );
      assert(
        storedBundle.holder_bundle.l_values.length === storedBundle.holder_bundle.control.window_count,
        `${kind}: holder_bundle deveria carregar todos os L-values`
      );

      const receiptFile = pExchange(exchangeDir, `${kind}_04_store_receipt.env.json`);
      await packEnvelopeToFile(
        holder,
        holderDid,
        issuerVerkey,
        "ssi/cred/store_receipt",
        null,
        JSON.stringify({
          ok: true,
          kind,
          credential_id: credentialIdInWallet,
          bundle_id: bundleId,
          window_count_received: storedBundle.holder_bundle.control.window_count,
        }),
        null,
        { step: `${kind}.store_receipt` },
        receiptFile
      );

      const receiptPlain = await unpackEnvelopeFromFile(issuer, issuerDid, receiptFile);
      assert(JSON.parse(receiptPlain).ok === true, `${kind}: receipt inválido`);

      return {
        issuedPkg: receivedPkg,
        credentialIdInWallet,
        bundleId,
        credDefId,
        startTime,
      };
    }

    console.log("12) Emitindo 3 credenciais revogáveis via envelopes...");
    const cpfFlow = await issueRevocableCredentialViaEnvelope({
      kind: "cpf",
      schemaId: schemaCpfId,
      credDefId: credDefCpfId,
      businessValues: { nome: "Edimar Verissimo", cpf: "12345678909", idade: "35" },
      credentialIdInWallet: "cred-cpf-rev-envelope-strict-v2-fp",
      bundleId: "bundle-cpf-rev-envelope-strict-v2-fp",
      issuedId: `issued-cpf-strict-v2-fp-${Date.now()}`,
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
      credentialIdInWallet: "cred-end-rev-envelope-strict-v2-fp",
      bundleId: "bundle-end-rev-envelope-strict-v2-fp",
      issuedId: `issued-end-strict-v2-fp-${Date.now()}`,
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
      credentialIdInWallet: "cred-contato-rev-envelope-strict-v2-fp",
      bundleId: "bundle-contato-rev-envelope-strict-v2-fp",
      issuedId: `issued-contato-strict-v2-fp-${Date.now()}`,
    });

    const policy = {
      max_consecutive_hits_for_revoke: 11,
      max_windows_to_request: 10,
      allow_post_expiry_confirmation_windows: true,
      holder_must_disprove_with_additional_windows: true,
    };

    const primaryWindowStart = cpfFlow.startTime + PRIMARY_WINDOW_INDEX * 86400;
    const threadId = `thread-v2-fp-3creds-${Date.now()}`;

    console.log("13) Verifier criando Proof Request e gravando envelope...");
    const proofRequest = {
      nonce: String(Date.now()),
      name: "proof-3creds-revogaveis-zkp18-strict-files-v2-fp",
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
    await packEnvelopeToFile(
      verifier,
      verifierDid,
      holderVerkey,
      "ssi/proof/request",
      threadId,
      JSON.stringify(proofRequest),
      null,
      { step: "proof_request" },
      proofReqFile
    );

    const proofReqPlain = await unpackEnvelopeFromFile(holder, holderDid, proofReqFile);
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

    const ids = readJson(ledgerIdsFile);
    const schemaCpfJsonLedger = await holder.fetchSchemaFromLedger(GENESIS_FILE, ids.schemaCpfId);
    const schemaEndJsonLedger = await holder.fetchSchemaFromLedger(GENESIS_FILE, ids.schemaEndId);
    const schemaContatoJsonLedger = await holder.fetchSchemaFromLedger(GENESIS_FILE, ids.schemaContatoId);
    const credDefCpfJsonLedger = await holder.fetchCredDefFromLedger(GENESIS_FILE, ids.credDefCpfId);
    const credDefEndJsonLedger = await holder.fetchCredDefFromLedger(GENESIS_FILE, ids.credDefEndId);
    const credDefContatoJsonLedger = await holder.fetchCredDefFromLedger(GENESIS_FILE, ids.credDefContatoId);

    const schemasMap = JSON.stringify({
      [ids.schemaCpfId]: JSON.parse(schemaCpfJsonLedger),
      [ids.schemaEndId]: JSON.parse(schemaEndJsonLedger),
      [ids.schemaContatoId]: JSON.parse(schemaContatoJsonLedger),
    });
    const credDefsMap = JSON.stringify({
      [ids.credDefCpfId]: JSON.parse(credDefCpfJsonLedger),
      [ids.credDefEndId]: JSON.parse(credDefEndJsonLedger),
      [ids.credDefContatoId]: JSON.parse(credDefContatoJsonLedger),
    });

    const verifierSchemasMap = JSON.stringify({
      [ids.schemaCpfId]: JSON.parse(await verifier.fetchSchemaFromLedger(GENESIS_FILE, ids.schemaCpfId)),
      [ids.schemaEndId]: JSON.parse(await verifier.fetchSchemaFromLedger(GENESIS_FILE, ids.schemaEndId)),
      [ids.schemaContatoId]: JSON.parse(await verifier.fetchSchemaFromLedger(GENESIS_FILE, ids.schemaContatoId)),
    });
    const verifierCredDefsMap = JSON.stringify({
      [ids.credDefCpfId]: JSON.parse(await verifier.fetchCredDefFromLedger(GENESIS_FILE, ids.credDefCpfId)),
      [ids.credDefEndId]: JSON.parse(await verifier.fetchCredDefFromLedger(GENESIS_FILE, ids.credDefEndId)),
      [ids.credDefContatoId]: JSON.parse(await verifier.fetchCredDefFromLedger(GENESIS_FILE, ids.credDefContatoId)),
    });

    function oneWindowSequences() {
      return [
        {
          credential_id_local: cpfFlow.credentialIdInWallet,
          primary_window_index: PRIMARY_WINDOW_INDEX,
          additional_window_count: 0,
        },
        {
          credential_id_local: endFlow.credentialIdInWallet,
          primary_window_index: PRIMARY_WINDOW_INDEX,
          additional_window_count: 0,
        },
        {
          credential_id_local: contatoFlow.credentialIdInWallet,
          primary_window_index: PRIMARY_WINDOW_INDEX,
          additional_window_count: 0,
        },
      ];
    }

    function refutationSequences() {
      return [
        {
          credential_id_local: cpfFlow.credentialIdInWallet,
          primary_window_index: PRIMARY_WINDOW_INDEX,
          additional_window_count: ADDITIONAL_CONFIRMATION_WINDOWS,
        },
        {
          credential_id_local: endFlow.credentialIdInWallet,
          primary_window_index: PRIMARY_WINDOW_INDEX,
          additional_window_count: 0,
        },
        {
          credential_id_local: contatoFlow.credentialIdInWallet,
          primary_window_index: PRIMARY_WINDOW_INDEX,
          additional_window_count: 0,
        },
      ];
    }

    function proofSequencePayload(packageReceived, manifestOverride = null) {
      return JSON.stringify(
        packageReceived.revocation_proof_sequences.map((item) => ({
          credential_id_local: item.credential_id_local,
          proof_sequence: manifestOverride
            ? withManifestOnProofSequence(item.proof_sequence, manifestOverride)
            : item.proof_sequence,
        }))
      );
    }

    async function fetchCurrentManifestAnchor() {
      const currentManifestEnvelope = await fetchManifestEnvelope(BFILTER_BASE_URL);
      const currentManifestJson = await revocationBuildManifestAnchor(
        issuerDid,
        `${BFILTER_BASE_URL}/manifest`,
        currentManifestEnvelope.manifest_hash_body,
        String(currentManifestEnvelope.manifest.version || 1)
      );
      return parseJsonSafe(currentManifestJson, "current_manifest_anchor");
    }

    console.log("14) Baseline: holder envia só 1 janela por credencial e o verifier aceita...");
    const baselinePackageJson = await createPresentationPackageWithRevocationV2(
      JSON.stringify(proofReqObj),
      JSON.stringify(requestedCreds),
      schemasMap,
      credDefsMap,
      JSON.stringify(oneWindowSequences())
    );
    const baselinePackage = parseJsonSafe(baselinePackageJson, "baseline_package");
    assert(baselinePackage.ok === true, "baseline package deveria retornar ok=true");
    assert(
      baselinePackage.revocation_proof_sequences.length === 3,
      "o holder deveria enviar 3 sequências de prova, uma por credencial"
    );
    assert(
      baselinePackage.revocation_proof_sequences.every((item) => item.additional_window_count === 0),
      "no baseline o holder deveria enviar só 1 janela por credencial"
    );

    const baselinePackageFile = pExchange(exchangeDir, "proof_02_baseline_package_v2.env.json");
    await packEnvelopeToFile(
      holder,
      holderDid,
      verifierVerkey,
      "ssi/proof/presentation_package_revocation_v2",
      threadId,
      JSON.stringify(baselinePackage),
      null,
      {
        step: "proof.presentation_package_v2.baseline",
        note: "holder->verifier envia só 1 janela por credencial no baseline",
      },
      baselinePackageFile
    );

    const baselinePackagePlain = await unpackEnvelopeFromFile(verifier, verifierDid, baselinePackageFile);
    const baselinePackageReceived = parseJsonSafe(baselinePackagePlain, "baseline_package_received");
    const baselineVerifyJson = await verifyMixedPresentationPackageV2(
      JSON.stringify(proofReqObj),
      baselinePackageReceived.presentation_json,
      verifierSchemasMap,
      verifierCredDefsMap,
      proofSequencePayload(baselinePackageReceived),
      null,
      JSON.stringify(policy)
    );
    const baselineVerify = parseJsonSafe(baselineVerifyJson, "baseline_verify");
    assert(baselineVerify.ok === true, "baseline_verify deveria retornar ok=true");
    assert(baselineVerify.accepted === true, "o baseline deveria ser aceito");
    assert(baselineVerify.revoked === false, "o baseline não deveria marcar revogação");

    console.log("15) Forçando falso positivo controlado na janela principal do CPF...");
    let falsePositiveReady = false;
    let fpBatchesUsed = 0;
    let currentManifestAnchor = manifest;
    for (let attempt = 1; attempt <= MAX_FP_BATCHES; attempt++) {
      const attemptPackageJson = await createPresentationPackageWithRevocationV2(
        JSON.stringify(proofReqObj),
        JSON.stringify(requestedCreds),
        schemasMap,
        credDefsMap,
        JSON.stringify(oneWindowSequences())
      );
      const attemptPackage = parseJsonSafe(attemptPackageJson, `attempt_package_${attempt}`);
      const attemptVerifyJson = await verifyMixedPresentationPackageV2(
        JSON.stringify(proofReqObj),
        attemptPackage.presentation_json,
        verifierSchemasMap,
        verifierCredDefsMap,
        proofSequencePayload(attemptPackage, currentManifestAnchor),
        null,
        JSON.stringify(policy)
      );
      const attemptVerify = parseJsonSafe(attemptVerifyJson, `attempt_verify_${attempt}`);
      const cpfStatus = attemptVerify.per_credential_status.find(
        (item) => item.credential_id_local === cpfFlow.credentialIdInWallet
      );
      if (
        cpfStatus &&
        cpfStatus.revocation_status &&
        cpfStatus.revocation_status.decision === "needs_next_window"
      ) {
        const refutePackageJson = await createPresentationPackageWithRevocationV2(
          JSON.stringify(proofReqObj),
          JSON.stringify(requestedCreds),
          schemasMap,
          credDefsMap,
          JSON.stringify(refutationSequences())
        );
        const refutePackage = parseJsonSafe(refutePackageJson, `refute_package_${attempt}`);
        const refuteVerifyJson = await verifyMixedPresentationPackageV2(
          JSON.stringify(proofReqObj),
          refutePackage.presentation_json,
          verifierSchemasMap,
          verifierCredDefsMap,
          proofSequencePayload(refutePackage, currentManifestAnchor),
          null,
          JSON.stringify(policy)
        );
        const refuteVerify = parseJsonSafe(refuteVerifyJson, `refute_verify_${attempt}`);
        const refuteCpfStatus = refuteVerify.per_credential_status.find(
          (item) => item.credential_id_local === cpfFlow.credentialIdInWallet
        );
        if (
          refuteCpfStatus &&
          refuteCpfStatus.revocation_status &&
          refuteCpfStatus.revocation_status.decision === "false_positive_confirmed"
        ) {
          falsePositiveReady = true;
          fpBatchesUsed = attempt - 1;
          break;
        }
      }

      await writeDummyRevocations({
        baseUrl: BFILTER_BASE_URL,
        adminToken: BFILTER_ADMIN_TOKEN,
        issuerDid,
        targetWindowStart: primaryWindowStart,
        count: DUMMY_BATCH_SIZE,
      });
      currentManifestAnchor = await fetchCurrentManifestAnchor();
    }
    assert(falsePositiveReady, "não foi possível induzir falso positivo controlado no CPF");

    const writeManifestAfterFpJson = await revocationWriteManifestAnchorOnLedger(
      GENESIS_FILE,
      issuerDid,
      JSON.stringify(currentManifestAnchor)
    );
    const writeManifestAfterFp = parseJsonSafe(writeManifestAfterFpJson, "write_manifest_after_fp");
    assert(writeManifestAfterFp.ok === true, "write manifesto after fp falhou");

    console.log("16) Holder envia só 1 janela por credencial e o verifier pede mais janelas para o CPF...");
    const oneWindowPackageJson = await createPresentationPackageWithRevocationV2(
      JSON.stringify(proofReqObj),
      JSON.stringify(requestedCreds),
      schemasMap,
      credDefsMap,
      JSON.stringify(oneWindowSequences())
    );
    const oneWindowPackage = parseJsonSafe(oneWindowPackageJson, "one_window_package");
    const oneWindowPackageFile = pExchange(exchangeDir, "proof_03_one_window_package_v2.env.json");
    await packEnvelopeToFile(
      holder,
      holderDid,
      verifierVerkey,
      "ssi/proof/presentation_package_revocation_v2",
      threadId,
      JSON.stringify(oneWindowPackage),
      null,
      {
        step: "proof.presentation_package_v2.one_window",
        note: "holder->verifier envia só a janela principal de cada credencial",
      },
      oneWindowPackageFile
    );

    const oneWindowPackagePlain = await unpackEnvelopeFromFile(verifier, verifierDid, oneWindowPackageFile);
    const oneWindowPackageReceived = parseJsonSafe(oneWindowPackagePlain, "one_window_package_received");
    const oneWindowVerifyJson = await verifyMixedPresentationPackageV2(
      JSON.stringify(proofReqObj),
      oneWindowPackageReceived.presentation_json,
      verifierSchemasMap,
      verifierCredDefsMap,
      proofSequencePayload(oneWindowPackageReceived, writeManifestAfterFp.manifest),
      null,
      JSON.stringify(policy)
    );
    const oneWindowVerify = parseJsonSafe(oneWindowVerifyJson, "one_window_verify");
    assert(oneWindowVerify.ok === true, "one_window_verify deveria retornar ok=true");
    assert(oneWindowVerify.accepted === false, "sem contraprova adicional o pacote deve ser rejeitado");
    assert(oneWindowVerify.revoked === false, "sem contraprova adicional o pacote ainda não deve confirmar revogação");
    assert(oneWindowVerify.requires_more_windows === true, "o pacote deveria indicar que faltam janelas");

    const oneWindowCpfStatus = oneWindowVerify.per_credential_status.find(
      (item) => item.credential_id_local === cpfFlow.credentialIdInWallet
    );
    const oneWindowCpfSequence = oneWindowPackageReceived.revocation_proof_sequences.find(
      (item) => item.credential_id_local === cpfFlow.credentialIdInWallet
    );
    assert(oneWindowCpfStatus, "o pacote deveria incluir status da credencial CPF");
    assert(oneWindowCpfSequence, "o pacote inicial deveria conter a sequência do CPF");
    assert(
      oneWindowCpfStatus.revocation_status.decision === "needs_next_window",
      "com só 1 janela o CPF deveria cair em needs_next_window"
    );

    console.log("17) Verifier solicita por envelope authcrypt mais 2 janelas só do CPF...");
    const moreWindowsRequest = {
      ok: true,
      credential_id_local: cpfFlow.credentialIdInWallet,
      primary_window_index: PRIMARY_WINDOW_INDEX,
      additional_window_count_requested: ADDITIONAL_CONFIRMATION_WINDOWS,
      reason: "primary window came back maybe_present; holder must disprove with additional windows",
    };
    const moreWindowsReqFile = pExchange(exchangeDir, "proof_04_more_windows_request.env.json");
    await packEnvelopeToFile(
      verifier,
      verifierDid,
      holderVerkey,
      "ssi/proof/revocation_more_windows_request",
      threadId,
      JSON.stringify(moreWindowsRequest),
      null,
      {
        step: "proof.more_windows_request",
        note: "verifier->holder pede mais 2 janelas apenas para o CPF",
      },
      moreWindowsReqFile
    );

    const moreWindowsReqPlain = await unpackEnvelopeFromFile(holder, holderDid, moreWindowsReqFile);
    const moreWindowsReqObj = parseJsonSafe(moreWindowsReqPlain, "more_windows_request");
    assert(
      moreWindowsReqObj.credential_id_local === cpfFlow.credentialIdInWallet,
      "o pedido adicional deveria mirar apenas a credencial CPF"
    );

    console.log("18) Holder responde com 3 janelas para CPF e 1 janela para as demais...");
    const threeWindowPackageJson = await createPresentationPackageWithRevocationV2(
      JSON.stringify(proofReqObj),
      JSON.stringify(requestedCreds),
      schemasMap,
      credDefsMap,
      JSON.stringify(refutationSequences())
    );
    const threeWindowPackage = parseJsonSafe(threeWindowPackageJson, "three_window_package");
    assert(threeWindowPackage.ok === true, "three_window_package deveria retornar ok=true");

    const cpfSequence = threeWindowPackage.revocation_proof_sequences.find(
      (item) => item.credential_id_local === cpfFlow.credentialIdInWallet
    );
    const endSequence = threeWindowPackage.revocation_proof_sequences.find(
      (item) => item.credential_id_local === endFlow.credentialIdInWallet
    );
    const contatoSequence = threeWindowPackage.revocation_proof_sequences.find(
      (item) => item.credential_id_local === contatoFlow.credentialIdInWallet
    );
    assert(cpfSequence.additional_window_count === 2, "o CPF deveria levar 2 janelas adicionais");
    assert(endSequence.additional_window_count === 0, "endereço não deveria levar janelas extras");
    assert(contatoSequence.additional_window_count === 0, "contato não deveria levar janelas extras");

    const threeWindowPackageFile = pExchange(exchangeDir, "proof_05_three_window_package_v2.env.json");
    await packEnvelopeToFile(
      holder,
      holderDid,
      verifierVerkey,
      "ssi/proof/presentation_package_revocation_v2",
      threadId,
      JSON.stringify(threeWindowPackage),
      null,
      {
        step: "proof.presentation_package_v2.refutation",
        note: "holder->verifier envia mais 2 janelas só para o CPF",
      },
      threeWindowPackageFile
    );

    const threeWindowPackagePlain = await unpackEnvelopeFromFile(verifier, verifierDid, threeWindowPackageFile);
    const threeWindowPackageReceived = parseJsonSafe(threeWindowPackagePlain, "three_window_package_received");
    const threeWindowVerifyJson = await verifyMixedPresentationPackageV2(
      JSON.stringify(proofReqObj),
      threeWindowPackageReceived.presentation_json,
      verifierSchemasMap,
      verifierCredDefsMap,
      proofSequencePayload(threeWindowPackageReceived, writeManifestAfterFp.manifest),
      null,
      JSON.stringify(policy)
    );
    const threeWindowVerify = parseJsonSafe(threeWindowVerifyJson, "three_window_verify");
    assert(threeWindowVerify.ok === true, "three_window_verify deveria retornar ok=true");
    assert(threeWindowVerify.accepted === true, "com a contraprova do holder o pacote deve voltar a ser aceito");
    assert(threeWindowVerify.revoked === false, "após a contraprova o pacote não deve permanecer revogado");

    const threeWindowCpfStatus = threeWindowVerify.per_credential_status.find(
      (item) => item.credential_id_local === cpfFlow.credentialIdInWallet
    );
    assert(threeWindowCpfStatus, "o pacote deveria manter o status do CPF");
    assert(
      threeWindowCpfStatus.revocation_status.decision === "false_positive_confirmed",
      "o CPF deveria ser reclassificado como false_positive_confirmed"
    );
    assert(
      threeWindowCpfStatus.revocation_status.trace.length >= 2 &&
        threeWindowCpfStatus.revocation_status.trace[0].maybe_present === true &&
        threeWindowCpfStatus.revocation_status.trace[1].maybe_present === false,
      "a refutação do falso positivo deveria aparecer como true,false"
    );

    console.log("✅ OK: teste strict files v2 com falso positivo e negociação de janelas passou.");
    console.log("📌 Resumo final:", {
      issuer_to_holder_window_count_cpf: cpfFlow.issuedPkg.holder_bundle.control.window_count,
      issuer_to_holder_window_count_end: endFlow.issuedPkg.holder_bundle.control.window_count,
      issuer_to_holder_window_count_contato: contatoFlow.issuedPkg.holder_bundle.control.window_count,
      holder_to_verifier_sequences_initial: oneWindowPackageReceived.revocation_proof_sequences.length,
      holder_to_verifier_sequences_refutation: threeWindowPackageReceived.revocation_proof_sequences.length,
      cpf_initial_additional_windows: oneWindowCpfSequence.additional_window_count,
      cpf_refutation_additional_windows: cpfSequence.additional_window_count,
      false_positive_batches_used: fpBatchesUsed,
      accepted_before_fp: baselineVerify.accepted,
      accepted_with_one_window_after_fp: oneWindowVerify.accepted,
      accepted_with_refutation_after_fp: threeWindowVerify.accepted,
    });
    console.log(`📁 Arquivos gerados em: ${exchangeDir}`);
  } finally {
    try { await issuer.walletClose(); } catch (_) {}
    try { await holder.walletClose(); } catch (_) {}
    try { await verifier.walletClose(); } catch (_) {}
  }
})().catch((e) => {
  console.error("FALHA NO TESTE:", e?.message || e);
  console.error(e?.stack || "");
  process.exit(1);
});
