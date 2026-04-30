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
TEST_FILTER_M_BITS=2000 \
TEST_FILTER_K=3 \
TRIALS=20 \
node teste-node/revocation/test_revocation_57_v2_false_positive_refutation_percentages_by_bloom_size_von.js

Para subir o bfilter em modo de testes:
cd /home/yugi/programacao/bfilter
BFILTER_ENABLE_TEST_API=1 \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
cargo run

ENV OPCIONAIS:
- RUN_MODE=smoke|full
- TEST_FILTER_M_BITS=200000
- TEST_FILTER_K=3
- TRIALS=20
- PRIMARY_WINDOW_INDEX=10
- VALIDITY_WINDOW_COUNT=30
- DUMMY_BATCH_SIZE=32
- MAX_FP_BATCHES=400
- OUT_DIR=teste-node/revocation/out
*/

/*
Teste experimental baseado no teste 50.

Objetivo:
- emitir 1 credencial revogavel valida com 10 janelas extras disponiveis para confirmacao;
- em cada rodada, resetar o Bloom Filter com o tamanho configurado;
- induzir um falso positivo apenas na janela principal;
- medir em quantas rodadas:
  - 1 janela extra basta para refutar o falso positivo (sequencia true,false);
  - 2 janelas extras sao necessarias (sequencia true,true,false);
  - nem 2 janelas extras bastam, embora a credencial ainda tenha mais janelas de confirmacao disponiveis no protocolo (sequencia true,true,true).

Interpretacao:
- os percentuais sao calculados sobre as rodadas em que um falso positivo na janela principal
  foi realmente encontrado dentro do budget configurado;
- o experimento mede so as duas primeiras janelas extras, mesmo que a credencial emitida carregue 10;
- o teste permite informar TEST_FILTER_M_BITS para aproximar um cenario operacional real.
*/

const crypto = require("crypto");
const fs = require("fs");
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

const BFILTER_BASE_URL = (process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080").replace(/\/+$/, "");
const BFILTER_ADMIN_TOKEN = process.env.BFILTER_ADMIN_TOKEN || "dev-admin-token";
const RUN_MODE = (process.env.RUN_MODE || "full").trim().toLowerCase();
const TEST_FILTER_M_BITS = Number(process.env.TEST_FILTER_M_BITS || "200000");
const TEST_FILTER_K = Number(process.env.TEST_FILTER_K || "3");
const TRIALS = Number(process.env.TRIALS || (RUN_MODE === "smoke" ? "3" : "20"));
const PRIMARY_WINDOW_INDEX = Number(process.env.PRIMARY_WINDOW_INDEX || "10");
const VALIDITY_WINDOW_COUNT = Number(process.env.VALIDITY_WINDOW_COUNT || "30");
const DUMMY_BATCH_SIZE = Number(process.env.DUMMY_BATCH_SIZE || (RUN_MODE === "smoke" ? "64" : "32"));
const MAX_FP_BATCHES = Number(process.env.MAX_FP_BATCHES || (RUN_MODE === "smoke" ? "80" : "400"));
const OUT_DIR = process.env.OUT_DIR || path.join("teste-node", "revocation", "out");
const REQUIRED_EXTRA_WINDOWS_FOR_FP = 10;
const ADDITIONAL_WINDOWS_ONE_EXTRA = 1;
const ADDITIONAL_WINDOWS_TWO_EXTRAS = 2;
const VERIFY_BASELINE_EACH_TRIAL =
  process.env.VERIFY_BASELINE_EACH_TRIAL === undefined
    ? RUN_MODE !== "smoke"
    : process.env.VERIFY_BASELINE_EACH_TRIAL === "1";
const STOP_AFTER_FIRST_FALSE_POSITIVE_IN_SMOKE =
  process.env.STOP_AFTER_FIRST_FALSE_POSITIVE_IN_SMOKE === undefined
    ? RUN_MODE === "smoke"
    : process.env.STOP_AFTER_FIRST_FALSE_POSITIVE_IN_SMOKE === "1";

const POLICY = {
  max_consecutive_hits_for_revoke: 11,
  max_windows_to_request: 10,
  allow_post_expiry_confirmation_windows: true,
  holder_must_disprove_with_additional_windows: true,
};

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function nowIso() {
  return new Date().toISOString();
}

function sha256Base64(input) {
  return crypto.createHash("sha256").update(input).digest("base64");
}

function mkdirp(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function formatInt(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) {
    return "-";
  }
  return Number(value).toLocaleString("pt-BR");
}

function formatPercent(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) {
    return "-";
  }
  return `${Number(value).toFixed(1)}%`;
}

function percentOf(value, total) {
  if (!Number(total)) return 0;
  return (Number(value) / Number(total)) * 100;
}

function average(values) {
  if (!values.length) return null;
  return values.reduce((acc, item) => acc + Number(item), 0) / values.length;
}

function bloomFpEstimate(mBits, k, insertedCount) {
  const m = Number(mBits);
  const hashes = Number(k);
  const n = Number(insertedCount);
  if (!m || !hashes || n < 0) return 0;
  return Math.pow(1 - Math.exp((-hashes * n) / m), hashes);
}

function makeMarkdownTable(rows, columns) {
  const widths = columns.map((column) => {
    const cellWidths = rows.map((row) => String(row[column.key]).length);
    return Math.max(column.label.length, ...cellWidths);
  });

  const pad = (value, width) => String(value).padEnd(width, " ");
  const header = `| ${columns.map((column, idx) => pad(column.label, widths[idx])).join(" | ")} |`;
  const divider = `| ${widths.map((width) => "-".repeat(width)).join(" | ")} |`;
  const body = rows.map(
    (row) => `| ${columns.map((column, idx) => pad(row[column.key], widths[idx])).join(" | ")} |`
  );

  return [header, divider, ...body].join("\n");
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function makeHtmlTable(rows, columns) {
  const headerHtml = columns
    .map(
      (column) =>
        `<th style="border:1px solid #999;padding:8px 10px;background:#f3f4f6;text-align:left;">${escapeHtml(column.label)}</th>`
    )
    .join("");

  const bodyHtml = rows
    .map((row, rowIndex) => {
      const background = rowIndex % 2 === 0 ? "#ffffff" : "#fafafa";
      const cells = columns
        .map(
          (column) =>
            `<td style="border:1px solid #bbb;padding:8px 10px;background:${background};vertical-align:top;">${escapeHtml(
              row[column.key]
            )}</td>`
        )
        .join("");
      return `<tr>${cells}</tr>`;
    })
    .join("\n");

  return [
    '<table style="border-collapse:collapse;margin:16px 0 20px 0;min-width:980px;">',
    `<thead><tr>${headerHtml}</tr></thead>`,
    `<tbody>${bodyHtml}</tbody>`,
    "</table>",
  ].join("\n");
}

async function readJsonResponse(resp, context) {
  const text = await resp.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch (err) {
    throw new Error(`${context}: resposta nao e JSON valido: ${text}`);
  }
  return body;
}

async function tryRegisterDid(agent, genesisFile, submitterDid, did, verkey, role) {
  try {
    await agent.registerDidOnLedger(genesisFile, submitterDid, did, verkey, role);
  } catch (e) {
    const msg = e?.message || String(e);
    if (/already exists|exists|DID.*exist|NYM.*exist|Ledger/i.test(msg)) {
      console.log(`ℹ️ DID ja estava no ledger, seguindo: ${did}`);
      return;
    }
    throw e;
  }
}

async function fetchManifestEnvelope(baseUrl) {
  const resp = await fetch(`${baseUrl}/manifest`);
  const manifestBodyText = await resp.text();
  let body = null;
  try {
    body = manifestBodyText ? JSON.parse(manifestBodyText) : null;
  } catch (err) {
    throw new Error(`GET /manifest: resposta nao e JSON valido: ${manifestBodyText}`);
  }
  assert(resp.ok, `Falha GET /manifest: ${resp.status} ${JSON.stringify(body)}`);
  assert(body && body.ok === true, "manifesto Bloom deveria retornar ok=true");
  body.manifest_hash_body = sha256Base64(manifestBodyText);
  return body;
}

function getFilterById(manifestEnvelope, filterId) {
  const filters = Array.isArray(manifestEnvelope?.manifest?.filters) ? manifestEnvelope.manifest.filters : [];
  const filter = filters.find((item) => item.filter_id === filterId);
  assert(filter, `Filtro nao encontrado no manifesto: ${filterId}`);
  return filter;
}

function getActiveFilter(manifestEnvelope) {
  return getFilterById(manifestEnvelope, manifestEnvelope.manifest.active_filter_id);
}

function buildManifestAnchorFromEnvelope(issuerDid, manifestEnvelope) {
  return {
    issuer_did: issuerDid,
    manifest_url: `${BFILTER_BASE_URL}/manifest`,
    manifest_hash: String(manifestEnvelope.manifest_hash_body || ""),
    manifest_version: String(manifestEnvelope?.manifest?.version || 1),
    updated_at: nowSec(),
  };
}

async function resetBfilterForTests(baseUrl, adminToken, mBits, k) {
  const resp = await fetch(`${baseUrl}/test/reset`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${adminToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      filter_id: `test-fp-extra-windows-${mBits}-${Date.now()}`,
      m_bits: mBits,
      k,
    }),
  });

  const body = await readJsonResponse(resp, "POST /test/reset");
  if (resp.status === 404) {
    throw new Error(
      "O endpoint /test/reset nao esta disponivel. Suba o bfilter com BFILTER_ENABLE_TEST_API=1."
    );
  }

  assert(resp.ok, `Falha POST /test/reset: ${resp.status} ${JSON.stringify(body)}`);
  assert(body && body.ok === true, "reset do bfilter deveria retornar ok=true");
  return body;
}

async function writeDummyRevocations({
  baseUrl,
  adminToken,
  issuerDid,
  targetWindowStart,
  count,
  trialIndex,
  batchIndex,
}) {
  const revocationKeys = Array.from({ length: count }, (_, idx) =>
    `dummy-fp-extra-window-${Date.now()}-${process.pid}-${trialIndex}-${batchIndex}-${idx}-${Math.random()}`
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
      credential_record_id: `dummy-fp-extra-window-${trialIndex}-${batchIndex}-${Date.now()}`,
      revocation_keys: revocationKeys,
      window_starts: windowStarts,
      reason: "measure-false-positive-extra-window-percentages",
      requested_by: "teste-node-revocation-57",
    }),
  });

  const body = await readJsonResponse(resp, "POST /admin/revocations/v2");
  assert(resp.ok, `Falha POST /admin/revocations/v2: ${resp.status} ${JSON.stringify(body)}`);
  assert(body && body.ok === true, "escrita dummy no Bloom deveria retornar ok=true");
  return body;
}

function withManifestOnProofSequence(proofSequence, manifestAnchor) {
  return {
    ...proofSequence,
    primary_proof: {
      ...proofSequence.primary_proof,
      manifest: manifestAnchor,
    },
    confirmation_proofs: (proofSequence.confirmation_proofs || []).map((proof) => ({
      ...proof,
      manifest: manifestAnchor,
    })),
  };
}

function tracePattern(status) {
  const trace = Array.isArray(status?.trace) ? status.trace : [];
  return trace
    .map((item) => {
      if (item.maybe_present === true) return "T";
      if (item.maybe_present === false) return "F";
      return "?";
    })
    .join(",");
}

function classifyTrial(twoWindowStatus, threeWindowStatus) {
  if (twoWindowStatus.decision === "false_positive_confirmed") {
    return "1_extra_window_sufficient";
  }

  if (!threeWindowStatus) {
    return "2_extra_windows_insufficient";
  }

  if (threeWindowStatus.decision === "false_positive_confirmed") {
    return "2_extra_windows_required";
  }

  if (threeWindowStatus.decision === "needs_next_window") {
    return "2_extra_windows_insufficient";
  }

  return "unexpected";
}

function makeSummary(results) {
  const fpTrials = results.filter((item) => item.false_positive_found);
  const oneExtra = fpTrials.filter((item) => item.classification === "1_extra_window_sufficient");
  const twoExtra = fpTrials.filter((item) => item.classification === "2_extra_windows_required");
  const insufficient = fpTrials.filter((item) => item.classification === "2_extra_windows_insufficient");
  const unexpected = fpTrials.filter((item) => item.classification === "unexpected");
  const withoutFp = results.filter((item) => !item.false_positive_found);
  const loads = fpTrials.map((item) => item.load_percent_at_hit).filter((value) => value !== null);

  return {
    total_trials: results.length,
    false_positive_trials: fpTrials.length,
    false_positive_trial_percent: percentOf(fpTrials.length, results.length),
    no_false_positive_within_budget: withoutFp.length,
    no_false_positive_within_budget_percent: percentOf(withoutFp.length, results.length),
    one_extra_window_sufficient: oneExtra.length,
    one_extra_window_sufficient_percent: percentOf(oneExtra.length, fpTrials.length),
    two_extra_windows_required: twoExtra.length,
    two_extra_windows_required_percent: percentOf(twoExtra.length, fpTrials.length),
    two_extra_windows_insufficient: insufficient.length,
    two_extra_windows_insufficient_percent: percentOf(insufficient.length, fpTrials.length),
    unexpected_classifications: unexpected.length,
    avg_load_percent_at_hit: average(loads),
    avg_inserted_count_at_hit: average(
      fpTrials.map((item) => item.inserted_count_at_hit).filter((value) => value !== null)
    ),
    avg_trial_duration_ms: average(
      results.map((item) => item.duration_ms).filter((value) => value !== null && value !== undefined)
    ),
    avg_theoretical_fp_percent_at_hit: average(
      fpTrials
        .map((item) => item.theoretical_fp_percent_at_hit)
        .filter((value) => value !== null)
    ),
  };
}

async function setupExperiment() {
  const IndyAgent = loadIndyAgent();
  const pass = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET = process.env.RESET_WALLET === "1";
  const TRUSTEE_SEED = process.env.TRUSTEE_SEED || NETWORK_CONFIG.trusteeSeed;
  const TRUSTEE_DID = process.env.TRUSTEE_DID || NETWORK_CONFIG.trusteeDid;

  const walletDir = ensureWalletDir();
  const issuerDb =
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_v2_fp_percentages_issuer.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_v2_fp_percentages_holder.db");
  const verifierDb =
    process.env.WALLET_VERIFIER || path.join(walletDir, "test_wallet_revocation_v2_fp_percentages_verifier.db");

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
  const createLinkSecret = fn(holder, "createLinkSecret", "create_link_secret");
  const createCredentialRequest = fn(holder, "createCredentialRequest", "create_credential_request");
  const storeCredential = fn(holder, "storeCredential", "store_credential");
  const issueRevocableCredential = fn(issuer, "issueRevocableCredential", "issue_revocable_credential");
  const storeReceivedRevocableCredential = fn(
    holder,
    "storeReceivedRevocableCredential",
    "store_received_revocable_credential"
  );
  const buildPresentationRevocationProofV2 = fn(
    holder,
    "buildPresentationRevocationProofV2",
    "build_presentation_revocation_proof_v2"
  );
  const verifyPresentationRevocationProofV2 = fn(
    verifier,
    "verifyPresentationRevocationProofV2",
    "verify_presentation_revocation_proof_v2"
  );

  console.log("1) Resetando o bfilter para montar o bundle SSI base...");
  await resetBfilterForTests(BFILTER_BASE_URL, BFILTER_ADMIN_TOKEN, TEST_FILTER_M_BITS, TEST_FILTER_K);
  const initialManifestEnvelope = await fetchManifestEnvelope(BFILTER_BASE_URL);

  console.log("2) Criando e registrando issuer, holder e verifier...");
  const [trusteeDid] = await importDidFromSeed(TRUSTEE_SEED);
  assert(trusteeDid === TRUSTEE_DID, `Trustee DID inesperado: ${trusteeDid}`);

  const [issuerDid, issuerVerkey] = await issuer.createOwnDid();
  const [holderDid, holderVerkey] = await holder.createOwnDid();
  const [verifierDid, verifierVerkey] = await verifier.createOwnDid();

  await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, issuerDid, issuerVerkey, "ENDORSER");
  await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, holderDid, holderVerkey, "ENDORSER");
  await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, verifierDid, verifierVerkey, "ENDORSER");

  console.log("3) Emitindo a credencial revogavel base do experimento...");
  const initialManifestAnchor = buildManifestAnchorFromEnvelope(issuerDid, initialManifestEnvelope);

  const schemaIdRev = await createAndRegisterSchema(
    genesisAbs,
    issuerDid,
    `SchemaRevV2FpPercentages_${Date.now()}`,
    `1.${nowSec()}`,
    ["nome", "cpf", "idade", ...CONTROL_ATTRS]
  );

  const localJson = await creddefSaveLocal(
    issuerDid,
    schemaIdRev,
    `TAG_REV_V2_FP_PERCENTAGES_${Date.now()}`,
    false,
    "prod"
  );
  const local = parseJsonSafe(localJson, "creddef_local");
  const reg = await creddefRegisterFromLocal(genesisAbs, local.id_local, issuerDid);
  const credDefIdRev = reg.credDefId || reg.cred_def_id;

  const schemaRevLedger = parseJsonSafe(await fetchSchemaFromLedger(genesisAbs, schemaIdRev), "schema_rev");
  const credDefRevLedger = parseJsonSafe(await fetchCredDefFromLedger(genesisAbs, credDefIdRev), "creddef_rev");

  try {
    await createLinkSecret("default");
  } catch (_) {}

  const startTime = nowSec();
  const validityEnd = startTime + 86400 * (VALIDITY_WINDOW_COUNT - 1);
  assert(
    PRIMARY_WINDOW_INDEX + ADDITIONAL_WINDOWS_TWO_EXTRAS < VALIDITY_WINDOW_COUNT,
    "PRIMARY_WINDOW_INDEX precisa deixar espaco para 2 janelas extras dentro da validade"
  );

  const offerJson = await createCredentialOffer(credDefIdRev, `offer-v2-fp-percentages-${Date.now()}`);
  const requestJson = await createCredentialRequest(
    "default",
    holderDid,
    JSON.stringify(credDefRevLedger),
    offerJson
  );
  const requestMetadataId = extractNonce(offerJson);

  const issuedJson = await issueRevocableCredential(
    genesisAbs,
    `issued-v2-fp-percentages-${Date.now()}`,
    holderDid,
    credDefIdRev,
    schemaIdRev,
    offerJson,
    requestJson,
    JSON.stringify({
      nome: "Alice FP Percentages",
      cpf: "12345678900",
      idade: "29",
    }),
    startTime,
    validityEnd,
    "days",
    1,
    REQUIRED_EXTRA_WINDOWS_FOR_FP,
    JSON.stringify(initialManifestAnchor),
    null,
    null
  );
  const issued = parseJsonSafe(issuedJson, "issued_revocable_v2_fp_percentages");

  const credentialId = `cred-v2-fp-percentages-${Date.now()}`;
  await storeCredential(
    credentialId,
    issued.credential_json,
    requestMetadataId,
    JSON.stringify(credDefRevLedger),
    null
  );

  const bundleId = `bundle-v2-fp-percentages-${Date.now()}`;
  const storedBundleJson = await storeReceivedRevocableCredential(
    bundleId,
    JSON.stringify(issued.holder_bundle),
    credentialId
  );
  const storedBundle = parseJsonSafe(storedBundleJson, "stored_bundle");
  assert(storedBundle.ok === true, "bundle deveria ser armazenado com ok=true");

  console.log("4) Pre-montando as 3 sequencias de prova: 1, 2 e 3 janelas...");
  const oneWindowJson = await buildPresentationRevocationProofV2(
    bundleId,
    PRIMARY_WINDOW_INDEX,
    0,
    credentialId
  );
  const oneWindow = parseJsonSafe(oneWindowJson, "proof_sequence_one_window");
  assert(oneWindow.ok === true, "proof_sequence_one_window deveria retornar ok=true");

  const twoWindowJson = await buildPresentationRevocationProofV2(
    bundleId,
    PRIMARY_WINDOW_INDEX,
    ADDITIONAL_WINDOWS_ONE_EXTRA,
    credentialId
  );
  const twoWindow = parseJsonSafe(twoWindowJson, "proof_sequence_two_windows");
  assert(twoWindow.ok === true, "proof_sequence_two_windows deveria retornar ok=true");
  assert(
    twoWindow.proof_sequence.confirmation_proofs.length === ADDITIONAL_WINDOWS_ONE_EXTRA,
    "a prova de 2 janelas deveria incluir 1 janela extra"
  );

  const threeWindowJson = await buildPresentationRevocationProofV2(
    bundleId,
    PRIMARY_WINDOW_INDEX,
    ADDITIONAL_WINDOWS_TWO_EXTRAS,
    credentialId
  );
  const threeWindow = parseJsonSafe(threeWindowJson, "proof_sequence_three_windows");
  assert(threeWindow.ok === true, "proof_sequence_three_windows deveria retornar ok=true");
  assert(
    threeWindow.proof_sequence.confirmation_proofs.length === ADDITIONAL_WINDOWS_TWO_EXTRAS,
    "a prova de 3 janelas deveria incluir 2 janelas extras"
  );

  return {
    issuer,
    holder,
    verifier,
    genesisAbs,
    issuerDid,
    credentialId,
    primaryWindowStart: startTime + PRIMARY_WINDOW_INDEX * 86400,
    verifyPresentationRevocationProofV2,
    proofSequences: {
      oneWindow: oneWindow.proof_sequence,
      twoWindows: twoWindow.proof_sequence,
      threeWindows: threeWindow.proof_sequence,
    },
  };
}

async function buildFreshManifestAnchor(issuerDid) {
  const manifestEnvelope = await fetchManifestEnvelope(BFILTER_BASE_URL);
  return {
    manifestEnvelope,
    manifestAnchor: buildManifestAnchorFromEnvelope(issuerDid, manifestEnvelope),
  };
}

async function verifySequence(verifyPresentationRevocationProofV2, proofSequence) {
  const resultJson = await verifyPresentationRevocationProofV2(
    JSON.stringify(proofSequence),
    null,
    JSON.stringify(POLICY)
  );
  return parseJsonSafe(resultJson, "verify_sequence");
}

async function runTrial({
  trialIndex,
  plannedTrials,
  issuerDid,
  primaryWindowStart,
  verifyPresentationRevocationProofV2,
  proofSequences,
  skipBaseline = false,
}) {
  const trialStartedAt = Date.now();
  await resetBfilterForTests(BFILTER_BASE_URL, BFILTER_ADMIN_TOKEN, TEST_FILTER_M_BITS, TEST_FILTER_K);

  let { manifestEnvelope, manifestAnchor } = await buildFreshManifestAnchor(issuerDid);
  const activeFilter = getActiveFilter(manifestEnvelope);

  if (!skipBaseline) {
    const baselineThreeWindows = await verifySequence(
      verifyPresentationRevocationProofV2,
      withManifestOnProofSequence(proofSequences.threeWindows, manifestAnchor)
    );
    assert(baselineThreeWindows.ok === true, "baseline isolado deveria retornar ok=true");
    assert(
      baselineThreeWindows.status.decision === "valid_not_revoked",
      `baseline deveria ser valid_not_revoked, veio ${baselineThreeWindows.status.decision}`
    );
  }

  let found = false;
  let oneWindowAfterFp = null;
  let twoWindowAfterFp = null;
  let threeWindowAfterFp = null;
  let batchesUsed = 0;
  let filterAtHit = activeFilter;

  for (let batchIndex = 0; batchIndex <= MAX_FP_BATCHES; batchIndex++) {
    const oneWindowCurrent = withManifestOnProofSequence(proofSequences.oneWindow, manifestAnchor);
    const oneWindowCheck = await verifySequence(verifyPresentationRevocationProofV2, oneWindowCurrent);

    if (oneWindowCheck.status.decision === "needs_next_window") {
      found = true;
      oneWindowAfterFp = oneWindowCheck;

      const twoWindowCurrent = withManifestOnProofSequence(proofSequences.twoWindows, manifestAnchor);
      twoWindowAfterFp = await verifySequence(verifyPresentationRevocationProofV2, twoWindowCurrent);

      // If the first extra window already clears the hit, we can skip the 3-window proof.
      if (twoWindowAfterFp.status.decision !== "false_positive_confirmed") {
        const threeWindowCurrent = withManifestOnProofSequence(proofSequences.threeWindows, manifestAnchor);
        threeWindowAfterFp = await verifySequence(verifyPresentationRevocationProofV2, threeWindowCurrent);
      }

      filterAtHit = getActiveFilter(manifestEnvelope);
      batchesUsed = batchIndex;
      break;
    }

    if (batchIndex === MAX_FP_BATCHES) {
      break;
    }

    await writeDummyRevocations({
      baseUrl: BFILTER_BASE_URL,
      adminToken: BFILTER_ADMIN_TOKEN,
      issuerDid,
      targetWindowStart: primaryWindowStart,
      count: DUMMY_BATCH_SIZE,
      trialIndex,
      batchIndex: batchIndex + 1,
    });

    const refreshed = await buildFreshManifestAnchor(issuerDid);
    manifestEnvelope = refreshed.manifestEnvelope;
    manifestAnchor = refreshed.manifestAnchor;
  }

  if (!found) {
    const filterAfterBudget = getActiveFilter(manifestEnvelope);
    return {
      trial_index: trialIndex,
      planned_trials: plannedTrials,
      false_positive_found: false,
      classification: null,
      filter_id: filterAfterBudget.filter_id,
      capacity_limit: Number(filterAfterBudget.capacity_limit || 0),
      inserted_count_at_hit: null,
      batches_used: null,
      load_percent_at_hit: null,
      theoretical_fp_percent_at_hit: null,
      one_window_decision: null,
      two_window_decision: null,
      three_window_decision: null,
      two_window_trace_pattern: null,
      three_window_trace_pattern: null,
      duration_ms: Date.now() - trialStartedAt,
      recorded_at: nowIso(),
    };
  }

  const insertedCountAtHit = Number(filterAtHit.inserted_count || batchesUsed * DUMMY_BATCH_SIZE);
  const capacityLimit = Number(filterAtHit.capacity_limit || 0);
  const classification = classifyTrial(
    twoWindowAfterFp.status,
    threeWindowAfterFp ? threeWindowAfterFp.status : null
  );

  assert(oneWindowAfterFp.ok === true, "oneWindowAfterFp deveria retornar ok=true");
  assert(twoWindowAfterFp.ok === true, "twoWindowAfterFp deveria retornar ok=true");
  if (threeWindowAfterFp) {
    assert(threeWindowAfterFp.ok === true, "threeWindowAfterFp deveria retornar ok=true");
  }
  assert(
    oneWindowAfterFp.status.decision === "needs_next_window",
    `com 1 janela o falso positivo deveria exigir a próxima janela, veio ${oneWindowAfterFp.status.decision}`
  );

  return {
    trial_index: trialIndex,
    planned_trials: plannedTrials,
    false_positive_found: true,
    classification,
    filter_id: filterAtHit.filter_id,
    capacity_limit: capacityLimit,
    inserted_count_at_hit: insertedCountAtHit,
    batches_used: batchesUsed,
    load_percent_at_hit: percentOf(insertedCountAtHit, capacityLimit),
    theoretical_fp_percent_at_hit:
      bloomFpEstimate(Number(filterAtHit.m_bits || TEST_FILTER_M_BITS), Number(filterAtHit.k || TEST_FILTER_K), insertedCountAtHit) *
      100,
    one_window_decision: oneWindowAfterFp.status.decision,
    two_window_decision: twoWindowAfterFp.status.decision,
    three_window_decision: threeWindowAfterFp ? threeWindowAfterFp.status.decision : null,
    two_window_trace_pattern: tracePattern(twoWindowAfterFp.status),
    three_window_trace_pattern: threeWindowAfterFp ? tracePattern(threeWindowAfterFp.status) : null,
    duration_ms: Date.now() - trialStartedAt,
    recorded_at: nowIso(),
  };
}

function buildDisplayRows(summary) {
  return [
    {
      metrica: "Rodadas com falso positivo encontrado",
      valor: `${formatInt(summary.false_positive_trials)}/${formatInt(summary.total_trials)}`,
      percentual: formatPercent(summary.false_positive_trial_percent),
      observacao: "falso positivo na janela principal encontrado dentro do budget",
    },
    {
      metrica: "1 janela extra suficiente",
      valor: formatInt(summary.one_extra_window_sufficient),
      percentual: formatPercent(summary.one_extra_window_sufficient_percent),
      observacao: "sequencia esperada: T,F",
    },
    {
      metrica: "2 janelas extras necessarias",
      valor: formatInt(summary.two_extra_windows_required),
      percentual: formatPercent(summary.two_extra_windows_required_percent),
      observacao: "sequencia esperada: T,T,F",
    },
    {
      metrica: "Nem 2 janelas extras bastaram",
      valor: formatInt(summary.two_extra_windows_insufficient),
      percentual: formatPercent(summary.two_extra_windows_insufficient_percent),
      observacao: "sequencia esperada: T,T,T",
    },
    {
      metrica: "Sem falso positivo no budget",
      valor: formatInt(summary.no_false_positive_within_budget),
      percentual: formatPercent(summary.no_false_positive_within_budget_percent),
      observacao: "rodadas em que a janela principal nao colidiu",
    },
    {
      metrica: "Carga media no hit",
      valor: summary.avg_load_percent_at_hit == null ? "-" : formatPercent(summary.avg_load_percent_at_hit),
      percentual: "-",
      observacao: "media de ocupacao do filtro quando o FP apareceu",
    },
    {
      metrica: "FP teorica media no hit",
      valor:
        summary.avg_theoretical_fp_percent_at_hit == null
          ? "-"
          : formatPercent(summary.avg_theoretical_fp_percent_at_hit),
      percentual: "-",
      observacao: "estimativa teorica no ponto em que o FP apareceu",
    },
    {
      metrica: "Tempo medio por rodada",
      valor:
        summary.avg_trial_duration_ms == null
          ? "-"
          : `${Number(summary.avg_trial_duration_ms).toFixed(0)} ms`,
      percentual: "-",
      observacao: "inclui reset do filtro, busca do hit e verificacoes",
    },
  ];
}

(async () => {
  assert(["smoke", "full"].includes(RUN_MODE), "RUN_MODE deve ser 'smoke' ou 'full'");
  assert(Number.isInteger(TEST_FILTER_M_BITS) && TEST_FILTER_M_BITS > 0, "TEST_FILTER_M_BITS deve ser inteiro positivo");
  assert(Number.isInteger(TEST_FILTER_K) && TEST_FILTER_K > 0, "TEST_FILTER_K deve ser inteiro positivo");
  assert(Number.isInteger(TRIALS) && TRIALS > 0, "TRIALS deve ser inteiro positivo");
  assert(Number.isInteger(DUMMY_BATCH_SIZE) && DUMMY_BATCH_SIZE > 0, "DUMMY_BATCH_SIZE deve ser inteiro positivo");
  assert(Number.isInteger(MAX_FP_BATCHES) && MAX_FP_BATCHES > 0, "MAX_FP_BATCHES deve ser inteiro positivo");

  console.log("🚀 TESTE REVOGACAO 57: percentuais de refutacao por 1 ou 2 janelas extras");
  console.log("Configuracao:", {
    run_mode: RUN_MODE,
    base_url: BFILTER_BASE_URL,
    test_filter_m_bits: TEST_FILTER_M_BITS,
    test_filter_k: TEST_FILTER_K,
    trials: TRIALS,
    primary_window_index: PRIMARY_WINDOW_INDEX,
    validity_window_count: VALIDITY_WINDOW_COUNT,
    dummy_batch_size: DUMMY_BATCH_SIZE,
    max_fp_batches: MAX_FP_BATCHES,
    verify_baseline_each_trial: VERIFY_BASELINE_EACH_TRIAL,
    stop_after_first_false_positive_in_smoke: STOP_AFTER_FIRST_FALSE_POSITIVE_IN_SMOKE,
  });

  const setup = await setupExperiment();

  try {
    const trialResults = [];

    console.log("5) Rodando as rodadas experimentais...");
    for (let trialIndex = 1; trialIndex <= TRIALS; trialIndex++) {
      console.log(`   - rodada ${trialIndex}/${TRIALS}`);
      const result = await runTrial({
        trialIndex,
        plannedTrials: TRIALS,
        issuerDid: setup.issuerDid,
        primaryWindowStart: setup.primaryWindowStart,
        verifyPresentationRevocationProofV2: setup.verifyPresentationRevocationProofV2,
        proofSequences: setup.proofSequences,
        skipBaseline: trialIndex > 1 && !VERIFY_BASELINE_EACH_TRIAL,
      });
      trialResults.push(result);

      if (!result.false_positive_found) {
        console.log("     sem falso positivo dentro do budget");
        continue;
      }

      console.log("     resultado:", {
        classification: result.classification,
        load_percent_at_hit: Number(result.load_percent_at_hit.toFixed(2)),
        inserted_count_at_hit: result.inserted_count_at_hit,
        two_window_trace_pattern: result.two_window_trace_pattern,
        three_window_trace_pattern: result.three_window_trace_pattern,
        duration_ms: result.duration_ms,
      });

      if (RUN_MODE === "smoke" && STOP_AFTER_FIRST_FALSE_POSITIVE_IN_SMOKE) {
        console.log("     smoke mode: falso positivo encontrado; encerrando cedo.");
        break;
      }
    }

    const summary = makeSummary(trialResults);
    const displayRows = buildDisplayRows(summary);
    const markdownTable = makeMarkdownTable(displayRows, [
      { key: "metrica", label: "Metrica" },
      { key: "valor", label: "Valor" },
      { key: "percentual", label: "Percentual" },
      { key: "observacao", label: "Observacao" },
    ]);
    const htmlTable = makeHtmlTable(displayRows, [
      { key: "metrica", label: "Metrica" },
      { key: "valor", label: "Valor" },
      { key: "percentual", label: "Percentual" },
      { key: "observacao", label: "Observacao" },
    ]);

    mkdirp(OUT_DIR);
    const stamp = `${Date.now()}_${process.pid}`;
    const jsonPath = path.join(OUT_DIR, `revocation_57_fp_extra_window_percentages_${stamp}.json`);
    const mdPath = path.join(OUT_DIR, `revocation_57_fp_extra_window_percentages_${stamp}.md`);

    fs.writeFileSync(
      jsonPath,
      JSON.stringify(
        {
          generated_at: nowIso(),
          config: {
            base_url: BFILTER_BASE_URL,
            test_filter_m_bits: TEST_FILTER_M_BITS,
            test_filter_k: TEST_FILTER_K,
            planned_trials: TRIALS,
            executed_trials: trialResults.length,
            run_mode: RUN_MODE,
            primary_window_index: PRIMARY_WINDOW_INDEX,
            validity_window_count: VALIDITY_WINDOW_COUNT,
            dummy_batch_size: DUMMY_BATCH_SIZE,
            max_fp_batches: MAX_FP_BATCHES,
            verify_baseline_each_trial: VERIFY_BASELINE_EACH_TRIAL,
            stop_after_first_false_positive_in_smoke: STOP_AFTER_FIRST_FALSE_POSITIVE_IN_SMOKE,
            policy: POLICY,
          },
          summary,
          results: trialResults,
        },
        null,
        2
      )
    );

    fs.writeFileSync(
      mdPath,
      [
        "# Teste 57 - Percentuais de refutacao com 1 ou 2 janelas extras",
        "",
        `Gerado em: ${nowIso()}`,
        "",
        `Bloom m_bits: ${TEST_FILTER_M_BITS}`,
        "",
        `Bloom k: ${TEST_FILTER_K}`,
        "",
        `Rodadas planejadas: ${TRIALS}`,
        "",
        `Rodadas executadas: ${trialResults.length}`,
        "",
        htmlTable,
        "",
        "## Leitura rapida",
        "",
        "- `1 janela extra suficiente`: a janela principal deu hit, mas a janela seguinte veio limpa.",
        "- `2 janelas extras necessarias`: a janela principal e a primeira extra deram hit, mas a segunda extra veio limpa.",
        "- `Nem 2 janelas extras bastaram`: as 3 janelas verificadas vieram com hit no Bloom.",
        "- Os percentuais dessas tres categorias sao calculados apenas sobre as rodadas com falso positivo encontrado na janela principal.",
        "",
      ].join("\n")
    );

    console.log("\n6) Tabela final:");
    console.log(markdownTable);
    console.log("\n✅ OK: TESTE REVOGACAO 57 passou.");
    console.log("Arquivos gerados:", {
      json: jsonPath,
      markdown: mdPath,
    });
  } finally {
    try { await setup.issuer.walletClose(); } catch {}
    try { await setup.holder.walletClose(); } catch {}
    try { await setup.verifier.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGACAO 57:", e && e.stack ? e.stack : e);
  process.exit(1);
});
