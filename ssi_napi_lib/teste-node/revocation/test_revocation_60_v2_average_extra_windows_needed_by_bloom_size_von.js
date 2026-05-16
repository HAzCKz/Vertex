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
TEST_FILTER_SIZES="256,512,1024,2048,4096,8192" \
TRIALS_PER_SIZE=5 \
node teste-node/revocation/test_revocation_60_v2_average_extra_windows_needed_by_bloom_size_von.js

Para subir o bfilter em modo de testes:
cd /home/yugi/programacao/bfilter
BFILTER_ENABLE_TEST_API=1 \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
cargo run

ENV OPCIONAIS:
- TEST_FILTER_SIZES="256,512,1024,2048,4096,8192"
- TEST_FILTER_K=3
- TRIALS_PER_SIZE=5
- PRIMARY_WINDOW_INDEX=10
- VALIDITY_WINDOW_COUNT=30
- DUMMY_BATCH_SIZE=32
- MAX_FP_BATCHES=400
- OUT_DIR=teste-node/revocation/out
*/

/*
Teste experimental para medir, por tamanho de Bloom Filter,
quantas janelas extras sao necessarias em media para confirmar
que um hit inicial era falso positivo.

O teste:
- emite 1 credencial valida com 10 janelas extras disponiveis;
- reseta o Bloom para tamanhos crescentes;
- para cada tamanho, procura falsos positivos na janela principal;
- quando encontra um hit inicial, adiciona janelas extras uma a uma;
- mede em qual janela extra o status vira false_positive_confirmed;
- fecha com uma tabela compacta por tamanho de filtro.

Observacao:
- o experimento mede o comportamento em filtros pequenos e medios;
- ele nao pretende reproduzir a probabilidade do filtro padrao de producao;
- o objetivo aqui e obter intuicao experimental sobre quantas extras
  costumam bastar quando o falso positivo aparece.
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
const TEST_FILTER_SIZES = parsePositiveIntList(
  process.env.TEST_FILTER_SIZES || "256,512,1024,2048,4096,8192"
);
const TEST_FILTER_K = Number(process.env.TEST_FILTER_K || "3");
const TRIALS_PER_SIZE = Number(process.env.TRIALS_PER_SIZE || "5");
const PRIMARY_WINDOW_INDEX = Number(process.env.PRIMARY_WINDOW_INDEX || "10");
const VALIDITY_WINDOW_COUNT = Number(process.env.VALIDITY_WINDOW_COUNT || "30");
const DUMMY_BATCH_SIZE = Number(process.env.DUMMY_BATCH_SIZE || "32");
const MAX_FP_BATCHES = Number(process.env.MAX_FP_BATCHES || "400");
const OUT_DIR = process.env.OUT_DIR || path.join("teste-node", "revocation", "out");
const REQUIRED_EXTRA_WINDOWS_FOR_FP = 10;
const MAX_EXTRA_WINDOWS_TO_MEASURE = REQUIRED_EXTRA_WINDOWS_FOR_FP;

const POLICY = {
  max_consecutive_hits_for_revoke: 1 + REQUIRED_EXTRA_WINDOWS_FOR_FP,
  max_windows_to_request: REQUIRED_EXTRA_WINDOWS_FOR_FP,
  allow_post_expiry_confirmation_windows: true,
  holder_must_disprove_with_additional_windows: true,
};

function parsePositiveIntList(raw) {
  return String(raw)
    .split(",")
    .map((item) => Number(String(item).trim()))
    .filter((value) => Number.isInteger(value) && value > 0);
}

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

function median(values) {
  if (!values.length) return null;
  const sorted = [...values].map(Number).sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 1) return sorted[middle];
  return (sorted[middle - 1] + sorted[middle]) / 2;
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
      filter_id: `test-fp-avg-extras-${mBits}-${Date.now()}`,
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
  sizeIndex,
  trialIndex,
  batchIndex,
}) {
  const revocationKeys = Array.from({ length: count }, (_, idx) =>
    `dummy-fp-avg-extras-${Date.now()}-${process.pid}-${sizeIndex}-${trialIndex}-${batchIndex}-${idx}-${Math.random()}`
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
      credential_record_id: `dummy-fp-avg-extras-${sizeIndex}-${trialIndex}-${batchIndex}-${Date.now()}`,
      revocation_keys: revocationKeys,
      window_starts: windowStarts,
      reason: "measure-average-extra-windows-needed-by-bloom-size",
      requested_by: "teste-node-revocation-60",
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

function buildDistributionString(values) {
  if (!values.length) return "-";
  const counts = new Map();
  for (const value of values) {
    counts.set(value, (counts.get(value) || 0) + 1);
  }
  return Array.from(counts.entries())
    .sort((a, b) => Number(a[0]) - Number(b[0]))
    .map(([windows, count]) => `${windows}:${count}`)
    .join(" ");
}

function makeSizeSummary(mBits, capacityLimit, results) {
  const found = results.filter((item) => item.false_positive_found);
  const confirmed = found.filter((item) => item.extra_windows_needed !== null);
  const unresolved = found.filter((item) => item.extra_windows_needed === null);
  const extrasValues = confirmed.map((item) => item.extra_windows_needed);
  const loads = found.map((item) => item.load_percent_at_hit).filter((value) => value !== null);
  const theoreticalFp = found
    .map((item) => item.theoretical_fp_percent_at_hit)
    .filter((value) => value !== null);
  const durationValues = results.map((item) => item.duration_ms).filter((value) => value != null);

  return {
    m_bits: mBits,
    k: TEST_FILTER_K,
    capacity_limit: capacityLimit,
    trials: results.length,
    false_positive_trials: found.length,
    false_positive_trial_percent: percentOf(found.length, results.length),
    confirmed_false_positive_trials: confirmed.length,
    confirmed_false_positive_trial_percent: percentOf(confirmed.length, found.length),
    unresolved_after_10_trials: unresolved.length,
    unresolved_after_10_percent: percentOf(unresolved.length, found.length),
    no_false_positive_trials: results.length - found.length,
    avg_extra_windows_needed: average(extrasValues),
    median_extra_windows_needed: median(extrasValues),
    min_extra_windows_needed: extrasValues.length ? Math.min(...extrasValues) : null,
    max_extra_windows_needed: extrasValues.length ? Math.max(...extrasValues) : null,
    distribution: buildDistributionString(extrasValues),
    avg_load_percent_at_hit: average(loads),
    avg_theoretical_fp_percent_at_hit: average(theoreticalFp),
    avg_duration_ms: average(durationValues),
  };
}

function buildDisplayRows(sizeSummaries) {
  return sizeSummaries.map((summary) => ({
    m_bits: formatInt(summary.m_bits),
    fp: `${formatInt(summary.false_positive_trials)}/${formatInt(summary.trials)}`,
    fp_refutados: formatInt(summary.confirmed_false_positive_trials),
    media_extras:
      summary.avg_extra_windows_needed == null
        ? "-"
        : Number(summary.avg_extra_windows_needed).toFixed(2),
    mediana:
      summary.median_extra_windows_needed == null
        ? "-"
        : Number(summary.median_extra_windows_needed).toFixed(1),
    min_max:
      summary.min_extra_windows_needed == null
        ? "-"
        : `${formatInt(summary.min_extra_windows_needed)}-${formatInt(summary.max_extra_windows_needed)}`,
    distribuicao: summary.distribution,
    carga_hit:
      summary.avg_load_percent_at_hit == null
        ? "-"
        : formatPercent(summary.avg_load_percent_at_hit),
    nao_refutado_em_10: formatInt(summary.unresolved_after_10_trials),
  }));
}

async function setupExperiment() {
  const IndyAgent = loadIndyAgent();
  const pass = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET = process.env.RESET_WALLET === "1";
  const TRUSTEE_SEED = process.env.TRUSTEE_SEED || NETWORK_CONFIG.trusteeSeed;
  const TRUSTEE_DID = process.env.TRUSTEE_DID || NETWORK_CONFIG.trusteeDid;

  const walletDir = ensureWalletDir();
  const issuerDb =
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_v2_avg_extras_issuer.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_v2_avg_extras_holder.db");
  const verifierDb =
    process.env.WALLET_VERIFIER || path.join(walletDir, "test_wallet_revocation_v2_avg_extras_verifier.db");

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
  await resetBfilterForTests(BFILTER_BASE_URL, BFILTER_ADMIN_TOKEN, TEST_FILTER_SIZES[0], TEST_FILTER_K);
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
    `SchemaRevV2AvgExtras_${Date.now()}`,
    `1.${nowSec()}`,
    ["nome", "cpf", "idade", ...CONTROL_ATTRS]
  );

  const localJson = await creddefSaveLocal(
    issuerDid,
    schemaIdRev,
    `TAG_REV_V2_AVG_EXTRAS_${Date.now()}`,
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
    PRIMARY_WINDOW_INDEX + MAX_EXTRA_WINDOWS_TO_MEASURE < VALIDITY_WINDOW_COUNT + REQUIRED_EXTRA_WINDOWS_FOR_FP,
    "PRIMARY_WINDOW_INDEX precisa deixar espaco para as janelas extras medidas"
  );

  const offerJson = await createCredentialOffer(credDefIdRev, `offer-v2-avg-extras-${Date.now()}`);
  const requestJson = await createCredentialRequest(
    "default",
    holderDid,
    JSON.stringify(credDefRevLedger),
    offerJson
  );
  const requestMetadataId = extractNonce(offerJson);

  const issuedJson = await issueRevocableCredential(
    genesisAbs,
    `issued-v2-avg-extras-${Date.now()}`,
    holderDid,
    credDefIdRev,
    schemaIdRev,
    offerJson,
    requestJson,
    JSON.stringify({
      nome: "Alice Avg Extras",
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
  const issued = parseJsonSafe(issuedJson, "issued_revocable_v2_avg_extras");

  const credentialId = `cred-v2-avg-extras-${Date.now()}`;
  await storeCredential(
    credentialId,
    issued.credential_json,
    requestMetadataId,
    JSON.stringify(credDefRevLedger),
    null
  );

  const bundleId = `bundle-v2-avg-extras-${Date.now()}`;
  const storedBundleJson = await storeReceivedRevocableCredential(
    bundleId,
    JSON.stringify(issued.holder_bundle),
    credentialId
  );
  const storedBundle = parseJsonSafe(storedBundleJson, "stored_bundle");
  assert(storedBundle.ok === true, "bundle deveria ser armazenado com ok=true");

  console.log("4) Pre-montando as sequencias v2 de 1 ate 11 janelas...");
  const proofSequencesByAdditionalCount = {};
  for (let additionalWindowCount = 0; additionalWindowCount <= MAX_EXTRA_WINDOWS_TO_MEASURE; additionalWindowCount++) {
    const proofJson = await buildPresentationRevocationProofV2(
      bundleId,
      PRIMARY_WINDOW_INDEX,
      additionalWindowCount,
      credentialId
    );
    const proofResponse = parseJsonSafe(proofJson, `proof_sequence_${additionalWindowCount}`);
    assert(proofResponse.ok === true, `proof_sequence_${additionalWindowCount} deveria retornar ok=true`);
    proofSequencesByAdditionalCount[additionalWindowCount] = proofResponse.proof_sequence;
  }

  return {
    issuer,
    holder,
    verifier,
    issuerDid,
    primaryWindowStart: startTime + PRIMARY_WINDOW_INDEX * 86400,
    verifyPresentationRevocationProofV2,
    proofSequencesByAdditionalCount,
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

async function runTrialForSize({
  sizeIndex,
  mBits,
  trialIndex,
  issuerDid,
  primaryWindowStart,
  verifyPresentationRevocationProofV2,
  proofSequencesByAdditionalCount,
}) {
  const trialStartedAt = Date.now();
  await resetBfilterForTests(BFILTER_BASE_URL, BFILTER_ADMIN_TOKEN, mBits, TEST_FILTER_K);

  let { manifestEnvelope, manifestAnchor } = await buildFreshManifestAnchor(issuerDid);
  let activeFilter = getActiveFilter(manifestEnvelope);
  let found = false;
  let oneWindowStatus = null;
  let finalStatus = null;
  let extraWindowsNeeded = null;
  let batchesUsed = 0;

  for (let batchIndex = 0; batchIndex <= MAX_FP_BATCHES; batchIndex++) {
    const oneWindowSequence = withManifestOnProofSequence(
      proofSequencesByAdditionalCount[0],
      manifestAnchor
    );
    const oneWindowCheck = await verifySequence(
      verifyPresentationRevocationProofV2,
      oneWindowSequence
    );

    assert(oneWindowCheck.ok === true, "oneWindowCheck deveria retornar ok=true");

    if (oneWindowCheck.status.decision === "needs_next_window") {
      found = true;
      oneWindowStatus = oneWindowCheck.status;
      activeFilter = getActiveFilter(manifestEnvelope);
      batchesUsed = batchIndex;

      for (let additionalWindowCount = 1; additionalWindowCount <= MAX_EXTRA_WINDOWS_TO_MEASURE; additionalWindowCount++) {
        const currentSequence = withManifestOnProofSequence(
          proofSequencesByAdditionalCount[additionalWindowCount],
          manifestAnchor
        );
        const currentCheck = await verifySequence(
          verifyPresentationRevocationProofV2,
          currentSequence
        );
        assert(currentCheck.ok === true, `currentCheck ${additionalWindowCount} deveria retornar ok=true`);

        if (currentCheck.status.decision === "false_positive_confirmed") {
          extraWindowsNeeded = additionalWindowCount;
          finalStatus = currentCheck.status;
          break;
        }

        finalStatus = currentCheck.status;
      }

      break;
    }

    assert(
      oneWindowCheck.status.decision === "valid_not_revoked",
      `com 1 janela o status deveria ser valid_not_revoked ou needs_next_window, veio ${oneWindowCheck.status.decision}`
    );

    if (batchIndex === MAX_FP_BATCHES) {
      break;
    }

    await writeDummyRevocations({
      baseUrl: BFILTER_BASE_URL,
      adminToken: BFILTER_ADMIN_TOKEN,
      issuerDid,
      targetWindowStart: primaryWindowStart,
      count: DUMMY_BATCH_SIZE,
      sizeIndex,
      trialIndex,
      batchIndex: batchIndex + 1,
    });

    const refreshed = await buildFreshManifestAnchor(issuerDid);
    manifestEnvelope = refreshed.manifestEnvelope;
    manifestAnchor = refreshed.manifestAnchor;
    activeFilter = getActiveFilter(manifestEnvelope);
  }

  if (!found) {
    return {
      m_bits: mBits,
      trial_index: trialIndex,
      false_positive_found: false,
      extra_windows_needed: null,
      inserted_count_at_hit: null,
      load_percent_at_hit: null,
      theoretical_fp_percent_at_hit: null,
      filter_id: activeFilter.filter_id,
      one_window_trace_pattern: null,
      final_trace_pattern: null,
      final_decision: null,
      duration_ms: Date.now() - trialStartedAt,
      recorded_at: nowIso(),
    };
  }

  const insertedCountAtHit = Number(activeFilter.inserted_count || batchesUsed * DUMMY_BATCH_SIZE);
  const capacityLimit = Number(activeFilter.capacity_limit || 0);

  return {
    m_bits: mBits,
    trial_index: trialIndex,
    false_positive_found: true,
    extra_windows_needed: extraWindowsNeeded,
    inserted_count_at_hit: insertedCountAtHit,
    load_percent_at_hit: percentOf(insertedCountAtHit, capacityLimit),
    theoretical_fp_percent_at_hit:
      bloomFpEstimate(Number(activeFilter.m_bits || mBits), Number(activeFilter.k || TEST_FILTER_K), insertedCountAtHit) *
      100,
    filter_id: activeFilter.filter_id,
    one_window_trace_pattern: tracePattern(oneWindowStatus),
    final_trace_pattern: finalStatus ? tracePattern(finalStatus) : null,
    final_decision: finalStatus ? finalStatus.decision : null,
    duration_ms: Date.now() - trialStartedAt,
    recorded_at: nowIso(),
  };
}

(async () => {
  assert(TEST_FILTER_SIZES.length > 0, "TEST_FILTER_SIZES deve conter ao menos 1 valor");
  assert(Number.isInteger(TEST_FILTER_K) && TEST_FILTER_K > 0, "TEST_FILTER_K deve ser inteiro positivo");
  assert(Number.isInteger(TRIALS_PER_SIZE) && TRIALS_PER_SIZE > 0, "TRIALS_PER_SIZE deve ser inteiro positivo");
  assert(Number.isInteger(DUMMY_BATCH_SIZE) && DUMMY_BATCH_SIZE > 0, "DUMMY_BATCH_SIZE deve ser inteiro positivo");
  assert(Number.isInteger(MAX_FP_BATCHES) && MAX_FP_BATCHES > 0, "MAX_FP_BATCHES deve ser inteiro positivo");

  console.log("🚀 TESTE REVOGACAO 60: media de janelas extras necessarias por tamanho de Bloom");
  console.log("Configuracao:", {
    base_url: BFILTER_BASE_URL,
    test_filter_sizes: TEST_FILTER_SIZES,
    test_filter_k: TEST_FILTER_K,
    trials_per_size: TRIALS_PER_SIZE,
    primary_window_index: PRIMARY_WINDOW_INDEX,
    validity_window_count: VALIDITY_WINDOW_COUNT,
    dummy_batch_size: DUMMY_BATCH_SIZE,
    max_fp_batches: MAX_FP_BATCHES,
    required_extra_windows_for_fp: REQUIRED_EXTRA_WINDOWS_FOR_FP,
  });

  const setup = await setupExperiment();

  try {
    const allResults = [];
    const sizeSummaries = [];

    console.log("5) Rodando o experimento por tamanhos crescentes de Bloom...");
    for (let sizeIndex = 0; sizeIndex < TEST_FILTER_SIZES.length; sizeIndex++) {
      const mBits = TEST_FILTER_SIZES[sizeIndex];
      console.log(`   - m_bits=${mBits}`);

      const sizeResults = [];
      for (let trialIndex = 1; trialIndex <= TRIALS_PER_SIZE; trialIndex++) {
        const result = await runTrialForSize({
          sizeIndex,
          mBits,
          trialIndex,
          issuerDid: setup.issuerDid,
          primaryWindowStart: setup.primaryWindowStart,
          verifyPresentationRevocationProofV2: setup.verifyPresentationRevocationProofV2,
          proofSequencesByAdditionalCount: setup.proofSequencesByAdditionalCount,
        });
        sizeResults.push(result);
        allResults.push(result);
      }

      const manifestEnvelope = await fetchManifestEnvelope(BFILTER_BASE_URL);
      const activeFilter = getActiveFilter(manifestEnvelope);
      sizeSummaries.push(
        makeSizeSummary(mBits, Number(activeFilter.capacity_limit || 0), sizeResults)
      );
    }

    const displayRows = buildDisplayRows(sizeSummaries);
    const markdownTable = makeMarkdownTable(displayRows, [
      { key: "m_bits", label: "m_bits" },
      { key: "fp", label: "FP" },
      { key: "fp_refutados", label: "FP refut." },
      { key: "media_extras", label: "Media extras" },
      { key: "mediana", label: "Mediana" },
      { key: "min_max", label: "Min-Max" },
      { key: "distribuicao", label: "Distribuicao" },
      { key: "carga_hit", label: "Carga hit" },
      { key: "nao_refutado_em_10", label: "Nao ref. em 10" },
    ]);
    const htmlTable = makeHtmlTable(displayRows, [
      { key: "m_bits", label: "m_bits" },
      { key: "fp", label: "FP" },
      { key: "fp_refutados", label: "FP refut." },
      { key: "media_extras", label: "Media extras" },
      { key: "mediana", label: "Mediana" },
      { key: "min_max", label: "Min-Max" },
      { key: "distribuicao", label: "Distribuicao" },
      { key: "carga_hit", label: "Carga hit" },
      { key: "nao_refutado_em_10", label: "Nao ref. em 10" },
    ]);

    mkdirp(OUT_DIR);
    const stamp = `${Date.now()}_${process.pid}`;
    const jsonPath = path.join(OUT_DIR, `revocation_60_avg_extra_windows_by_bloom_size_${stamp}.json`);
    const mdPath = path.join(OUT_DIR, `revocation_60_avg_extra_windows_by_bloom_size_${stamp}.md`);

    fs.writeFileSync(
      jsonPath,
      JSON.stringify(
        {
          generated_at: nowIso(),
          config: {
            base_url: BFILTER_BASE_URL,
            test_filter_sizes: TEST_FILTER_SIZES,
            test_filter_k: TEST_FILTER_K,
            trials_per_size: TRIALS_PER_SIZE,
            primary_window_index: PRIMARY_WINDOW_INDEX,
            validity_window_count: VALIDITY_WINDOW_COUNT,
            dummy_batch_size: DUMMY_BATCH_SIZE,
            max_fp_batches: MAX_FP_BATCHES,
            required_extra_windows_for_fp: REQUIRED_EXTRA_WINDOWS_FOR_FP,
            policy: POLICY,
          },
          summaries: sizeSummaries,
          results: allResults,
        },
        null,
        2
      )
    );

    fs.writeFileSync(
      mdPath,
      [
        "# Teste 60 - Media de janelas extras por tamanho de Bloom",
        "",
        `Gerado em: ${nowIso()}`,
        "",
        `Tamanhos testados: ${TEST_FILTER_SIZES.join(", ")}`,
        "",
        `k do Bloom: ${TEST_FILTER_K}`,
        "",
        `Rodadas por tamanho: ${TRIALS_PER_SIZE}`,
        "",
        htmlTable,
        "",
        "## Leitura rapida",
        "",
        "- `FP`: quantas rodadas daquele tamanho chegaram a gerar falso positivo na janela principal.",
        "- `FP refut.`: quantas dessas rodadas chegaram a `false_positive_confirmed` dentro das 10 extras disponiveis.",
        "- `Media extras`: numero medio de janelas extras necessarias para chegar a false_positive_confirmed.",
        "- `Distribuicao`: contagem compacta no formato `extras:rodadas`. Ex.: `1:5` significa que 1 janela extra bastou em 5 rodadas.",
        "- `Nao ref. em 10`: rodadas com falso positivo encontrado, mas que nao foram confirmadas como false_positive_confirmed nas 10 extras medidas.",
        "- Se `Media extras = 1.00` e `Distribuicao = 1:5`, isso nao quer dizer 5 janelas extras num unico caso. Quer dizer que houve 5 rodadas, e em todas 1 janela extra bastou.",
        "",
      ].join("\n")
    );

    console.log("\n6) Tabela final:");
    console.log(markdownTable);
    console.log("\n✅ OK: TESTE REVOGACAO 60 passou.");
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
  console.error("❌ FALHA TESTE REVOGACAO 60:", e && e.stack ? e.stack : e);
  process.exit(1);
});
