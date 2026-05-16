/*
TESTE MANUAL: VARREDURA DE FALSO POSITIVO POR PERCENTUAL

PARA RODAR:
1. Suba o servico com BFILTER_ENABLE_TEST_API=1.
   Se quiser medir acima do limiar atual de rotacao do servico,
   suba tambem com BFILTER_ROTATE_AT_PERCENT maior ou igual ao maior percentual do teste.

BFILTER_ENABLE_TEST_API=1 \
BFILTER_ROTATE_AT_PERCENT=100 \
cargo run

2. Rode este script:

cd /home/yugi/programacao/bfilter
BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
START_PERCENT="50" \
END_PERCENT="95" \
PERCENT_STEP="5" \
INSERT_BATCH_SIZE="5000" \
CHECK_BATCH_SIZE="2000" \
ABSENT_KEYS_TO_TEST="1000000" \
SANITY_PRESENT_CHECKS="128" \
node tests/manual_false_positive_rotation_sweep.js

O que este script faz:
- reseta o filtro antes de cada percentual
- preenche o filtro ate o percentual desejado com chaves identificaveis
- testa chaves ausentes aleatorias, que sabemos nao terem sido inseridas
- para no primeiro falso positivo ou ao atingir o limite configurado
- recomeça do zero com o proximo percentual

Fluxo padrao:
- comeca em 50%
- aumenta de 5 em 5
- termina em 95%

ATENCAO:
- este script APAGA os filtros atuais via POST /test/reset
- ele exige BFILTER_ENABLE_TEST_API=1
*/

const { randomBytes } = require("node:crypto");

const BFILTER_BASE_URL = (process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080").replace(/\/+$/, "");
const BFILTER_ADMIN_TOKEN = process.env.BFILTER_ADMIN_TOKEN || "dev-admin-token";
const START_PERCENT = parsePercentInt("START_PERCENT", process.env.START_PERCENT, 50);
const END_PERCENT = parsePercentInt("END_PERCENT", process.env.END_PERCENT, 95);
const PERCENT_STEP = parsePositiveInt("PERCENT_STEP", process.env.PERCENT_STEP, 5);
const INSERT_BATCH_SIZE = parsePositiveInt("INSERT_BATCH_SIZE", process.env.INSERT_BATCH_SIZE, 5000);
const CHECK_BATCH_SIZE = parsePositiveInt("CHECK_BATCH_SIZE", process.env.CHECK_BATCH_SIZE, 2000);
const ABSENT_KEYS_TO_TEST = parsePositiveInt("ABSENT_KEYS_TO_TEST", process.env.ABSENT_KEYS_TO_TEST, 1000000);
const SANITY_PRESENT_CHECKS = parsePositiveInt(
  "SANITY_PRESENT_CHECKS",
  process.env.SANITY_PRESENT_CHECKS,
  128
);
const REQUESTED_BY = "manual-false-positive-rotation-sweep";

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function parsePositiveInt(name, rawValue, fallback) {
  if (rawValue == null || rawValue === "") return fallback;
  const value = Number(rawValue);
  assert(Number.isInteger(value) && value > 0, `${name} deve ser inteiro positivo, veio: ${rawValue}`);
  return value;
}

function parsePercentInt(name, rawValue, fallback) {
  const value = parsePositiveInt(name, rawValue, fallback);
  assert(value >= 1 && value <= 100, `${name} deve ficar entre 1 e 100, veio: ${value}`);
  return value;
}

function buildPercentList() {
  assert(START_PERCENT <= END_PERCENT, `START_PERCENT deve ser <= END_PERCENT`);
  const values = [];
  for (let percent = START_PERCENT; percent <= END_PERCENT; percent += PERCENT_STEP) {
    values.push(percent);
  }
  assert(values.length > 0, "A lista de percentuais nao pode ficar vazia");
  return values;
}

function rotationThreshold(capacityLimit, percent) {
  return Math.floor((capacityLimit * percent + 99) / 100);
}

function falsePositiveProbability(mBits, k, n) {
  if (n === 0 || k === 0) return 0;
  const oneMinusOneOverM = 1 - 1 / mBits;
  const inner = 1 - Math.pow(oneMinusOneOverM, k * n);
  return Math.pow(inner, k);
}

function expectedProbesUntilFirstFalsePositive(probability) {
  if (probability <= 0) return Number.POSITIVE_INFINITY;
  return 1 / probability;
}

function formatNumber(value, fractionDigits = 2) {
  if (value == null) return null;
  if (!Number.isFinite(value)) return "Infinity";
  return value.toLocaleString("en-US", {
    maximumFractionDigits: fractionDigits,
    minimumFractionDigits: 0,
  });
}

function makeKeys(prefix, startIndex, count) {
  return Array.from({ length: count }, (_, idx) => `${prefix}-${String(startIndex + idx).padStart(12, "0")}`);
}

function makeRandomAbsentKeys(runId, percent, startIndex, count) {
  return Array.from({ length: count }, (_, idx) => {
    const randomHex = randomBytes(16).toString("hex");
    const absoluteIndex = String(startIndex + idx).padStart(12, "0");
    return `fp-sweep-absent-${runId}-p${percent}-${absoluteIndex}-${randomHex}`;
  });
}

function getActiveFilter(manifest) {
  const activeId = manifest.active_filter_id;
  const active = (manifest.filters || []).find((item) => item.filter_id === activeId);
  assert(active, `Filtro ativo nao encontrado no manifesto: ${activeId}`);
  return active;
}

function getFilterById(manifest, filterId) {
  const filter = (manifest.filters || []).find((item) => item.filter_id === filterId);
  assert(filter, `Filtro nao encontrado no manifesto: ${filterId}`);
  return filter;
}

async function readJsonResponse(resp, context) {
  const text = await resp.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch (err) {
    throw new Error(`${context}: resposta nao eh JSON valido: ${text}`);
  }
  return body;
}

async function getManifest() {
  const resp = await fetch(`${BFILTER_BASE_URL}/manifest`);
  const body = await readJsonResponse(resp, "GET /manifest");
  assert(resp.ok, `Falha GET /manifest: ${resp.status} ${JSON.stringify(body)}`);
  assert(body && body.ok === true, "manifesto deveria retornar ok=true");
  return body.manifest;
}

async function resetFiltersForTest() {
  const resp = await fetch(`${BFILTER_BASE_URL}/test/reset`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${BFILTER_ADMIN_TOKEN}`,
    },
    body: JSON.stringify({}),
  });
  const body = await readJsonResponse(resp, "POST /test/reset");
  if (resp.status === 404) {
    throw new Error(
      "POST /test/reset retornou 404. Suba o servico com BFILTER_ENABLE_TEST_API=1 para usar este teste."
    );
  }
  assert(resp.ok, `Falha POST /test/reset: ${resp.status} ${JSON.stringify(body)}`);
  assert(body && body.ok === true, "reset deveria retornar ok=true");
  assert(body.manifest, "reset deveria retornar manifest");
  return body.manifest;
}

async function writeRevocations(keys, reason) {
  const resp = await fetch(`${BFILTER_BASE_URL}/admin/revocations/v2`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${BFILTER_ADMIN_TOKEN}`,
    },
    body: JSON.stringify({
      revocation_keys: keys,
      requested_by: REQUESTED_BY,
      reason,
    }),
  });
  const body = await readJsonResponse(resp, "POST /admin/revocations/v2");
  assert(resp.ok, `Falha POST /admin/revocations/v2: ${resp.status} ${JSON.stringify(body)}`);
  assert(body && body.ok === true, "resposta de revogacao deveria retornar ok=true");
  return body;
}

async function checkKeys(filterId, keys) {
  const resp = await fetch(`${BFILTER_BASE_URL}/check`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      filter_id: filterId,
      revocation_keys: keys,
      encoding: "utf8",
    }),
  });
  const body = await readJsonResponse(resp, "POST /check");
  assert(resp.ok, `Falha POST /check: ${resp.status} ${JSON.stringify(body)}`);
  assert(body && body.ok === true, "check deveria retornar ok=true");
  assert(Array.isArray(body.results), "check deveria retornar results");
  assert(body.results.length === keys.length, "check deveria retornar um resultado por chave");
  return body;
}

async function fillFilterToPercent(filterId, percent, targetInsertCount, runId, sampleInsertedKeys) {
  let written = 0;
  let batchNo = 0;

  while (written < targetInsertCount) {
    batchNo += 1;
    const batchSize = Math.min(INSERT_BATCH_SIZE, targetInsertCount - written);
    const keys = makeKeys(`fp-sweep-insert-${runId}-p${percent}`, written, batchSize);

    while (sampleInsertedKeys.length < SANITY_PRESENT_CHECKS && sampleInsertedKeys.length < targetInsertCount) {
      const sampleIndex = sampleInsertedKeys.length;
      if (sampleIndex >= written && sampleIndex < written + keys.length) {
        sampleInsertedKeys.push(keys[sampleIndex - written]);
      } else {
        break;
      }
    }

    const body = await writeRevocations(keys, `fill-until-${percent}-percent-batch-${batchNo}`);
    written += batchSize;

    if (batchNo === 1 || written === targetInsertCount || batchNo % 10 === 0) {
      console.log(`Insercao ${percent}% lote ${batchNo}:`, {
        filter_id: body.filter_id,
        batch_size: batchSize,
        written_total: written,
        target_total: targetInsertCount,
      });
    }
  }

  return filterId;
}

async function verifyInsertedKeys(filterId, insertedKeys) {
  if (insertedKeys.length === 0) return;
  const body = await checkKeys(filterId, insertedKeys);
  const missing = body.results.filter((item) => item.maybe_present !== true);
  assert(
    missing.length === 0,
    `Foram encontrados ${missing.length} falsos negativos na amostra de chaves inseridas`
  );
}

async function findFirstFalsePositive(filterId, percent, runId) {
  let checked = 0;
  let batchNo = 0;

  while (checked < ABSENT_KEYS_TO_TEST) {
    batchNo += 1;
    const batchSize = Math.min(CHECK_BATCH_SIZE, ABSENT_KEYS_TO_TEST - checked);
    const keys = makeRandomAbsentKeys(runId, percent, checked, batchSize);
    const body = await checkKeys(filterId, keys);
    const hitIndex = body.results.findIndex((item) => item.maybe_present === true);

    if (hitIndex >= 0) {
      const probesUntilFirstFp = checked + hitIndex + 1;
      console.log(`Consulta ${percent}% lote ${batchNo}:`, {
        checked_total: checked + batchSize,
        first_false_positive_after: probesUntilFirstFp,
      });
      return {
        first_false_positive_after: probesUntilFirstFp,
        absent_keys_tested: probesUntilFirstFp,
        false_positive_found: true,
      };
    }

    checked += batchSize;

    if (batchNo === 1 || checked === ABSENT_KEYS_TO_TEST || batchNo % 20 === 0) {
      console.log(`Consulta ${percent}% lote ${batchNo}:`, {
        checked_total: checked,
        first_false_positive_after: null,
      });
    }
  }

  return {
    first_false_positive_after: null,
    absent_keys_tested: checked,
    false_positive_found: false,
  };
}

async function runScenario(percent, scenarioIndex) {
  const runId = `${Date.now()}-${process.pid}-${scenarioIndex}`;
  const manifestAfterReset = await resetFiltersForTest();
  const activeBefore = getActiveFilter(manifestAfterReset);
  const targetInsertCount = rotationThreshold(activeBefore.capacity_limit, percent);
  const sampleInsertedKeys = [];

  console.log("\n------------------------------------------------------------");
  console.log(`CENARIO ${percent}%`);
  console.log("Filtro limpo apos reset:", {
    filter_id: activeBefore.filter_id,
    status: activeBefore.status,
    inserted_count: activeBefore.inserted_count,
    capacity_limit: activeBefore.capacity_limit,
    m_bits: activeBefore.m_bits,
    k: activeBefore.k,
    target_insert_count: targetInsertCount,
  });

  await fillFilterToPercent(activeBefore.filter_id, percent, targetInsertCount, runId, sampleInsertedKeys);

  const manifestAfterFill = await getManifest();
  const testedFilter = getFilterById(manifestAfterFill, activeBefore.filter_id);
  const actualInsertedCount = Number(testedFilter.inserted_count);

  assert(
    actualInsertedCount >= targetInsertCount,
    `Filtro testado deveria ter pelo menos inserted_count=${targetInsertCount}, veio ${actualInsertedCount}`
  );

  await verifyInsertedKeys(testedFilter.filter_id, sampleInsertedKeys);

  const firstFalsePositive = await findFirstFalsePositive(testedFilter.filter_id, percent, runId);
  const theoreticalProbability = falsePositiveProbability(testedFilter.m_bits, testedFilter.k, actualInsertedCount);
  const expectedProbes = expectedProbesUntilFirstFalsePositive(theoreticalProbability);

  return {
    percent,
    filter_id: testedFilter.filter_id,
    inserted_count: actualInsertedCount,
    capacity_limit: Number(testedFilter.capacity_limit),
    load_percent: ((actualInsertedCount / Number(testedFilter.capacity_limit)) * 100).toFixed(2),
    status_after_fill: testedFilter.status,
    m_bits: Number(testedFilter.m_bits),
    k: Number(testedFilter.k),
    absent_keys_tested: firstFalsePositive.absent_keys_tested,
    false_positive_found: firstFalsePositive.false_positive_found,
    first_false_positive_after: firstFalsePositive.first_false_positive_after,
    theoretical_fp_probability: theoreticalProbability,
    theoretical_expected_probes_until_fp: expectedProbes,
  };
}

(async () => {
  const percentList = buildPercentList();
  const manifestBefore = await getManifest();

  console.log("============================================================");
  console.log("MANUAL BLOOM FILTER FALSE POSITIVE ROTATION SWEEP");
  console.log("Config:", {
    BFILTER_BASE_URL,
    START_PERCENT,
    END_PERCENT,
    PERCENT_STEP,
    percent_list: percentList,
    INSERT_BATCH_SIZE,
    CHECK_BATCH_SIZE,
    ABSENT_KEYS_TO_TEST,
    SANITY_PRESENT_CHECKS,
    adminToken: "***",
  });
  console.log("Servico antes do primeiro reset:", {
    false_positive_power: Number(manifestBefore.false_positive_power || 32),
    active_filter_id: manifestBefore.active_filter_id,
  });
  console.log("============================================================");

  const summaries = [];
  for (let index = 0; index < percentList.length; index += 1) {
    const result = await runScenario(percentList[index], index + 1);
    summaries.push(result);
  }

  console.log("\n============================================================");
  console.log("RESUMO FINAL");
  for (const summary of summaries) {
    console.log(`${summary.percent}%:`, {
      filter_id: summary.filter_id,
      status_after_fill: summary.status_after_fill,
      inserted_count: summary.inserted_count,
      capacity_limit: summary.capacity_limit,
      load_percent: summary.load_percent,
      absent_keys_tested: summary.absent_keys_tested,
      false_positive_found: summary.false_positive_found,
      first_false_positive_after: summary.first_false_positive_after,
      theoretical_fp_probability: summary.theoretical_fp_probability,
      theoretical_expected_probes_until_fp: formatNumber(summary.theoretical_expected_probes_until_fp, 2),
      m_bits: summary.m_bits,
      k: summary.k,
    });
  }
  console.log("============================================================");
})().catch((err) => {
  console.error(
    "FALHA NO SCRIPT MANUAL DE VARREDURA DE FALSO POSITIVO POR ROTACAO:",
    err && err.stack ? err.stack : err
  );
  process.exit(1);
});
