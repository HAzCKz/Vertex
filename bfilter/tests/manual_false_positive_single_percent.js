/*
TESTE MANUAL: FALSO POSITIVO EM UM UNICO PERCENTUAL

PARA RODAR:
1. Suba o servico com BFILTER_ENABLE_TEST_API=1.
   Se quiser medir acima do limiar atual de rotacao do servico,
   suba tambem com BFILTER_ROTATE_AT_PERCENT maior ou igual ao percentual do teste.

cd /home/yugi/programacao/bfilter
BFILTER_ENABLE_TEST_API=1 \
BFILTER_ROTATE_AT_PERCENT=100 \
cargo run

2. Rode este script:

cd /home/yugi/programacao/bfilter
BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
FILL_PERCENT="95" \
INSERT_BATCH_SIZE="5000" \
CHECK_BATCH_SIZE="5000" \
CHECK_WORKERS="1" \
ABSENT_KEYS_TO_TEST="10000000" \
SANITY_PRESENT_CHECKS="128" \
node tests/manual_false_positive_single_percent.js

O que este script faz:
- reseta o filtro
- preenche o filtro ate um percentual configurado com chaves identificaveis
- testa um total configurado de chaves ausentes aleatorias derivadas de hash
- pode paralelizar a fase de consulta com varios workers
- mede o primeiro falso positivo encontrado, se houver
- conta o total de falsos positivos observados na amostra inteira

ATENCAO:
- este script APAGA os filtros atuais via POST /test/reset
- ele exige BFILTER_ENABLE_TEST_API=1
*/

const { createHash, randomBytes } = require("node:crypto");
const os = require("node:os");
const { Worker, isMainThread, parentPort, workerData } = require("node:worker_threads");

const BFILTER_BASE_URL = (process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080").replace(/\/+$/, "");
const BFILTER_ADMIN_TOKEN = process.env.BFILTER_ADMIN_TOKEN || "dev-admin-token";
const FILL_PERCENT = parsePercentInt("FILL_PERCENT", process.env.FILL_PERCENT, 90);
const INSERT_BATCH_SIZE = parsePositiveInt("INSERT_BATCH_SIZE", process.env.INSERT_BATCH_SIZE, 5000);
const CHECK_BATCH_SIZE = parsePositiveInt("CHECK_BATCH_SIZE", process.env.CHECK_BATCH_SIZE, 5000);
const CHECK_WORKERS = parsePositiveInt("CHECK_WORKERS", process.env.CHECK_WORKERS, 1);
const ABSENT_KEYS_TO_TEST = parsePositiveInt("ABSENT_KEYS_TO_TEST", process.env.ABSENT_KEYS_TO_TEST, 100000000);
const SANITY_PRESENT_CHECKS = parsePositiveInt(
  "SANITY_PRESENT_CHECKS",
  process.env.SANITY_PRESENT_CHECKS,
  128
);
const REQUESTED_BY = "manual-false-positive-single-percent";

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

function getAvailableParallelism() {
  if (typeof os.availableParallelism === "function") {
    return os.availableParallelism();
  }
  return os.cpus().length;
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

function expectedFalsePositives(sampleSize, probability) {
  return sampleSize * probability;
}

function expectedProbesUntilFirstFalsePositive(probability) {
  if (probability <= 0) return Number.POSITIVE_INFINITY;
  return 1 / probability;
}

function testsNeededForConfidence(probability, confidence) {
  if (probability <= 0) return Number.POSITIVE_INFINITY;
  if (confidence <= 0) return 0;
  if (confidence >= 1) return Number.POSITIVE_INFINITY;
  return Math.log(1 - confidence) / Math.log(1 - probability);
}

function formatNumber(value, fractionDigits = 2) {
  if (value == null) return null;
  if (!Number.isFinite(value)) return "Infinity";
  return value.toLocaleString("en-US", {
    maximumFractionDigits: fractionDigits,
    minimumFractionDigits: 0,
  });
}

function makeInsertedKeys(runId, startIndex, count) {
  return Array.from({ length: count }, (_, idx) =>
    `fp-single-insert-${runId}-${String(startIndex + idx).padStart(12, "0")}`
  );
}

function makeRandomAbsentKeys(runId, startIndex, count) {
  return Array.from({ length: count }, (_, idx) => {
    const absoluteIndex = String(startIndex + idx).padStart(12, "0");
    const seed = Buffer.concat([
      Buffer.from(`fp-single-absent-${runId}-${absoluteIndex}-`, "utf8"),
      randomBytes(32),
    ]);
    const digestHex = createHash("sha256").update(seed).digest("hex");
    return `fp-single-absent-hash-${runId}-${absoluteIndex}-${digestHex}`;
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

function buildWorkerRanges(total, workers) {
  const ranges = [];
  const baseSize = Math.floor(total / workers);
  const remainder = total % workers;
  let cursor = 0;

  for (let workerIndex = 0; workerIndex < workers; workerIndex += 1) {
    const size = baseSize + (workerIndex < remainder ? 1 : 0);
    if (size <= 0) continue;
    ranges.push({
      workerIndex: workerIndex + 1,
      startOffset: cursor,
      totalToCheck: size,
    });
    cursor += size;
  }

  return ranges;
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
  return checkKeysViaBaseUrl(BFILTER_BASE_URL, filterId, keys);
}

async function checkKeysViaBaseUrl(baseUrl, filterId, keys) {
  const resp = await fetch(`${baseUrl}/check`, {
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

async function fillFilterToPercent(filterId, targetInsertCount, runId, sampleInsertedKeys) {
  let written = 0;
  let batchNo = 0;

  while (written < targetInsertCount) {
    batchNo += 1;
    const batchSize = Math.min(INSERT_BATCH_SIZE, targetInsertCount - written);
    const keys = makeInsertedKeys(runId, written, batchSize);

    while (sampleInsertedKeys.length < SANITY_PRESENT_CHECKS && sampleInsertedKeys.length < targetInsertCount) {
      const sampleIndex = sampleInsertedKeys.length;
      if (sampleIndex >= written && sampleIndex < written + keys.length) {
        sampleInsertedKeys.push(keys[sampleIndex - written]);
      } else {
        break;
      }
    }

    const body = await writeRevocations(keys, `fill-until-${FILL_PERCENT}-percent-batch-${batchNo}`);
    written += batchSize;

    if (batchNo === 1 || written === targetInsertCount || batchNo % 10 === 0) {
      console.log(`Insercao lote ${batchNo}:`, {
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

function runMeasureWorker(input) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(__filename, {
      workerData: input,
    });
    let settled = false;

    worker.on("message", (message) => {
      if (message.type === "progress") {
        console.log(`Consulta worker ${message.workerIndex} lote ${message.batchNo}:`, {
          checked_total_worker: message.checked,
          false_positives_total_worker: message.falsePositives,
          first_false_positive_after_worker: message.firstFalsePositiveAfter,
        });
        return;
      }

      if (message.type === "result" && !settled) {
        settled = true;
        resolve(message.payload);
      }
    });

    worker.on("error", (err) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    });

    worker.on("exit", (code) => {
      if (!settled && code !== 0) {
        settled = true;
        reject(new Error(`Worker de consulta terminou com codigo ${code}`));
      }
    });
  });
}

async function measureFalsePositivesParallel(filterId, runId) {
  const workerCount = Math.min(CHECK_WORKERS, ABSENT_KEYS_TO_TEST);
  const ranges = buildWorkerRanges(ABSENT_KEYS_TO_TEST, workerCount);
  const workerResults = await Promise.all(
    ranges.map((range) =>
      runMeasureWorker({
        mode: "measure_false_positives_worker",
        workerIndex: range.workerIndex,
        startOffset: range.startOffset,
        totalToCheck: range.totalToCheck,
        checkBatchSize: CHECK_BATCH_SIZE,
        baseUrl: BFILTER_BASE_URL,
        filterId,
        runId,
      })
    )
  );

  let checked = 0;
  let falsePositives = 0;
  let firstFalsePositiveAfter = null;

  for (const result of workerResults) {
    checked += result.checked;
    falsePositives += result.falsePositives;
    if (
      result.firstFalsePositiveAfter != null &&
      (firstFalsePositiveAfter == null || result.firstFalsePositiveAfter < firstFalsePositiveAfter)
    ) {
      firstFalsePositiveAfter = result.firstFalsePositiveAfter;
    }
  }

  return {
    checked,
    falsePositives,
    firstFalsePositiveAfter,
    workerCount,
  };
}

async function workerMeasureFalsePositives() {
  const {
    workerIndex,
    startOffset,
    totalToCheck,
    checkBatchSize,
    baseUrl,
    filterId,
    runId,
  } = workerData;

  let checked = 0;
  let falsePositives = 0;
  let firstFalsePositiveAfter = null;
  let batchNo = 0;

  while (checked < totalToCheck) {
    batchNo += 1;
    const batchSize = Math.min(checkBatchSize, totalToCheck - checked);
    const globalOffset = startOffset + checked;
    const keys = makeRandomAbsentKeys(runId, globalOffset, batchSize);
    const body = await checkKeysViaBaseUrl(baseUrl, filterId, keys);

    for (let idx = 0; idx < body.results.length; idx += 1) {
      if (body.results[idx].maybe_present === true) {
        falsePositives += 1;
        if (firstFalsePositiveAfter == null) {
          firstFalsePositiveAfter = globalOffset + idx + 1;
        }
      }
    }

    checked += batchSize;

    if (batchNo === 1 || checked === totalToCheck || batchNo % 20 === 0) {
      parentPort.postMessage({
        type: "progress",
        workerIndex,
        batchNo,
        checked,
        falsePositives,
        firstFalsePositiveAfter,
      });
    }
  }

  parentPort.postMessage({
    type: "result",
    payload: {
      workerIndex,
      checked,
      falsePositives,
      firstFalsePositiveAfter,
    },
  });
}

async function main() {
  assert(CHECK_WORKERS >= 1, `CHECK_WORKERS deve ser >= 1, veio: ${CHECK_WORKERS}`);

  const runId = `${Date.now()}-${process.pid}`;
  const manifestBefore = await getManifest();

  console.log("============================================================");
  console.log("MANUAL BLOOM FILTER FALSE POSITIVE SINGLE PERCENT");
  console.log("Config:", {
    BFILTER_BASE_URL,
    FILL_PERCENT,
    INSERT_BATCH_SIZE,
    CHECK_BATCH_SIZE,
    CHECK_WORKERS,
    ABSENT_KEYS_TO_TEST,
    SANITY_PRESENT_CHECKS,
    available_parallelism: getAvailableParallelism(),
    adminToken: "***",
  });
  console.log("Servico antes do reset:", {
    false_positive_power: Number(manifestBefore.false_positive_power || 32),
    active_filter_id: manifestBefore.active_filter_id,
  });
  console.log("============================================================");

  const manifestAfterReset = await resetFiltersForTest();
  const activeBefore = getActiveFilter(manifestAfterReset);
  const targetInsertCount = rotationThreshold(activeBefore.capacity_limit, FILL_PERCENT);
  const sampleInsertedKeys = [];

  console.log("Filtro limpo apos reset:", {
    filter_id: activeBefore.filter_id,
    status: activeBefore.status,
    inserted_count: activeBefore.inserted_count,
    capacity_limit: activeBefore.capacity_limit,
    m_bits: activeBefore.m_bits,
    k: activeBefore.k,
    target_insert_count: targetInsertCount,
  });

  await fillFilterToPercent(activeBefore.filter_id, targetInsertCount, runId, sampleInsertedKeys);

  const manifestAfterFill = await getManifest();
  const testedFilter = getFilterById(manifestAfterFill, activeBefore.filter_id);
  const actualInsertedCount = Number(testedFilter.inserted_count);

  assert(
    actualInsertedCount >= targetInsertCount,
    `Filtro testado deveria ter pelo menos inserted_count=${targetInsertCount}, veio ${actualInsertedCount}`
  );

  await verifyInsertedKeys(testedFilter.filter_id, sampleInsertedKeys);

  const measured = await measureFalsePositivesParallel(testedFilter.filter_id, runId);
  const observedRate = measured.falsePositives / measured.checked;
  const theoreticalProbability = falsePositiveProbability(testedFilter.m_bits, testedFilter.k, actualInsertedCount);
  const expectedFpCount = expectedFalsePositives(measured.checked, theoreticalProbability);
  const expectedProbes = expectedProbesUntilFirstFalsePositive(theoreticalProbability);
  const testsFor50Percent = testsNeededForConfidence(theoreticalProbability, 0.5);
  const testsFor95Percent = testsNeededForConfidence(theoreticalProbability, 0.95);
  const testsFor99Percent = testsNeededForConfidence(theoreticalProbability, 0.99);

  console.log("\n============================================================");
  console.log("RESUMO FINAL");
  console.log({
    filter_id: testedFilter.filter_id,
    status_after_fill: testedFilter.status,
    inserted_count: actualInsertedCount,
    capacity_limit: Number(testedFilter.capacity_limit),
    load_percent: ((actualInsertedCount / Number(testedFilter.capacity_limit)) * 100).toFixed(2),
    absent_keys_tested: measured.checked,
    check_workers_used: measured.workerCount,
    false_positives_observed: measured.falsePositives,
    first_false_positive_after: measured.firstFalsePositiveAfter,
    observed_fp_rate: observedRate,
    theoretical_fp_probability: theoreticalProbability,
    theoretical_expected_false_positives_in_sample: expectedFpCount,
    theoretical_expected_probes_until_fp: formatNumber(expectedProbes, 2),
    theoretical_tests_for_50_percent_chance_of_fp: formatNumber(testsFor50Percent, 2),
    theoretical_tests_for_95_percent_chance_of_fp: formatNumber(testsFor95Percent, 2),
    theoretical_tests_for_99_percent_chance_of_fp: formatNumber(testsFor99Percent, 2),
    m_bits: Number(testedFilter.m_bits),
    k: Number(testedFilter.k),
  });
  console.log("============================================================");
}

if (!isMainThread && workerData && workerData.mode === "measure_false_positives_worker") {
  workerMeasureFalsePositives().catch((err) => {
    throw err;
  });
} else if (isMainThread) {
  main().catch((err) => {
    console.error(
      "FALHA NO SCRIPT MANUAL DE FALSO POSITIVO EM UM UNICO PERCENTUAL:",
      err && err.stack ? err.stack : err
    );
    process.exit(1);
  });
}
