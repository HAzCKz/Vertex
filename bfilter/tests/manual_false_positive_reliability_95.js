/*
TESTE MANUAL: CONFIABILIDADE EM CONFIGURACAO PRODUCAO-LIKE

PARA RODAR:
1. Suba o servico com BFILTER_ENABLE_TEST_API=1.
BFILTER_ENABLE_TEST_API=1 \
cargo run

2. Rode:

cd /home/yugi/programacao/bfilter
BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
BFILTER_ROTATE_AT_PERCENT="95" \
INSERT_BATCH_SIZE="5000" \
CHECK_BATCH_SIZE="1000" \
FALSE_POSITIVE_TESTS="200000" \
SANITY_PRESENT_CHECKS="128" \
node tests/manual_false_positive_reliability_95.js

O que este script faz:
- reseta a instancia de testes para um filtro limpo no tamanho padrao
- calcula o limiar de rotacao em 95% da capacidade teorica do filtro
- cadastra entradas aleatorias ate fechar o filtro exatamente no limiar
- valida que algumas chaves inseridas continuam presentes no filtro fechado
- testa uma amostra de chaves ausentes para procurar falsos positivos
- compara a taxa observada com a probabilidade teorica no ponto de 95%

Uso recomendado:
- validacao operacional
- regressao de integracao
- confirmacao de que o filtro continua seguro a 95% da capacidade

Observacao:
- este teste nao foi feito para medir empiricamente taxas ultra-baixas como 2^-32

ATENCAO:
- este script APAGA os filtros atuais via POST /test/reset
- use apenas contra um ambiente controlado de testes
*/

const BFILTER_BASE_URL = (process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080").replace(/\/+$/, "");
const BFILTER_ADMIN_TOKEN = process.env.BFILTER_ADMIN_TOKEN || "dev-admin-token";
const BFILTER_ROTATE_AT_PERCENT = parsePositiveInt(
  "BFILTER_ROTATE_AT_PERCENT",
  process.env.BFILTER_ROTATE_AT_PERCENT,
  95
);
const INSERT_BATCH_SIZE = parsePositiveInt("INSERT_BATCH_SIZE", process.env.INSERT_BATCH_SIZE, 5000);
const CHECK_BATCH_SIZE = parsePositiveInt("CHECK_BATCH_SIZE", process.env.CHECK_BATCH_SIZE, 1000);
const FALSE_POSITIVE_TESTS = parsePositiveInt(
  "FALSE_POSITIVE_TESTS",
  process.env.FALSE_POSITIVE_TESTS,
  200000
);
const SANITY_PRESENT_CHECKS = parsePositiveInt(
  "SANITY_PRESENT_CHECKS",
  process.env.SANITY_PRESENT_CHECKS,
  128
);
const REQUESTED_BY = "manual-false-positive-reliability-95";

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

assert(
  BFILTER_ROTATE_AT_PERCENT >= 1 && BFILTER_ROTATE_AT_PERCENT <= 100,
  `BFILTER_ROTATE_AT_PERCENT deve ficar entre 1 e 100, veio: ${BFILTER_ROTATE_AT_PERCENT}`
);

function parsePositiveInt(name, rawValue, fallback) {
  if (rawValue == null || rawValue === "") return fallback;
  const value = Number(rawValue);
  assert(Number.isInteger(value) && value > 0, `${name} deve ser inteiro positivo, veio: ${rawValue}`);
  return value;
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

function upperBoundZeroEvents(sampleSize, confidence = 0.95) {
  return -Math.log(1 - confidence) / sampleSize;
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

function makeKeys(prefix, startIndex, count) {
  return Array.from({ length: count }, (_, idx) => `${prefix}-${String(startIndex + idx).padStart(12, "0")}`);
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

async function writeUntilThreshold(totalKeys, runId, sampleInsertedKeys) {
  let written = 0;
  let batchNo = 0;

  while (written < totalKeys) {
    batchNo += 1;
    const batchSize = Math.min(INSERT_BATCH_SIZE, totalKeys - written);
    const keys = makeKeys(`fp95-insert-${runId}`, written, batchSize);

    while (sampleInsertedKeys.length < SANITY_PRESENT_CHECKS && sampleInsertedKeys.length < totalKeys) {
      const sampleIndex = sampleInsertedKeys.length;
      if (sampleIndex >= written && sampleIndex < written + keys.length) {
        sampleInsertedKeys.push(keys[sampleIndex - written]);
      } else {
        break;
      }
    }

    const body = await writeRevocations(keys, `fill-until-${BFILTER_ROTATE_AT_PERCENT}-percent-batch-${batchNo}`);
    written += batchSize;

    if (batchNo === 1 || written === totalKeys || batchNo % 10 === 0) {
      console.log(`Insercao lote ${batchNo}:`, {
        batch_size: batchSize,
        written_total: written,
        target_total: totalKeys,
        filter_id: body.filter_id,
      });
    }
  }
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

async function measureFalsePositives(filterId, runId) {
  let checked = 0;
  let falsePositives = 0;
  let batchNo = 0;

  while (checked < FALSE_POSITIVE_TESTS) {
    batchNo += 1;
    const batchSize = Math.min(CHECK_BATCH_SIZE, FALSE_POSITIVE_TESTS - checked);
    const keys = makeKeys(`fp95-probe-${runId}`, checked, batchSize);
    const body = await checkKeys(filterId, keys);
    const batchFalsePositives = body.results.filter((item) => item.maybe_present === true).length;

    falsePositives += batchFalsePositives;
    checked += batchSize;

    if (batchNo === 1 || checked === FALSE_POSITIVE_TESTS || batchNo % 20 === 0) {
      console.log(`Consulta lote ${batchNo}:`, {
        batch_size: batchSize,
        checked_total: checked,
        false_positives_total: falsePositives,
      });
    }
  }

  return { checked, falsePositives };
}

(async () => {
  const runId = `${Date.now()}-${process.pid}`;

  console.log("============================================================");
  console.log("MANUAL BLOOM FILTER FALSE POSITIVE RELIABILITY @ 95%");
  console.log("Config:", {
    BFILTER_BASE_URL,
    BFILTER_ROTATE_AT_PERCENT,
    INSERT_BATCH_SIZE,
    CHECK_BATCH_SIZE,
    FALSE_POSITIVE_TESTS,
    SANITY_PRESENT_CHECKS,
    adminToken: "***",
  });
  console.log("============================================================");

  const manifestAfterReset = await resetFiltersForTest();
  const activeBefore = getActiveFilter(manifestAfterReset);
  const targetProbability = Math.pow(2, -Number(manifestAfterReset.false_positive_power || 32));
  const safeInsertCount = rotationThreshold(activeBefore.capacity_limit, BFILTER_ROTATE_AT_PERCENT);
  const expectedProbabilityAt95 = falsePositiveProbability(
    activeBefore.m_bits,
    activeBefore.k,
    safeInsertCount
  );

  console.log("Filtro limpo apos reset:", {
    filter_id: activeBefore.filter_id,
    status: activeBefore.status,
    inserted_count: activeBefore.inserted_count,
    capacity_limit: activeBefore.capacity_limit,
    m_bits: activeBefore.m_bits,
    k: activeBefore.k,
    safe_insert_count: safeInsertCount,
    target_probability: targetProbability,
    expected_probability_at_safe_load: expectedProbabilityAt95,
  });

  assert(
    expectedProbabilityAt95 <= targetProbability,
    "A probabilidade teorica em 95% deveria ficar abaixo do alvo configurado"
  );

  const sampleInsertedKeys = [];
  await writeUntilThreshold(safeInsertCount, runId, sampleInsertedKeys);

  const manifestAfterFill = await getManifest();
  const closedFilter = getFilterById(manifestAfterFill, activeBefore.filter_id);
  const newActive = getActiveFilter(manifestAfterFill);

  assert(
    closedFilter.status === "closed",
    `Filtro preenchido deveria estar closed apos atingir ${BFILTER_ROTATE_AT_PERCENT}%, veio ${closedFilter.status}`
  );
  assert(
    Number(closedFilter.inserted_count) === safeInsertCount,
    `Filtro fechado deveria ter inserted_count=${safeInsertCount}, veio ${closedFilter.inserted_count}`
  );
  assert(closedFilter.closed_at, "Filtro fechado deveria ter closed_at");
  assert(
    newActive.filter_id !== closedFilter.filter_id,
    "A rotacao deveria abrir um novo filtro ativo apos fechar o filtro de teste"
  );
  assert(newActive.status === "active", `Novo filtro deveria estar active, veio ${newActive.status}`);
  assert(Number(newActive.inserted_count || 0) === 0, "Novo filtro deveria iniciar vazio");

  await verifyInsertedKeys(closedFilter.filter_id, sampleInsertedKeys);

  const measured = await measureFalsePositives(closedFilter.filter_id, runId);
  const observedRate = measured.falsePositives / measured.checked;
  const theoreticalProbability = falsePositiveProbability(
    closedFilter.m_bits,
    closedFilter.k,
    Number(closedFilter.inserted_count)
  );
  const expectedFalsePositivesInSample = theoreticalProbability * measured.checked;
  const zeroEventUpperBound95 = upperBoundZeroEvents(measured.checked, 0.95);

  assert(
    theoreticalProbability <= targetProbability,
    "A probabilidade teorica no filtro fechado deveria permanecer abaixo do alvo configurado"
  );
  assert(
    measured.falsePositives === 0,
    `Foram detectados ${measured.falsePositives} falsos positivos em ${measured.checked} consultas`
  );

  console.log("\n============================================================");
  console.log("TESTE DE CONFIABILIDADE CONCLUIDO");
  console.log("Filtro fechado testado:", {
    filter_id: closedFilter.filter_id,
    inserted_count: closedFilter.inserted_count,
    capacity_limit: closedFilter.capacity_limit,
    safe_load_percent: ((Number(closedFilter.inserted_count) / Number(closedFilter.capacity_limit)) * 100).toFixed(2),
    m_bits: closedFilter.m_bits,
    k: closedFilter.k,
  });
  console.log("Resultados:", {
    checked_absent_keys: measured.checked,
    false_positives: measured.falsePositives,
    observed_fp_rate: observedRate,
    expected_fp_rate_at_95: theoreticalProbability,
    expected_fp_in_sample: expectedFalsePositivesInSample,
    upper_bound_if_zero_fp_95_confidence: zeroEventUpperBound95,
  });
  console.log("Novo filtro ativo:", {
    filter_id: newActive.filter_id,
    status: newActive.status,
    inserted_count: newActive.inserted_count,
  });
  console.log("============================================================");
})().catch((err) => {
  console.error(
    "FALHA NO SCRIPT MANUAL DE CONFIABILIDADE DE FALSO POSITIVO:",
    err && err.stack ? err.stack : err
  );
  process.exit(1);
});
