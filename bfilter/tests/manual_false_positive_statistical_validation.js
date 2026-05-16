/*
TESTE MANUAL: VALIDACAO ESTATISTICA EM LABORATORIO

PARA RODAR:
1. Suba o servico em modo de teste com uma meta de falso positivo mensuravel.
   Exemplo recomendado:

BFILTER_ENABLE_TEST_API=1 \
BFILTER_FALSE_POSITIVE_POWER=10 \
cargo run

2. Rode este script:

cd /home/yugi/programacao/bfilter
BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
BFILTER_ROTATE_AT_PERCENT="95" \
TEST_FILTER_BYTES="2097152" \
TEST_K="32" \
INSERT_BATCH_SIZE="5000" \
CHECK_BATCH_SIZE="1000" \
FALSE_POSITIVE_TESTS="10000000" \
SANITY_PRESENT_CHECKS="128" \
MIN_EXPECTED_FALSE_POSITIVES="25" \
MAX_Z_SCORE="6" \
node tests/manual_false_positive_statistical_validation.js

O que este script faz:
- reseta a instancia de testes para um filtro menor e limpo
- usa um k de teste explicito, suportando tanto cenario mensuravel quanto cenario ultra-baixo
- preenche o filtro ate 95% da capacidade teorica
- valida ausencia de falso negativo em uma amostra de inseridos
- mede falsos positivos em uma amostra grande de ausentes
- compara o valor observado com a expectativa teorica usando z-score
- quando a expectativa teorica for proxima de zero, valida o regime de zero eventos

Uso recomendado:
- comparacao entre teoria e pratica
- tuning de parametros
- demonstracao de taxa de falso positivo em cenario mensuravel
- confirmacao de que configuracoes como k=32 nao geram falso positivo observavel na amostra

ATENCAO:
- este script APAGA os filtros atuais via POST /test/reset
- ele exige BFILTER_ENABLE_TEST_API=1
- para BFILTER_FALSE_POSITIVE_POWER muito alto, o proprio script vai pedir um cenario mais mensuravel
*/

const BFILTER_BASE_URL = (process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080").replace(/\/+$/, "");
const BFILTER_ADMIN_TOKEN = process.env.BFILTER_ADMIN_TOKEN || "dev-admin-token";
const BFILTER_ROTATE_AT_PERCENT = parsePositiveInt(
  "BFILTER_ROTATE_AT_PERCENT",
  process.env.BFILTER_ROTATE_AT_PERCENT,
  95
);
const TEST_FILTER_BYTES = parsePositiveInt("TEST_FILTER_BYTES", process.env.TEST_FILTER_BYTES, 131072);
const TEST_K = parsePositiveInt("TEST_K", process.env.TEST_K, 3);
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
const MIN_EXPECTED_FALSE_POSITIVES = parsePositiveInt(
  "MIN_EXPECTED_FALSE_POSITIVES",
  process.env.MIN_EXPECTED_FALSE_POSITIVES,
  25
);
const MAX_Z_SCORE = parsePositiveNumber("MAX_Z_SCORE", process.env.MAX_Z_SCORE, 6);
const REQUESTED_BY = "manual-false-positive-statistical-validation";

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

function parsePositiveNumber(name, rawValue, fallback) {
  if (rawValue == null || rawValue === "") return fallback;
  const value = Number(rawValue);
  assert(Number.isFinite(value) && value > 0, `${name} deve ser numero positivo, veio: ${rawValue}`);
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

function expectedCount(sampleSize, probability) {
  return sampleSize * probability;
}

function standardDeviation(sampleSize, probability) {
  return Math.sqrt(sampleSize * probability * (1 - probability));
}

function zScore(observedCount, expectedCountValue, stddev) {
  if (stddev === 0) {
    return observedCount === expectedCountValue ? 0 : Number.POSITIVE_INFINITY;
  }
  return Math.abs(observedCount - expectedCountValue) / stddev;
}

function upperBoundZeroEvents(sampleSize, confidence = 0.95) {
  return -Math.log(1 - confidence) / sampleSize;
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

async function resetFiltersForTest(mBits, k) {
  const resp = await fetch(`${BFILTER_BASE_URL}/test/reset`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${BFILTER_ADMIN_TOKEN}`,
    },
    body: JSON.stringify({
      m_bits: mBits,
      k,
    }),
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
    const keys = makeKeys(`fp-stat-insert-${runId}`, written, batchSize);

    while (sampleInsertedKeys.length < SANITY_PRESENT_CHECKS && sampleInsertedKeys.length < totalKeys) {
      const sampleIndex = sampleInsertedKeys.length;
      if (sampleIndex >= written && sampleIndex < written + keys.length) {
        sampleInsertedKeys.push(keys[sampleIndex - written]);
      } else {
        break;
      }
    }

    const body = await writeRevocations(keys, `statistical-fill-batch-${batchNo}`);
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

async function ensureFilterClosed(filterId, manifestAfterFill, runId) {
  let manifest = manifestAfterFill;
  let testedFilter = getFilterById(manifest, filterId);
  let extraWritten = 0;
  const initialInsertedCount = Number(testedFilter.inserted_count || 0);
  const capacityLimit = Number(testedFilter.capacity_limit || 0);
  const maxAdditionalKeys = Math.max(INSERT_BATCH_SIZE, capacityLimit - initialInsertedCount + INSERT_BATCH_SIZE);

  if (testedFilter.status !== "closed") {
    console.warn(
      "AVISO: filtro ainda active apos a carga alvo do script. Continuando a inserir ate a rotacao real do servico."
    );
    console.warn("Isso normalmente indica que o servico foi iniciado com BFILTER_ROTATE_AT_PERCENT diferente do script.");
  }

  while (testedFilter.status !== "closed" && extraWritten < maxAdditionalKeys) {
    const remainingBeforeCapacity = Math.max(1, capacityLimit - Number(testedFilter.inserted_count || 0));
    const batchSize = Math.min(INSERT_BATCH_SIZE, remainingBeforeCapacity, maxAdditionalKeys - extraWritten);
    const keys = makeKeys(`fp-stat-close-gap-${runId}`, extraWritten, batchSize);

    await writeRevocations(keys, `statistical-close-gap-${extraWritten + batchSize}`);
    extraWritten += batchSize;
    manifest = await getManifest();
    testedFilter = getFilterById(manifest, filterId);

    console.log("Carga extra para forcar rotacao:", {
      batch_size: batchSize,
      extra_written_total: extraWritten,
      filter_id: testedFilter.filter_id,
      status: testedFilter.status,
      inserted_count: testedFilter.inserted_count,
    });
  }

  assert(
    testedFilter.status === "closed",
    [
      "Filtro testado permaneceu active mesmo apos a carga extra.",
      `filter_id=${filterId}`,
      `inserted_count=${testedFilter.inserted_count}`,
      `capacity_limit=${testedFilter.capacity_limit}`,
      "Verifique se o servico em execucao suporta rotacao automatica e se foi iniciado com a configuracao esperada.",
    ].join(" ")
  );

  return { manifest, testedFilter, extraWritten };
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
    const keys = makeKeys(`fp-stat-probe-${runId}`, checked, batchSize);
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
  const testMBits = TEST_FILTER_BYTES * 8;

  console.log("============================================================");
  console.log("MANUAL BLOOM FILTER FALSE POSITIVE STATISTICAL VALIDATION");
  console.log("Config:", {
    BFILTER_BASE_URL,
    BFILTER_ROTATE_AT_PERCENT,
    TEST_FILTER_BYTES,
    TEST_K,
    test_m_bits: testMBits,
    FALSE_POSITIVE_TESTS,
    MIN_EXPECTED_FALSE_POSITIVES,
    MAX_Z_SCORE,
    adminToken: "***",
  });
  console.log("============================================================");

  const manifestBeforeReset = await getManifest();
  const manifestAfterReset = await resetFiltersForTest(testMBits, TEST_K);
  const activeBefore = getActiveFilter(manifestAfterReset);
  const safeInsertCount = rotationThreshold(activeBefore.capacity_limit, BFILTER_ROTATE_AT_PERCENT);
  const theoreticalProbabilityAt95 = falsePositiveProbability(activeBefore.m_bits, activeBefore.k, safeInsertCount);
  const expectedFpPreview = expectedCount(FALSE_POSITIVE_TESTS, theoreticalProbabilityAt95);
  const statisticalMode =
    expectedFpPreview >= MIN_EXPECTED_FALSE_POSITIVES ? "measurable-fp" : "zero-event";

  console.log("Filtro limpo apos reset:", {
    filter_id: activeBefore.filter_id,
    status: activeBefore.status,
    inserted_count: activeBefore.inserted_count,
    capacity_limit: activeBefore.capacity_limit,
    m_bits: activeBefore.m_bits,
    k: activeBefore.k,
    safe_insert_count: safeInsertCount,
    manifest_false_positive_power_before_reset: Number(manifestBeforeReset.false_positive_power || 32),
    expected_probability_at_safe_load: theoreticalProbabilityAt95,
    expected_false_positives_in_sample_preview: expectedFpPreview,
    statistical_mode: statisticalMode,
  });

  if (statisticalMode === "zero-event") {
    console.log(
      "Modo de zero eventos ativado:",
      `expected_false_positives_in_sample=${expectedFpPreview}. O teste vai exigir zero falsos positivos observados.`
    );
  } else {
    assert(
      expectedFpPreview >= MIN_EXPECTED_FALSE_POSITIVES,
      [
        "O cenario atual nao produz falsos positivos suficientes para uma validacao estatistica util.",
        `expected_false_positives_in_sample=${expectedFpPreview}`,
        `min_required=${MIN_EXPECTED_FALSE_POSITIVES}`,
        `Sugestao: reduza TEST_K abaixo de ${activeBefore.k}, aumente FALSE_POSITIVE_TESTS,`,
        "ou use um filtro ainda menor em TEST_FILTER_BYTES.",
      ].join(" ")
    );
  }

  const sampleInsertedKeys = [];
  await writeUntilThreshold(safeInsertCount, runId, sampleInsertedKeys);

  const manifestAfterFill = await getManifest();
  const closure = await ensureFilterClosed(activeBefore.filter_id, manifestAfterFill, runId);
  const closedFilter = closure.testedFilter;
  const newActive = getActiveFilter(closure.manifest);

  assert(
    closedFilter.status === "closed",
    `Filtro preenchido deveria estar closed apos atingir ${BFILTER_ROTATE_AT_PERCENT}%, veio ${closedFilter.status}`
  );
  assert(
    Number(closedFilter.inserted_count) >= safeInsertCount,
    `Filtro fechado deveria ter inserted_count >= ${safeInsertCount}, veio ${closedFilter.inserted_count}`
  );
  assert(
    newActive.filter_id !== closedFilter.filter_id,
    "A rotacao deveria abrir um novo filtro ativo apos fechar o filtro de teste"
  );
  assert(Number(newActive.inserted_count || 0) === 0, "Novo filtro deveria iniciar vazio");

  await verifyInsertedKeys(closedFilter.filter_id, sampleInsertedKeys);

  const measured = await measureFalsePositives(closedFilter.filter_id, runId);
  const observedRate = measured.falsePositives / measured.checked;
  const theoreticalProbability = falsePositiveProbability(
    closedFilter.m_bits,
    closedFilter.k,
    Number(closedFilter.inserted_count)
  );
  const expectedFp = expectedCount(measured.checked, theoreticalProbability);
  const stddev = standardDeviation(measured.checked, theoreticalProbability);
  const score = zScore(measured.falsePositives, expectedFp, stddev);
  const zeroEventUpperBound95 = upperBoundZeroEvents(measured.checked, 0.95);

  if (statisticalMode === "zero-event") {
    assert(
      measured.falsePositives === 0,
      [
        "Para este cenario ultra-baixo eram esperados zero falsos positivos observados na amostra.",
        `observed_fp=${measured.falsePositives}`,
        `checked=${measured.checked}`,
        `theoretical_expected_fp=${expectedFp}`,
      ].join(" ")
    );
  } else {
    assert(
      score <= MAX_Z_SCORE,
      `Taxa observada fora da faixa aceitavel: z_score=${score}, max=${MAX_Z_SCORE}, observed_fp=${measured.falsePositives}, expected_fp=${expectedFp}`
    );
  }

  console.log("\n============================================================");
  console.log("VALIDACAO ESTATISTICA CONCLUIDA");
  console.log("Filtro fechado testado:", {
    filter_id: closedFilter.filter_id,
    inserted_count: closedFilter.inserted_count,
    capacity_limit: closedFilter.capacity_limit,
    extra_keys_written_until_rotation: closure.extraWritten,
    safe_load_percent: ((Number(closedFilter.inserted_count) / Number(closedFilter.capacity_limit)) * 100).toFixed(2),
    m_bits: closedFilter.m_bits,
    k: closedFilter.k,
  });
  console.log("Resultados:", {
    statistical_mode: statisticalMode,
    checked_absent_keys: measured.checked,
    false_positives_observed: measured.falsePositives,
    observed_fp_rate: observedRate,
    expected_fp_rate_at_tested_load: theoreticalProbability,
    expected_false_positives: expectedFp,
    stddev_false_positives: stddev,
    z_score: score,
    max_z_score_allowed: MAX_Z_SCORE,
    zero_event_upper_bound_95_confidence: zeroEventUpperBound95,
  });
  console.log("Novo filtro ativo:", {
    filter_id: newActive.filter_id,
    status: newActive.status,
    inserted_count: newActive.inserted_count,
  });
  console.log("============================================================");
})().catch((err) => {
  console.error(
    "FALHA NO SCRIPT MANUAL DE VALIDACAO ESTATISTICA DE FALSO POSITIVO:",
    err && err.stack ? err.stack : err
  );
  process.exit(1);
});
