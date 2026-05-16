/*
TESTE MANUAL: CURVA EMPIRICA DE CAPACIDADE

PARA RODAR:
1. Suba o servico em modo de teste com uma meta mensuravel.
   Exemplo recomendado:

cd /home/yugi/programacao/bfilter
BFILTER_ENABLE_TEST_API=1 \
BFILTER_FALSE_POSITIVE_POWER=10 \
BFILTER_ROTATE_AT_PERCENT=100 \
cargo run

2. Rode este script:

cd /home/yugi/programacao/bfilter
BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
BFILTER_ROTATE_AT_PERCENT="100" \
TEST_FILTER_BYTES="131072" \
TEST_K="3" \
FILL_PERCENTS="50,70,80,90,95,100,105,110" \
INSERT_BATCH_SIZE="5000" \
CHECK_BATCH_SIZE="1000" \
FALSE_POSITIVE_TESTS="200000" \
SANITY_PRESENT_CHECKS="128" \
MIN_EXPECTED_FALSE_POSITIVES="25" \
MAX_TARGET_Z_SCORE="3" \
node tests/manual_empirical_capacity_curve.js

O que este script faz:
- reseta o ambiente para um filtro controlado antes de cada percentual
- calcula a capacidade teorica para o k real do filtro
- preenche o filtro em varios percentuais dessa capacidade teorica
- mede falsos positivos em uma amostra grande de chaves ausentes
- compara taxa observada vs taxa teorica no ponto testado
- informa um intervalo empirico para a capacidade observada

ATENCAO:
- este script APAGA os filtros atuais via POST /test/reset
- ele exige BFILTER_ENABLE_TEST_API=1
- para testar percentuais acima de 100% da capacidade teorica do k escolhido,
  o servico precisa permitir inserir tudo no mesmo filtro sem rotacao antecipada
*/

const BFILTER_BASE_URL = (process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080").replace(/\/+$/, "");
const BFILTER_ADMIN_TOKEN = process.env.BFILTER_ADMIN_TOKEN || "dev-admin-token";
const BFILTER_ROTATE_AT_PERCENT = parsePositiveInt(
  "BFILTER_ROTATE_AT_PERCENT",
  process.env.BFILTER_ROTATE_AT_PERCENT,
  100
);
const TEST_FILTER_BYTES = parsePositiveInt("TEST_FILTER_BYTES", process.env.TEST_FILTER_BYTES, 131072);
const TEST_K = parseOptionalPositiveInt("TEST_K", process.env.TEST_K);
const FILL_PERCENTS = parsePercentList(
  "FILL_PERCENTS",
  process.env.FILL_PERCENTS,
  "50,70,80,90,95,100,105,110"
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
const MIN_EXPECTED_FALSE_POSITIVES = parsePositiveInt(
  "MIN_EXPECTED_FALSE_POSITIVES",
  process.env.MIN_EXPECTED_FALSE_POSITIVES,
  25
);
const MAX_TARGET_Z_SCORE = parsePositiveNumber(
  "MAX_TARGET_Z_SCORE",
  process.env.MAX_TARGET_Z_SCORE,
  3
);
const REQUESTED_BY = "manual-empirical-capacity-curve";

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function parsePositiveInt(name, rawValue, fallback) {
  if (rawValue == null || rawValue === "") return fallback;
  const value = Number(rawValue);
  assert(Number.isInteger(value) && value > 0, `${name} deve ser inteiro positivo, veio: ${rawValue}`);
  return value;
}

function parseOptionalPositiveInt(name, rawValue) {
  if (rawValue == null || rawValue === "") return undefined;
  return parsePositiveInt(name, rawValue);
}

function parsePositiveNumber(name, rawValue, fallback) {
  if (rawValue == null || rawValue === "") return fallback;
  const value = Number(rawValue);
  assert(Number.isFinite(value) && value > 0, `${name} deve ser numero positivo, veio: ${rawValue}`);
  return value;
}

function parsePercentList(name, rawValue, fallback) {
  const source = rawValue == null || rawValue === "" ? fallback : rawValue;
  const values = source
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => {
      const value = Number(item);
      assert(Number.isInteger(value) && value > 0, `${name} deve conter inteiros positivos, veio: ${item}`);
      return value;
    });

  assert(values.length > 0, `${name} nao pode ficar vazio`);

  const uniqueSorted = [...new Set(values)].sort((a, b) => a - b);
  return uniqueSorted;
}

function targetInsertCountForPercent(capacityLimit, percent) {
  return Math.floor((capacityLimit * percent + 99) / 100);
}

function falsePositiveProbability(mBits, k, n) {
  if (n === 0 || k === 0) return 0;
  const oneMinusOneOverM = 1 - 1 / mBits;
  const inner = 1 - Math.pow(oneMinusOneOverM, k * n);
  return Math.pow(inner, k);
}

function maxNForK(mBits, k, pTarget) {
  let low = 0;
  let high = mBits;

  while (low < high) {
    const mid = Math.floor((low + high + 1) / 2);
    const pMid = falsePositiveProbability(mBits, k, mid);
    if (pMid <= pTarget) {
      low = mid;
    } else {
      high = mid - 1;
    }
  }

  return low;
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

function oneSidedUpperZScore(observedCount, expectedCountValue, stddev) {
  if (stddev === 0) {
    return observedCount <= expectedCountValue ? Number.NEGATIVE_INFINITY : Number.POSITIVE_INFINITY;
  }
  return (observedCount - expectedCountValue) / stddev;
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

async function resetFiltersForTest(mBits, k) {
  const payload = { m_bits: mBits };
  if (k != null) payload.k = k;

  const resp = await fetch(`${BFILTER_BASE_URL}/test/reset`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${BFILTER_ADMIN_TOKEN}`,
    },
    body: JSON.stringify(payload),
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

async function writeUntilCount(totalKeys, runId, fillPercent, sampleInsertedKeys) {
  let written = 0;
  let batchNo = 0;

  while (written < totalKeys) {
    batchNo += 1;
    const batchSize = Math.min(INSERT_BATCH_SIZE, totalKeys - written);
    const keys = makeKeys(`empirical-capacity-insert-${runId}-p${fillPercent}`, written, batchSize);

    while (sampleInsertedKeys.length < SANITY_PRESENT_CHECKS && sampleInsertedKeys.length < totalKeys) {
      const sampleIndex = sampleInsertedKeys.length;
      if (sampleIndex >= written && sampleIndex < written + keys.length) {
        sampleInsertedKeys.push(keys[sampleIndex - written]);
      } else {
        break;
      }
    }

    const body = await writeRevocations(keys, `empirical-fill-${fillPercent}-batch-${batchNo}`);
    written += batchSize;

    if (batchNo === 1 || written === totalKeys || batchNo % 10 === 0) {
      console.log(`Insercao ${fillPercent}% lote ${batchNo}:`, {
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

async function measureFalsePositives(filterId, runId, fillPercent) {
  let checked = 0;
  let falsePositives = 0;
  let batchNo = 0;

  while (checked < FALSE_POSITIVE_TESTS) {
    batchNo += 1;
    const batchSize = Math.min(CHECK_BATCH_SIZE, FALSE_POSITIVE_TESTS - checked);
    const keys = makeKeys(`empirical-capacity-probe-${runId}-p${fillPercent}`, checked, batchSize);
    const body = await checkKeys(filterId, keys);
    const batchFalsePositives = body.results.filter((item) => item.maybe_present === true).length;

    falsePositives += batchFalsePositives;
    checked += batchSize;

    if (batchNo === 1 || checked === FALSE_POSITIVE_TESTS || batchNo % 20 === 0) {
      console.log(`Consulta ${fillPercent}% lote ${batchNo}:`, {
        batch_size: batchSize,
        checked_total: checked,
        false_positives_total: falsePositives,
      });
    }
  }

  return { checked, falsePositives };
}

function summarizePoint(fillPercent, theoreticalCapacityForK, testedFilter, measured, pTarget) {
  const actualInsertedCount = Number(testedFilter.inserted_count || 0);
  const observedRate = measured.falsePositives / measured.checked;
  const theoreticalProbability = falsePositiveProbability(
    Number(testedFilter.m_bits),
    Number(testedFilter.k),
    actualInsertedCount
  );
  const expectedTheory = expectedCount(measured.checked, theoreticalProbability);
  const stddevTheory = standardDeviation(measured.checked, theoreticalProbability);
  const theoryZScore = zScore(measured.falsePositives, expectedTheory, stddevTheory);
  const expectedAtTarget = expectedCount(measured.checked, pTarget);
  const stddevTarget = standardDeviation(measured.checked, pTarget);
  const upperTargetZ = oneSidedUpperZScore(measured.falsePositives, expectedAtTarget, stddevTarget);
  const zeroEventUpperBound95 = upperBoundZeroEvents(measured.checked, 0.95);
  const targetSignalMode =
    expectedAtTarget >= MIN_EXPECTED_FALSE_POSITIVES
      ? "measurable-fp"
      : measured.falsePositives === 0 && zeroEventUpperBound95 <= pTarget
        ? "zero-event-validated"
        : "low-signal";
  const targetExceededWithConfidence =
    targetSignalMode === "measurable-fp" && upperTargetZ > MAX_TARGET_Z_SCORE;
  const compatibleWithTarget =
    targetSignalMode === "measurable-fp"
      ? !targetExceededWithConfidence
      : targetSignalMode === "zero-event-validated";
  const compatibleWithTheory =
    expectedTheory >= MIN_EXPECTED_FALSE_POSITIVES
      ? theoryZScore <= MAX_TARGET_Z_SCORE
      : measured.falsePositives === 0 || observedRate <= theoreticalProbability;
  const status =
    targetSignalMode === "low-signal"
      ? "INCONCLUSIVE"
      : compatibleWithTarget
        ? "PASS"
        : "FAIL";

  return {
    fill_percent: fillPercent,
    target_insert_count: targetInsertCountForPercent(theoreticalCapacityForK, fillPercent),
    actual_inserted_count: actualInsertedCount,
    theoretical_capacity_for_k: theoreticalCapacityForK,
    manifest_capacity_limit: Number(testedFilter.capacity_limit || 0),
    k: Number(testedFilter.k),
    observed_false_positives: measured.falsePositives,
    checked_absent_keys: measured.checked,
    observed_fp_rate: observedRate,
    theoretical_fp_rate_at_tested_load: theoreticalProbability,
    target_fp_rate: pTarget,
    expected_false_positives_theory: expectedTheory,
    expected_false_positives_target: expectedAtTarget,
    theory_z_score: theoryZScore,
    target_upper_z_score: upperTargetZ,
    zero_event_upper_bound_95: zeroEventUpperBound95,
    target_signal_mode: targetSignalMode,
    target_exceeded_with_confidence: targetExceededWithConfidence,
    compatible_with_theory: compatibleWithTheory,
    compatible_with_target: compatibleWithTarget,
    status,
  };
}

(async () => {
  const testMBits = TEST_FILTER_BYTES * 8;
  const manifestBefore = await getManifest();
  const falsePositivePower = Number(manifestBefore.false_positive_power || 32);
  const pTarget = 2 ** -falsePositivePower;
  const summaries = [];

  console.log("============================================================");
  console.log("MANUAL EMPIRICAL CAPACITY CURVE");
  console.log("Config:", {
    BFILTER_BASE_URL,
    BFILTER_ROTATE_AT_PERCENT,
    TEST_FILTER_BYTES,
    TEST_K: TEST_K ?? null,
    test_m_bits: testMBits,
    FILL_PERCENTS,
    FALSE_POSITIVE_TESTS,
    MIN_EXPECTED_FALSE_POSITIVES,
    MAX_TARGET_Z_SCORE,
    manifest_false_positive_power: falsePositivePower,
    target_fp_rate: pTarget,
    adminToken: "***",
  });
  console.log("============================================================");

  for (const fillPercent of FILL_PERCENTS) {
    const runId = `${Date.now()}-${process.pid}-${fillPercent}`;
    console.log(`\n--- Percentual alvo: ${fillPercent}% ---`);

    const manifestAfterReset = await resetFiltersForTest(testMBits, TEST_K);
    const activeBefore = getActiveFilter(manifestAfterReset);
    const theoreticalCapacityForK = maxNForK(activeBefore.m_bits, activeBefore.k, pTarget);
    const targetInsertCount = targetInsertCountForPercent(theoreticalCapacityForK, fillPercent);
    const serviceRotationCount = targetInsertCountForPercent(activeBefore.capacity_limit, BFILTER_ROTATE_AT_PERCENT);

    console.log("Filtro limpo apos reset:", {
      filter_id: activeBefore.filter_id,
      status: activeBefore.status,
      manifest_capacity_limit: activeBefore.capacity_limit,
      theoretical_capacity_for_k: theoreticalCapacityForK,
      m_bits: activeBefore.m_bits,
      k: activeBefore.k,
      target_insert_count: targetInsertCount,
      service_rotation_count_assumed: serviceRotationCount,
    });

    if (targetInsertCount > serviceRotationCount) {
      console.warn(
        [
          `Percentual ${fillPercent}% ultrapassa o limite assumido de escrita no mesmo filtro.`,
          `target_insert_count=${targetInsertCount}`,
          `service_rotation_count_assumed=${serviceRotationCount}`,
          "Pulando este ponto. Se quiser testa-lo, suba o servico com BFILTER_ROTATE_AT_PERCENT maior ou use um k explicito menor.",
        ].join(" ")
      );
      summaries.push({
        fill_percent: fillPercent,
        status: "SKIPPED",
        reason: "rotation-threshold",
        target_insert_count: targetInsertCount,
        service_rotation_count_assumed: serviceRotationCount,
        theoretical_capacity_for_k: theoreticalCapacityForK,
        manifest_capacity_limit: Number(activeBefore.capacity_limit || 0),
      });
      continue;
    }

    const sampleInsertedKeys = [];
    await writeUntilCount(targetInsertCount, runId, fillPercent, sampleInsertedKeys);

    const manifestAfterFill = await getManifest();
    const testedFilter = getFilterById(manifestAfterFill, activeBefore.filter_id);

    assert(
      Number(testedFilter.inserted_count || 0) >= targetInsertCount,
      [
        "O filtro de teste nao atingiu a carga esperada.",
        `filter_id=${testedFilter.filter_id}`,
        `inserted_count=${testedFilter.inserted_count}`,
        `target_insert_count=${targetInsertCount}`,
        "Verifique se o servico rotacionou antes do esperado ou se BFILTER_ROTATE_AT_PERCENT difere do script.",
      ].join(" ")
    );

    await verifyInsertedKeys(testedFilter.filter_id, sampleInsertedKeys);

    const measured = await measureFalsePositives(testedFilter.filter_id, runId, fillPercent);
    const summary = summarizePoint(fillPercent, theoreticalCapacityForK, testedFilter, measured, pTarget);
    summaries.push(summary);

    console.log("Resumo do ponto:", summary);
  }

  const evaluated = summaries.filter((item) => item.status !== "SKIPPED");
  assert(evaluated.length > 0, "Nenhum ponto foi efetivamente testado.");

  const passedPoints = evaluated.filter((item) => item.status === "PASS");
  const failedPoints = evaluated.filter((item) => item.status === "FAIL");
  const inconclusivePoints = evaluated.filter((item) => item.status === "INCONCLUSIVE");

  const firstFailIndex = summaries.findIndex((item) => item.status === "FAIL");
  const empiricalFirstFail = firstFailIndex >= 0 ? summaries[firstFailIndex] : null;
  const lowerBoundCandidates =
    firstFailIndex >= 0
      ? summaries.slice(0, firstFailIndex).filter((item) => item.status === "PASS")
      : passedPoints;
  const empiricalLowerBound =
    lowerBoundCandidates.length > 0 ? lowerBoundCandidates[lowerBoundCandidates.length - 1] : null;

  console.log("\n============================================================");
  console.log("CURVA EMPIRICA CONCLUIDA");
  console.table(
    summaries.map((item) => ({
      fill_percent: item.fill_percent,
      status: item.status,
      k: item.k ?? null,
      target_insert_count: item.target_insert_count,
      actual_inserted_count: item.actual_inserted_count ?? null,
      observed_fp_rate: item.observed_fp_rate ?? null,
      theoretical_fp_rate: item.theoretical_fp_rate_at_tested_load ?? null,
      target_fp_rate: item.target_fp_rate ?? null,
      target_upper_z_score: item.target_upper_z_score ?? null,
      target_exceeded_with_confidence: item.target_exceeded_with_confidence ?? null,
      theory_z_score: item.theory_z_score ?? null,
    }))
  );

  console.log("Resumo final:", {
    tested_points: evaluated.length,
    passed_points: passedPoints.length,
    failed_points: failedPoints.length,
    inconclusive_points: inconclusivePoints.length,
    empirical_capacity_lower_bound: empiricalLowerBound
      ? {
          fill_percent: empiricalLowerBound.fill_percent,
          inserted_count: empiricalLowerBound.actual_inserted_count,
          theoretical_capacity_for_k: empiricalLowerBound.theoretical_capacity_for_k,
        }
      : null,
    empirical_first_fail: empiricalFirstFail
      ? {
          fill_percent: empiricalFirstFail.fill_percent,
          inserted_count: empiricalFirstFail.actual_inserted_count,
          theoretical_capacity_for_k: empiricalFirstFail.theoretical_capacity_for_k,
        }
      : null,
  });
  console.log("============================================================");
})().catch((err) => {
  console.error(
    "FALHA NO SCRIPT MANUAL DE CURVA EMPIRICA DE CAPACIDADE:",
    err && err.stack ? err.stack : err
  );
  process.exit(1);
});
