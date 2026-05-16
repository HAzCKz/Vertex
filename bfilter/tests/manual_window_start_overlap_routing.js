/*
TESTE MANUAL: SOBREPOSICAO DE WINDOW_START

PARA RODAR:
1. Suba o servico com BFILTER_ENABLE_TEST_API=1.
BFILTER_ENABLE_TEST_API=1 \
cargo run

2. Rode:

cd /home/yugi/programacao/bfilter
BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
BFILTER_ROTATE_AT_PERCENT="95" \
TEST_FILTER_M_BITS="100000" \
TEST_K="4" \
INSERT_BATCH_SIZE="1000" \
OLD_WINDOW_BASE="1700000000" \
OLD_WINDOW_SPREAD="30" \
NEW_WINDOW_BASE="1700000010" \
NEW_WINDOW_SPREAD="25" \
OUTSIDE_WINDOW_START="1700200000" \
node tests/manual_window_start_overlap_routing.js

O que este script faz:
- reseta a instancia de testes para um filtro limpo
- preenche o primeiro filtro ate a rotacao com uma faixa temporal antiga
- escreve novas chaves no filtro ativo com uma faixa que sobrepoe a faixa antiga
- valida que GET /filters/for-window/:window_start retorna dois candidatos na faixa sobreposta
- valida que POST /check com window_start consulta ambos os filtros
- valida que chaves do filtro antigo e do novo continuam encontraveis na janela sobreposta

Uso recomendado:
- regressao do caso em que mais de um filtro e candidato para a mesma janela
- validacao do formato `filter_id` concatenado em POST /check
- confirmacao da ordem de candidatos retornada pela API

ATENCAO:
- este script APAGA os filtros atuais via POST /test/reset
- ele exige BFILTER_ENABLE_TEST_API=1
- use apenas contra um ambiente controlado de testes
*/

const BFILTER_BASE_URL = (process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080").replace(/\/+$/, "");
const BFILTER_ADMIN_TOKEN = process.env.BFILTER_ADMIN_TOKEN || "dev-admin-token";
const BFILTER_ROTATE_AT_PERCENT = parsePositiveInt(
  "BFILTER_ROTATE_AT_PERCENT",
  process.env.BFILTER_ROTATE_AT_PERCENT,
  95
);
const TEST_FILTER_M_BITS = parsePositiveInt("TEST_FILTER_M_BITS", process.env.TEST_FILTER_M_BITS, 100000);
const TEST_K = parsePositiveInt("TEST_K", process.env.TEST_K, 4);
const INSERT_BATCH_SIZE = parsePositiveInt("INSERT_BATCH_SIZE", process.env.INSERT_BATCH_SIZE, 1000);
const OLD_WINDOW_BASE = parseInteger("OLD_WINDOW_BASE", process.env.OLD_WINDOW_BASE, 1700000000);
const OLD_WINDOW_SPREAD = parsePositiveInt("OLD_WINDOW_SPREAD", process.env.OLD_WINDOW_SPREAD, 30);
const NEW_WINDOW_BASE = parseInteger("NEW_WINDOW_BASE", process.env.NEW_WINDOW_BASE, 1700000010);
const NEW_WINDOW_SPREAD = parsePositiveInt("NEW_WINDOW_SPREAD", process.env.NEW_WINDOW_SPREAD, 25);
const OUTSIDE_WINDOW_START = parseInteger(
  "OUTSIDE_WINDOW_START",
  process.env.OUTSIDE_WINDOW_START,
  1700200000
);
const REQUESTED_BY = "manual-window-start-overlap-routing";

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

assert(
  BFILTER_ROTATE_AT_PERCENT >= 1 && BFILTER_ROTATE_AT_PERCENT <= 100,
  `BFILTER_ROTATE_AT_PERCENT deve ficar entre 1 e 100, veio: ${BFILTER_ROTATE_AT_PERCENT}`
);
assert(
  NEW_WINDOW_BASE > OLD_WINDOW_BASE,
  [
    "NEW_WINDOW_BASE deve ser maior que OLD_WINDOW_BASE para existir uma faixa exclusiva do filtro antigo.",
    `OLD_WINDOW_BASE=${OLD_WINDOW_BASE}`,
    `NEW_WINDOW_BASE=${NEW_WINDOW_BASE}`,
  ].join(" ")
);
assert(
  NEW_WINDOW_BASE <= OLD_WINDOW_BASE + OLD_WINDOW_SPREAD - 1,
  [
    "NEW_WINDOW_BASE deve cair dentro da faixa antiga para criar sobreposicao.",
    `OLD_RANGE=[${OLD_WINDOW_BASE}, ${OLD_WINDOW_BASE + OLD_WINDOW_SPREAD - 1}]`,
    `NEW_WINDOW_BASE=${NEW_WINDOW_BASE}`,
  ].join(" ")
);
assert(
  NEW_WINDOW_BASE + NEW_WINDOW_SPREAD - 1 > OLD_WINDOW_BASE + OLD_WINDOW_SPREAD - 1,
  [
    "A nova faixa deve ultrapassar o fim da antiga para existir uma faixa exclusiva do filtro novo.",
    `OLD_RANGE_END=${OLD_WINDOW_BASE + OLD_WINDOW_SPREAD - 1}`,
    `NEW_RANGE_END=${NEW_WINDOW_BASE + NEW_WINDOW_SPREAD - 1}`,
  ].join(" ")
);
assert(
  OUTSIDE_WINDOW_START < OLD_WINDOW_BASE ||
    OUTSIDE_WINDOW_START > Math.max(OLD_WINDOW_BASE + OLD_WINDOW_SPREAD - 1, NEW_WINDOW_BASE + NEW_WINDOW_SPREAD - 1),
  [
    "OUTSIDE_WINDOW_START deve ficar fora das duas faixas para demonstrar o caso sem candidatos.",
    `OLD_RANGE=[${OLD_WINDOW_BASE}, ${OLD_WINDOW_BASE + OLD_WINDOW_SPREAD - 1}]`,
    `NEW_RANGE=[${NEW_WINDOW_BASE}, ${NEW_WINDOW_BASE + NEW_WINDOW_SPREAD - 1}]`,
    `OUTSIDE_WINDOW_START=${OUTSIDE_WINDOW_START}`,
  ].join(" ")
);

function parsePositiveInt(name, rawValue, fallback) {
  if (rawValue == null || rawValue === "") return fallback;
  const value = Number(rawValue);
  assert(Number.isInteger(value) && value > 0, `${name} deve ser inteiro positivo, veio: ${rawValue}`);
  return value;
}

function parseInteger(name, rawValue, fallback) {
  if (rawValue == null || rawValue === "") return fallback;
  const value = Number(rawValue);
  assert(Number.isInteger(value), `${name} deve ser inteiro, veio: ${rawValue}`);
  return value;
}

function rotationThreshold(capacityLimit, percent) {
  return Math.floor((capacityLimit * percent + 99) / 100);
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

function makeWindowStarts(base, spread, startIndex, count) {
  return Array.from({ length: count }, (_, idx) => base + ((startIndex + idx) % spread));
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

async function writeRevocationsV2(keys, windowStarts, reason, filterId) {
  const payload = {
    revocation_keys: keys,
    window_starts: windowStarts,
    requested_by: REQUESTED_BY,
    reason,
  };
  if (filterId) payload.filter_id = filterId;

  const resp = await fetch(`${BFILTER_BASE_URL}/admin/revocations/v2`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${BFILTER_ADMIN_TOKEN}`,
    },
    body: JSON.stringify(payload),
  });
  const body = await readJsonResponse(resp, "POST /admin/revocations/v2");
  assert(resp.ok, `Falha POST /admin/revocations/v2: ${resp.status} ${JSON.stringify(body)}`);
  assert(body && body.ok === true, "resposta de revogacao deveria retornar ok=true");
  return body;
}

async function getCandidateFilters(windowStart) {
  const resp = await fetch(`${BFILTER_BASE_URL}/filters/for-window/${windowStart}`);
  const body = await readJsonResponse(resp, "GET /filters/for-window/:window_start");
  assert(resp.ok, `Falha GET /filters/for-window/${windowStart}: ${resp.status} ${JSON.stringify(body)}`);
  assert(body && body.ok === true, "filters/for-window deveria retornar ok=true");
  assert(Array.isArray(body.filters), "filters/for-window deveria retornar filters");
  return body;
}

async function checkKeysByWindow(windowStart, keys) {
  const resp = await fetch(`${BFILTER_BASE_URL}/check`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      window_start: windowStart,
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

async function writeWindowedKeys(targetFilterId, keyPrefix, totalKeys, windowBase, windowSpread, reasonPrefix) {
  const allKeys = [];
  const allWindowStarts = [];
  let written = 0;
  let batchNo = 0;

  while (written < totalKeys) {
    batchNo += 1;
    const batchSize = Math.min(INSERT_BATCH_SIZE, totalKeys - written);
    const keys = makeKeys(keyPrefix, written, batchSize);
    const windowStarts = makeWindowStarts(windowBase, windowSpread, written, batchSize);
    const body = await writeRevocationsV2(
      keys,
      windowStarts,
      `${reasonPrefix}-batch-${batchNo}`,
      targetFilterId
    );

    allKeys.push(...keys);
    allWindowStarts.push(...windowStarts);
    written += batchSize;

    if (batchNo === 1 || written === totalKeys || batchNo % 10 === 0) {
      console.log(`Insercao ${reasonPrefix} lote ${batchNo}:`, {
        batch_size: batchSize,
        written_total: written,
        target_total: totalKeys,
        filter_id: body.filter_id,
      });
    }
  }

  return {
    keys: allKeys,
    windowStarts: allWindowStarts,
  };
}

(async () => {
  const runId = `${Date.now()}-${process.pid}`;

  console.log("============================================================");
  console.log("MANUAL WINDOW_START OVERLAP ROUTING");
  console.log("Config:", {
    BFILTER_BASE_URL,
    BFILTER_ROTATE_AT_PERCENT,
    TEST_FILTER_M_BITS,
    TEST_K,
    INSERT_BATCH_SIZE,
    OLD_WINDOW_BASE,
    OLD_WINDOW_SPREAD,
    NEW_WINDOW_BASE,
    NEW_WINDOW_SPREAD,
    OUTSIDE_WINDOW_START,
    adminToken: "***",
  });
  console.log("============================================================");

  const manifestAfterReset = await resetFiltersForTest(TEST_FILTER_M_BITS, TEST_K);
  const firstActive = getActiveFilter(manifestAfterReset);
  const rotateThreshold = rotationThreshold(firstActive.capacity_limit, BFILTER_ROTATE_AT_PERCENT);

  console.log("Filtro ativo limpo apos reset:", {
    filter_id: firstActive.filter_id,
    status: firstActive.status,
    inserted_count: firstActive.inserted_count,
    capacity_limit: firstActive.capacity_limit,
    rotate_threshold: rotateThreshold,
    m_bits: firstActive.m_bits,
    k: firstActive.k,
  });

  assert(rotateThreshold >= 1, `rotate_threshold deveria ser >= 1, veio ${rotateThreshold}`);

  const oldData = await writeWindowedKeys(
    firstActive.filter_id,
    `window-overlap-old-${runId}`,
    rotateThreshold,
    OLD_WINDOW_BASE,
    OLD_WINDOW_SPREAD,
    "old-overlap-fill"
  );

  const manifestAfterFirstFill = await getManifest();
  const oldFilter = getFilterById(manifestAfterFirstFill, firstActive.filter_id);
  const newActive = getActiveFilter(manifestAfterFirstFill);

  assert(oldFilter.status === "closed", `Filtro antigo deveria estar closed, veio ${oldFilter.status}`);
  assert(oldFilter.closed_at, "Filtro antigo deveria ter closed_at apos rotacao");
  assert(
    newActive.filter_id !== oldFilter.filter_id,
    "A rotacao deveria abrir um novo filtro ativo apos fechar o filtro antigo"
  );

  const oldRangeEnd = OLD_WINDOW_BASE + OLD_WINDOW_SPREAD - 1;
  const firstNewOnlyWindow = oldRangeEnd + 1;
  const minKeysToReachNewOnlyWindow = firstNewOnlyWindow - NEW_WINDOW_BASE + 1;
  const newWriteCount = Math.max(5, minKeysToReachNewOnlyWindow);
  assert(
    newWriteCount < rotateThreshold,
    [
      "A quantidade minima de escritas para atingir a faixa exclusiva do filtro novo nao pode disparar nova rotacao.",
      `new_write_count=${newWriteCount}`,
      `rotate_threshold=${rotateThreshold}`,
    ].join(" ")
  );

  const newData = await writeWindowedKeys(
    newActive.filter_id,
    `window-overlap-new-${runId}`,
    newWriteCount,
    NEW_WINDOW_BASE,
    NEW_WINDOW_SPREAD,
    "new-overlap-fill"
  );

  const manifestAfterAllWrites = await getManifest();
  const oldFilterAfterAllWrites = getFilterById(manifestAfterAllWrites, oldFilter.filter_id);
  const activeAfterAllWrites = getActiveFilter(manifestAfterAllWrites);

  assert(
    activeAfterAllWrites.filter_id === newActive.filter_id,
    "O filtro ativo nao deveria mudar apos a segunda escrita"
  );
  assert(oldFilterAfterAllWrites.window_start_min != null, "Filtro antigo deveria ter window_start_min");
  assert(oldFilterAfterAllWrites.window_start_max != null, "Filtro antigo deveria ter window_start_max");
  assert(activeAfterAllWrites.window_start_min != null, "Filtro novo deveria ter window_start_min");
  assert(activeAfterAllWrites.window_start_max != null, "Filtro novo deveria ter window_start_max");

  const overlapStart = Math.max(oldFilterAfterAllWrites.window_start_min, activeAfterAllWrites.window_start_min);
  const overlapEnd = Math.min(oldFilterAfterAllWrites.window_start_max, activeAfterAllWrites.window_start_max);
  assert(overlapStart <= overlapEnd, `As faixas deveriam se sobrepor, veio [${overlapStart}, ${overlapEnd}]`);
  const overlapProbeWindow = overlapStart;

  const oldOnlyWindow = oldFilterAfterAllWrites.window_start_min;
  const newOnlyWindow = activeAfterAllWrites.window_start_max;

  const candidatesOverlap = await getCandidateFilters(overlapProbeWindow);
  const candidatesOldOnly = await getCandidateFilters(oldOnlyWindow);
  const candidatesNewOnly = await getCandidateFilters(newOnlyWindow);
  const candidatesOutside = await getCandidateFilters(OUTSIDE_WINDOW_START);

  assert(
    candidatesOverlap.filters.length === 2,
    `Janela sobreposta deveria retornar 2 filtros, veio ${candidatesOverlap.filters.length}`
  );
  assert(
    candidatesOverlap.filters[0].filter_id === activeAfterAllWrites.filter_id,
    [
      "Na ordem atual da API, o filtro ativo deve vir primeiro na sobreposicao.",
      `esperado=${activeAfterAllWrites.filter_id}`,
      `recebido=${candidatesOverlap.filters[0].filter_id}`,
    ].join(" ")
  );
  assert(
    candidatesOverlap.filters[1].filter_id === oldFilterAfterAllWrites.filter_id,
    [
      "Na ordem atual da API, o filtro fechado antigo deve vir depois do ativo.",
      `esperado=${oldFilterAfterAllWrites.filter_id}`,
      `recebido=${candidatesOverlap.filters[1].filter_id}`,
    ].join(" ")
  );
  assert(candidatesOldOnly.filters.length === 1, `Janela so-antiga deveria retornar 1 filtro, veio ${candidatesOldOnly.filters.length}`);
  assert(
    candidatesOldOnly.filters[0].filter_id === oldFilterAfterAllWrites.filter_id,
    `Janela so-antiga deveria retornar ${oldFilterAfterAllWrites.filter_id}, veio ${candidatesOldOnly.filters[0].filter_id}`
  );
  assert(candidatesNewOnly.filters.length === 1, `Janela so-nova deveria retornar 1 filtro, veio ${candidatesNewOnly.filters.length}`);
  assert(
    candidatesNewOnly.filters[0].filter_id === activeAfterAllWrites.filter_id,
    `Janela so-nova deveria retornar ${activeAfterAllWrites.filter_id}, veio ${candidatesNewOnly.filters[0].filter_id}`
  );
  assert(
    candidatesOutside.filters.length === 0,
    `Janela fora das faixas deveria retornar 0 filtros, veio ${candidatesOutside.filters.length}`
  );

  const oldKeyCheck = await checkKeysByWindow(overlapProbeWindow, [oldData.keys[0]]);
  const newKeyCheck = await checkKeysByWindow(overlapProbeWindow, [newData.keys[0]]);
  const absentKeyCheck = await checkKeysByWindow(overlapProbeWindow, [`window-overlap-absent-${runId}`]);

  const expectedFilterIdList = `${activeAfterAllWrites.filter_id},${oldFilterAfterAllWrites.filter_id}`;
  assert(
    oldKeyCheck.filter_id === expectedFilterIdList,
    `Check na sobreposicao deveria retornar filter_id=${expectedFilterIdList}, veio ${oldKeyCheck.filter_id}`
  );
  assert(
    newKeyCheck.filter_id === expectedFilterIdList,
    `Check na sobreposicao deveria retornar filter_id=${expectedFilterIdList}, veio ${newKeyCheck.filter_id}`
  );
  assert(
    absentKeyCheck.filter_id === expectedFilterIdList,
    `Check de chave ausente deveria retornar filter_id=${expectedFilterIdList}, veio ${absentKeyCheck.filter_id}`
  );
  assert(oldKeyCheck.results[0].maybe_present === true, "Chave antiga deveria continuar maybe_present=true na sobreposicao");
  assert(newKeyCheck.results[0].maybe_present === true, "Chave nova deveria continuar maybe_present=true na sobreposicao");
  assert(absentKeyCheck.results[0].maybe_present === false, "Chave ausente deveria retornar maybe_present=false na sobreposicao");

  console.log("\n============================================================");
  console.log("SOBREPOSICAO DE WINDOW_START CONFIRMADA");
  console.log("Filtro antigo fechado:", {
    filter_id: oldFilterAfterAllWrites.filter_id,
    status: oldFilterAfterAllWrites.status,
    inserted_count: oldFilterAfterAllWrites.inserted_count,
    window_start_min: oldFilterAfterAllWrites.window_start_min,
    window_start_max: oldFilterAfterAllWrites.window_start_max,
    closed_at: oldFilterAfterAllWrites.closed_at,
  });
  console.log("Filtro ativo atual:", {
    filter_id: activeAfterAllWrites.filter_id,
    status: activeAfterAllWrites.status,
    inserted_count: activeAfterAllWrites.inserted_count,
    window_start_min: activeAfterAllWrites.window_start_min,
    window_start_max: activeAfterAllWrites.window_start_max,
  });
  console.log("Consulta por janela sobreposta:", {
    overlap_probe_window: overlapProbeWindow,
    overlap_candidates: candidatesOverlap.filters.map((item) => item.filter_id),
    expected_filter_id_join: expectedFilterIdList,
  });
  console.log("============================================================");
})().catch((err) => {
  console.error(
    "FALHA NO SCRIPT MANUAL DE SOBREPOSICAO POR WINDOW_START:",
    err && err.stack ? err.stack : err
  );
  process.exit(1);
});
