/*
TESTE MANUAL: ROTEAMENTO POR WINDOW_START

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
OLD_WINDOW_SPREAD="17" \
NEW_WINDOW_BASE="1700100000" \
NEW_WINDOW_SPREAD="11" \
OUTSIDE_WINDOW_START="1700200000" \
node tests/manual_window_start_routing.js

O que este script faz:
- reseta a instancia de testes para um filtro pequeno e limpo
- preenche o primeiro filtro ate o limiar de rotacao usando window_starts antigos
- confirma que esse filtro fecha e que a faixa temporal dele foi registrada
- escreve novas chaves no novo filtro ativo com outra faixa temporal
- valida GET /filters/for-window/:window_start para janela antiga, nova e sem candidatos
- valida POST /check com window_start e o fallback para o filtro ativo quando nao ha candidatos

Uso recomendado:
- validacao funcional da semantica de janelas temporais
- regressao do roteamento por window_start
- confirmacao de integracao entre /admin/revocations/v2, /filters/for-window e /check

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
const TEST_FILTER_M_BITS = parsePositiveInt("TEST_FILTER_M_BITS", process.env.TEST_FILTER_M_BITS, 1024);
const TEST_K = parsePositiveInt("TEST_K", process.env.TEST_K, 4);
const INSERT_BATCH_SIZE = parsePositiveInt("INSERT_BATCH_SIZE", process.env.INSERT_BATCH_SIZE, 1000);
const OLD_WINDOW_BASE = parseInteger("OLD_WINDOW_BASE", process.env.OLD_WINDOW_BASE, 1700000000);
const OLD_WINDOW_SPREAD = parsePositiveInt("OLD_WINDOW_SPREAD", process.env.OLD_WINDOW_SPREAD, 17);
const NEW_WINDOW_BASE = parseInteger("NEW_WINDOW_BASE", process.env.NEW_WINDOW_BASE, 1700100000);
const NEW_WINDOW_SPREAD = parsePositiveInt("NEW_WINDOW_SPREAD", process.env.NEW_WINDOW_SPREAD, 11);
const OUTSIDE_WINDOW_START = parseInteger(
  "OUTSIDE_WINDOW_START",
  process.env.OUTSIDE_WINDOW_START,
  1700200000
);
const REQUESTED_BY = "manual-window-start-routing";

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

assert(
  BFILTER_ROTATE_AT_PERCENT >= 1 && BFILTER_ROTATE_AT_PERCENT <= 100,
  `BFILTER_ROTATE_AT_PERCENT deve ficar entre 1 e 100, veio: ${BFILTER_ROTATE_AT_PERCENT}`
);
assert(
  NEW_WINDOW_BASE >= OLD_WINDOW_BASE + OLD_WINDOW_SPREAD,
  [
    "NEW_WINDOW_BASE deve ser maior do que a faixa antiga para evitar sobreposicao acidental.",
    `OLD_WINDOW_BASE=${OLD_WINDOW_BASE}`,
    `OLD_WINDOW_SPREAD=${OLD_WINDOW_SPREAD}`,
    `NEW_WINDOW_BASE=${NEW_WINDOW_BASE}`,
  ].join(" ")
);
assert(
  OUTSIDE_WINDOW_START < OLD_WINDOW_BASE || OUTSIDE_WINDOW_START >= NEW_WINDOW_BASE + NEW_WINDOW_SPREAD,
  [
    "OUTSIDE_WINDOW_START deve ficar fora das duas faixas para demonstrar o fallback.",
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
  console.log("MANUAL WINDOW_START ROUTING");
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
    `window-old-${runId}`,
    rotateThreshold,
    OLD_WINDOW_BASE,
    OLD_WINDOW_SPREAD,
    "old-window-fill"
  );

  const manifestAfterOldRange = await getManifest();
  const oldFilter = getFilterById(manifestAfterOldRange, firstActive.filter_id);
  const newActive = getActiveFilter(manifestAfterOldRange);

  assert(oldFilter.status === "closed", `Filtro antigo deveria estar closed, veio ${oldFilter.status}`);
  assert(Number(oldFilter.inserted_count) === rotateThreshold, `Filtro antigo deveria ter inserted_count=${rotateThreshold}, veio ${oldFilter.inserted_count}`);
  assert(oldFilter.closed_at, "Filtro antigo deveria ter closed_at apos rotacao");
  assert(
    newActive.filter_id !== oldFilter.filter_id,
    "A rotacao deveria abrir um novo filtro ativo apos fechar o filtro antigo"
  );
  assert(Number(newActive.inserted_count || 0) === 0, "Novo filtro deveria iniciar vazio");
  assert(
    oldFilter.window_start_min === Math.min(...oldData.windowStarts),
    `window_start_min do filtro antigo deveria ser ${Math.min(...oldData.windowStarts)}, veio ${oldFilter.window_start_min}`
  );
  assert(
    oldFilter.window_start_max === Math.max(...oldData.windowStarts),
    `window_start_max do filtro antigo deveria ser ${Math.max(...oldData.windowStarts)}, veio ${oldFilter.window_start_max}`
  );

  const newData = await writeWindowedKeys(
    newActive.filter_id,
    `window-new-${runId}`,
    Math.min(3, rotateThreshold),
    NEW_WINDOW_BASE,
    NEW_WINDOW_SPREAD,
    "new-window-fill"
  );

  const manifestAfterNewRange = await getManifest();
  const oldFilterAfterAllWrites = getFilterById(manifestAfterNewRange, oldFilter.filter_id);
  const activeAfterNewWrites = getActiveFilter(manifestAfterNewRange);

  assert(
    activeAfterNewWrites.filter_id === newActive.filter_id,
    "O filtro ativo nao deveria mudar apos a segunda escrita"
  );
  assert(
    Number(activeAfterNewWrites.inserted_count) === newData.keys.length,
    `Novo filtro deveria ter inserted_count=${newData.keys.length}, veio ${activeAfterNewWrites.inserted_count}`
  );
  assert(
    activeAfterNewWrites.window_start_min === Math.min(...newData.windowStarts),
    [
      "window_start_min do novo filtro nao bate com os dados inseridos.",
      `esperado=${Math.min(...newData.windowStarts)}`,
      `recebido=${activeAfterNewWrites.window_start_min}`,
    ].join(" ")
  );
  assert(
    activeAfterNewWrites.window_start_max === Math.max(...newData.windowStarts),
    [
      "window_start_max do novo filtro nao bate com os dados inseridos.",
      `esperado=${Math.max(...newData.windowStarts)}`,
      `recebido=${activeAfterNewWrites.window_start_max}`,
    ].join(" ")
  );
  assert(
    oldFilterAfterAllWrites.window_start_min === oldFilter.window_start_min &&
      oldFilterAfterAllWrites.window_start_max === oldFilter.window_start_max,
    "A faixa temporal do filtro antigo nao deveria mudar apos escrever no novo filtro"
  );

  const oldProbeWindow = oldData.windowStarts[Math.floor(oldData.windowStarts.length / 2)];
  const newProbeWindow = newData.windowStarts[Math.floor(newData.windowStarts.length / 2)];

  const candidatesOld = await getCandidateFilters(oldProbeWindow);
  const candidatesNew = await getCandidateFilters(newProbeWindow);
  const candidatesOutside = await getCandidateFilters(OUTSIDE_WINDOW_START);

  assert(candidatesOld.filters.length === 1, `Janela antiga deveria retornar 1 filtro, veio ${candidatesOld.filters.length}`);
  assert(
    candidatesOld.filters[0].filter_id === oldFilter.filter_id,
    `Janela antiga deveria retornar ${oldFilter.filter_id}, veio ${candidatesOld.filters[0].filter_id}`
  );
  assert(candidatesNew.filters.length === 1, `Janela nova deveria retornar 1 filtro, veio ${candidatesNew.filters.length}`);
  assert(
    candidatesNew.filters[0].filter_id === activeAfterNewWrites.filter_id,
    `Janela nova deveria retornar ${activeAfterNewWrites.filter_id}, veio ${candidatesNew.filters[0].filter_id}`
  );
  assert(
    candidatesOutside.filters.length === 0,
    `Janela fora das faixas deveria retornar 0 filtros, veio ${candidatesOutside.filters.length}`
  );

  const checkOld = await checkKeysByWindow(oldProbeWindow, [oldData.keys[0]]);
  const checkNew = await checkKeysByWindow(newProbeWindow, [newData.keys[0]]);
  const checkFallback = await checkKeysByWindow(OUTSIDE_WINDOW_START, [newData.keys[0]]);

  assert(
    checkOld.filter_id === oldFilter.filter_id,
    `Check da janela antiga deveria usar ${oldFilter.filter_id}, veio ${checkOld.filter_id}`
  );
  assert(checkOld.results[0].maybe_present === true, "Chave antiga deveria aparecer como maybe_present=true");
  assert(
    checkNew.filter_id === activeAfterNewWrites.filter_id,
    `Check da janela nova deveria usar ${activeAfterNewWrites.filter_id}, veio ${checkNew.filter_id}`
  );
  assert(checkNew.results[0].maybe_present === true, "Chave nova deveria aparecer como maybe_present=true");
  assert(
    checkFallback.filter_id === activeAfterNewWrites.filter_id,
    [
      "Sem candidatos para a janela, /check deveria cair no filtro ativo.",
      `esperado=${activeAfterNewWrites.filter_id}`,
      `recebido=${checkFallback.filter_id}`,
    ].join(" ")
  );
  assert(
    checkFallback.results[0].maybe_present === true,
    "No fallback para o filtro ativo, a chave do novo filtro deveria continuar maybe_present=true"
  );

  console.log("\n============================================================");
  console.log("ROTEAMENTO POR WINDOW_START CONFIRMADO");
  console.log("Filtro antigo fechado:", {
    filter_id: oldFilter.filter_id,
    status: oldFilter.status,
    inserted_count: oldFilter.inserted_count,
    window_start_min: oldFilter.window_start_min,
    window_start_max: oldFilter.window_start_max,
    closed_at: oldFilter.closed_at,
  });
  console.log("Filtro ativo atual:", {
    filter_id: activeAfterNewWrites.filter_id,
    status: activeAfterNewWrites.status,
    inserted_count: activeAfterNewWrites.inserted_count,
    window_start_min: activeAfterNewWrites.window_start_min,
    window_start_max: activeAfterNewWrites.window_start_max,
  });
  console.log("Consulta por janela:", {
    old_probe_window: oldProbeWindow,
    old_candidates: candidatesOld.filters.map((item) => item.filter_id),
    new_probe_window: newProbeWindow,
    new_candidates: candidatesNew.filters.map((item) => item.filter_id),
    outside_window_start: OUTSIDE_WINDOW_START,
    outside_candidates: candidatesOutside.filters.map((item) => item.filter_id),
    fallback_filter_id: checkFallback.filter_id,
  });
  console.log("============================================================");
})().catch((err) => {
  console.error(
    "FALHA NO SCRIPT MANUAL DE ROTEAMENTO POR WINDOW_START:",
    err && err.stack ? err.stack : err
  );
  process.exit(1);
});
