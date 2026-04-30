/*
TESTE MANUAL: RESET DO FILTRO EM MODO TESTS

PARA RODAR:
1. Suba o servico com BFILTER_ENABLE_TEST_API=1.
cd /home/yugi/programacao/bfilter \
BFILTER_ENABLE_TEST_API=1 \
cargo run

2. Rode:

cd /home/yugi/programacao/bfilter
BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
BFILTER_TEST_M_BITS="16777216" \
node tests/manual_reset_test_mode.js

Opcionalmente, voce pode pedir um novo filtro com configuracao explicita:

BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
BFILTER_TEST_FILTER_ID="manual-reset-small" \
BFILTER_TEST_M_BITS="1024" \
BFILTER_TEST_K="4" \
node tests/manual_reset_test_mode.js

O que este script faz:
- consulta o manifesto atual
- chama POST /test/reset
- valida que o ambiente fica com exatamente um filtro ativo
- mostra o estado antes e depois do reset

ATENCAO:
- este script APAGA os filtros atuais via POST /test/reset
- use apenas contra um ambiente controlado de testes
*/

const BFILTER_BASE_URL = (process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080").replace(/\/+$/, "");
const BFILTER_ADMIN_TOKEN = process.env.BFILTER_ADMIN_TOKEN || "dev-admin-token";
const BFILTER_TEST_FILTER_ID = process.env.BFILTER_TEST_FILTER_ID || undefined;
const BFILTER_TEST_M_BITS = parseOptionalPositiveInt("BFILTER_TEST_M_BITS", process.env.BFILTER_TEST_M_BITS);
const BFILTER_TEST_K = parseOptionalPositiveInt("BFILTER_TEST_K", process.env.BFILTER_TEST_K);

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function parseOptionalPositiveInt(name, rawValue) {
  if (rawValue == null || rawValue === "") return undefined;
  const value = Number(rawValue);
  assert(Number.isInteger(value) && value > 0, `${name} deve ser inteiro positivo, veio: ${rawValue}`);
  return value;
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
  assert(body && body.ok === true, "manifest deveria retornar ok=true");
  return body.manifest;
}

function getActiveFilter(manifest) {
  const activeId = manifest.active_filter_id;
  const active = (manifest.filters || []).find((item) => item.filter_id === activeId);
  assert(active, `Filtro ativo nao encontrado no manifesto: ${activeId}`);
  return active;
}

async function resetFiltersForTest() {
  const payload = {};
  if (BFILTER_TEST_FILTER_ID) payload.filter_id = BFILTER_TEST_FILTER_ID;
  if (BFILTER_TEST_M_BITS != null) payload.m_bits = BFILTER_TEST_M_BITS;
  if (BFILTER_TEST_K != null) payload.k = BFILTER_TEST_K;

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
  assert(body.active_filter, "reset deveria retornar active_filter");
  return body;
}

(async () => {
  console.log("============================================================");
  console.log("MANUAL TEST RESET MODE");
  console.log("Config:", {
    BFILTER_BASE_URL,
    adminToken: "***",
    BFILTER_TEST_FILTER_ID: BFILTER_TEST_FILTER_ID || null,
    BFILTER_TEST_M_BITS: BFILTER_TEST_M_BITS ?? null,
    BFILTER_TEST_K: BFILTER_TEST_K ?? null,
  });
  console.log("============================================================");

  const manifestBefore = await getManifest();
  const activeBefore = getActiveFilter(manifestBefore);

  console.log("Antes do reset:", {
    active_filter_id: manifestBefore.active_filter_id,
    total_filters: (manifestBefore.filters || []).length,
    active_filter: {
      filter_id: activeBefore.filter_id,
      status: activeBefore.status,
      inserted_count: activeBefore.inserted_count,
      m_bits: activeBefore.m_bits,
      k: activeBefore.k,
    },
  });

  const resetBody = await resetFiltersForTest();
  const manifestAfter = resetBody.manifest;
  const activeAfter = resetBody.active_filter;

  assert(Array.isArray(manifestAfter.filters), "manifest.filters deveria ser array");
  assert(manifestAfter.filters.length === 1, `reset deveria deixar exatamente 1 filtro, veio ${manifestAfter.filters.length}`);
  assert(manifestAfter.active_filter_id === activeAfter.filter_id, "active_filter_id deveria apontar para o filtro retornado");
  assert(activeAfter.status === "active", `filtro retornado deveria estar active, veio ${activeAfter.status}`);
  assert(Number(activeAfter.inserted_count || 0) === 0, "filtro apos reset deveria iniciar com inserted_count=0");
  if (BFILTER_TEST_FILTER_ID) {
    assert(
      activeAfter.filter_id === BFILTER_TEST_FILTER_ID,
      `filter_id apos reset deveria ser ${BFILTER_TEST_FILTER_ID}, veio ${activeAfter.filter_id}`
    );
  }
  if (BFILTER_TEST_M_BITS != null) {
    assert(activeAfter.m_bits === BFILTER_TEST_M_BITS, `m_bits apos reset deveria ser ${BFILTER_TEST_M_BITS}, veio ${activeAfter.m_bits}`);
  }
  if (BFILTER_TEST_K != null) {
    assert(activeAfter.k === BFILTER_TEST_K, `k apos reset deveria ser ${BFILTER_TEST_K}, veio ${activeAfter.k}`);
  }

  console.log("\n============================================================");
  console.log("RESET CONFIRMADO");
  console.log("Depois do reset:", {
    active_filter_id: manifestAfter.active_filter_id,
    total_filters: manifestAfter.filters.length,
    active_filter: {
      filter_id: activeAfter.filter_id,
      status: activeAfter.status,
      inserted_count: activeAfter.inserted_count,
      m_bits: activeAfter.m_bits,
      k: activeAfter.k,
      file_name: activeAfter.file_name,
    },
  });
  console.log("============================================================");
})().catch((err) => {
  console.error("FALHA NO SCRIPT MANUAL DE RESET:", err && err.stack ? err.stack : err);
  process.exit(1);
});
