/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
node teste-node/revocation/test_revocation_55_bloom_saturation_zero_bytes_table_von.js

Para subir o bfilter em modo de testes:
cd /home/yugi/programacao/bfilter
BFILTER_ENABLE_TEST_API=1 \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
cargo run

ENV OPCIONAIS:
- BATCH_SIZE=1000           -> lote fixo de entradas por escrita
- INTERVAL_PERCENT=5        -> intervalo da tabela resumida
- TARGET_CLOSE_PERCENT=95   -> percentual-alvo de fechamento
- TEST_FILTER_M_BITS=32768  -> reseta com filtro menor para rodadas mais rápidas
*/

/*
Teste manual de saturação do Bloom Filter com foco nos bytes "00" restantes.

Objetivo:
- resetar o Bloom Filter para um estado limpo;
- preencher o filtro em lotes de 1000 entradas;
- contar, a cada etapa relevante, quantos bytes 0x00 ainda restam no filtro;
- montar uma tabela resumida de 5% em 5% até o ponto de fechamento automático;
- capturar a margem final de bytes 0x00 quando o filtro atinge 95% da capacidade.

Observações:
- o teste usa a API administrativa do bfilter;
- o histórico completo por lote fica salvo em JSON;
- a tabela resumida também fica salva em Markdown para consulta rápida.
*/

const fs = require("fs");
const path = require("path");

const BFILTER_BASE_URL = (process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080").replace(/\/+$/, "");
const BFILTER_ADMIN_TOKEN = process.env.BFILTER_ADMIN_TOKEN || "dev-admin-token";
const BATCH_SIZE = Number(process.env.BATCH_SIZE || "1000");
const INTERVAL_PERCENT = Number(process.env.INTERVAL_PERCENT || "5");
const TARGET_CLOSE_PERCENT = Number(process.env.TARGET_CLOSE_PERCENT || "95");
const TEST_FILTER_M_BITS = process.env.TEST_FILTER_M_BITS ? Number(process.env.TEST_FILTER_M_BITS) : null;
const FILTER_HEADER_BYTES = 16;

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function mkdirp(p) {
  fs.mkdirSync(p, { recursive: true });
}

function nowIso() {
  return new Date().toISOString();
}

function rotationThreshold(capacityLimit, percent) {
  return Math.floor((Number(capacityLimit) * Number(percent) + 99) / 100);
}

function percentOf(value, total) {
  if (!Number(total)) return 0;
  return (Number(value) / Number(total)) * 100;
}

function formatPercent(value) {
  return `${Number(value).toFixed(2)}%`;
}

function formatInt(value) {
  return Number(value).toLocaleString("pt-BR");
}

function makeThresholdPercents(intervalPercent, targetPercent) {
  const items = [0];
  for (let pct = intervalPercent; pct <= targetPercent; pct += intervalPercent) {
    items.push(pct);
  }
  if (items[items.length - 1] !== targetPercent) {
    items.push(targetPercent);
  }
  return items;
}

function normalizeUrl(baseUrl, maybeRelativePath) {
  if (!maybeRelativePath) return null;
  if (/^https?:\/\//i.test(maybeRelativePath)) return maybeRelativePath;
  return `${baseUrl}${maybeRelativePath.startsWith("/") ? "" : "/"}${maybeRelativePath}`;
}

async function readJsonResponse(resp, context) {
  const text = await resp.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch (err) {
    throw new Error(`${context}: resposta não é JSON válido: ${text}`);
  }
  return body;
}

async function fetchManifestEnvelope(baseUrl) {
  const resp = await fetch(`${baseUrl}/manifest`);
  const body = await readJsonResponse(resp, "GET /manifest");
  assert(resp.ok, `Falha GET /manifest: ${resp.status} ${JSON.stringify(body)}`);
  assert(body && body.ok === true, "manifesto deveria retornar ok=true");
  return body;
}

function getFilterById(manifestEnvelope, filterId) {
  const manifest = manifestEnvelope.manifest || {};
  const filters = Array.isArray(manifest.filters) ? manifest.filters : [];
  const filter = filters.find((item) => item.filter_id === filterId);
  assert(filter, `Filtro não encontrado no manifesto: ${filterId}`);
  return filter;
}

function getActiveFilter(manifestEnvelope) {
  return getFilterById(manifestEnvelope, manifestEnvelope.manifest.active_filter_id);
}

async function resetBfilterForSaturation(baseUrl, adminToken, testMBits) {
  const payload = testMBits
    ? {
        filter_id: `test-saturation-${Date.now()}`,
        m_bits: testMBits,
      }
    : {};

  const resp = await fetch(`${baseUrl}/test/reset`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${adminToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  const body = await readJsonResponse(resp, "POST /test/reset");
  if (resp.status === 404) {
    throw new Error(
      "O endpoint /test/reset não está disponível. Suba o bfilter com BFILTER_ENABLE_TEST_API=1."
    );
  }

  assert(resp.ok, `Falha POST /test/reset: ${resp.status} ${JSON.stringify(body)}`);
  assert(body && body.ok === true, "reset do bfilter deveria retornar ok=true");
  assert(body.manifest, "reset deveria retornar manifest");
  return body;
}

async function writeDummyRevocations({ baseUrl, adminToken, runId, batchNo, count }) {
  const revocationKeys = Array.from({ length: count }, (_, idx) =>
    `sat-zero-bytes-${runId}-${String(batchNo).padStart(4, "0")}-${String(idx).padStart(4, "0")}`
  );

  const resp = await fetch(`${baseUrl}/admin/revocations/v2`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${adminToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      revocation_keys: revocationKeys,
      requested_by: "teste-node-revocation-55",
      reason: "fill-bloom-and-measure-zero-bytes",
    }),
  });

  const body = await readJsonResponse(resp, "POST /admin/revocations/v2");
  assert(resp.ok, `Falha POST /admin/revocations/v2: ${resp.status} ${JSON.stringify(body)}`);
  assert(body && body.ok === true, "escrita dummy no Bloom deveria retornar ok=true");
  return body;
}

async function fetchFilterBuffer(baseUrl, filterId) {
  const resp = await fetch(`${baseUrl}/filters/${encodeURIComponent(filterId)}`);
  const body = await readJsonResponse(resp, `GET /filters/${filterId}`);
  assert(resp.ok, `Falha GET /filters/${filterId}: ${resp.status} ${JSON.stringify(body)}`);
  assert(body && body.ok === true, `filtro ${filterId} deveria retornar ok=true`);
  assert(typeof body.bloom_base64 === "string" && body.bloom_base64.length > 0, "bloom_base64 ausente");
  const rawBuffer = Buffer.from(body.bloom_base64, "base64");
  assert(
    rawBuffer.length >= FILTER_HEADER_BYTES,
    `filtro serializado deveria ter ao menos ${FILTER_HEADER_BYTES} bytes`
  );

  const mBitsFromHeader = Number(rawBuffer.readBigUInt64LE(0));
  const kFromHeader = Number(rawBuffer.readBigUInt64LE(8));
  const payloadBuffer = rawBuffer.subarray(FILTER_HEADER_BYTES);

  return {
    rawBuffer,
    payloadBuffer,
    meta: body.meta || {},
    download_url: normalizeUrl(baseUrl, body.meta?.download_url || null),
    header: {
      m_bits: mBitsFromHeader,
      k: kFromHeader,
    },
  };
}

function countZeroBytes(buffer) {
  let zeroBytes = 0;
  for (const byte of buffer) {
    if (byte === 0) zeroBytes += 1;
  }
  return zeroBytes;
}

async function captureState(baseUrl, filterId, batchNo, totalKeysRequested) {
  const manifestEnvelope = await fetchManifestEnvelope(baseUrl);
  const filterMeta = getFilterById(manifestEnvelope, filterId);
  const filterPayload = await fetchFilterBuffer(baseUrl, filterId);
  const totalBytes = filterPayload.payloadBuffer.length;
  const serializedTotalBytes = filterPayload.rawBuffer.length;
  const expectedBytes = Math.ceil(Number(filterMeta.m_bits || 0) / 8);
  assert(
    totalBytes === expectedBytes,
    `Tamanho do filtro em bytes diverge: esperado ${expectedBytes}, recebido ${totalBytes}`
  );
  assert(
    Number(filterMeta.m_bits || 0) === filterPayload.header.m_bits,
    `m_bits no header diverge do manifesto: ${filterPayload.header.m_bits} vs ${filterMeta.m_bits}`
  );
  assert(
    Number(filterMeta.k || 0) === filterPayload.header.k,
    `k no header diverge do manifesto: ${filterPayload.header.k} vs ${filterMeta.k}`
  );

  const zeroBytesRemaining = countZeroBytes(filterPayload.payloadBuffer);
  const nonZeroBytes = totalBytes - zeroBytesRemaining;
  const insertedCount = Number(filterMeta.inserted_count || 0);
  const capacityLimit = Number(filterMeta.capacity_limit || 0);

  return {
    batch_no: batchNo,
    total_keys_requested: totalKeysRequested,
    filter_id: filterId,
    filter_status: String(filterMeta.status || ""),
    inserted_count: insertedCount,
    capacity_limit: capacityLimit,
    load_percent: percentOf(insertedCount, capacityLimit),
    total_bytes: totalBytes,
    serialized_total_bytes: serializedTotalBytes,
    zero_bytes_remaining: zeroBytesRemaining,
    zero_bytes_remaining_percent: percentOf(zeroBytesRemaining, totalBytes),
    non_zero_bytes: nonZeroBytes,
    m_bits: Number(filterMeta.m_bits || 0),
    k: Number(filterMeta.k || 0),
    download_url: filterPayload.download_url,
    manifest_active_filter_id: manifestEnvelope.manifest.active_filter_id,
    captured_at: nowIso(),
  };
}

function buildThresholdRows(statesByThreshold, thresholdPercents, capacityLimit) {
  return thresholdPercents.map((thresholdPercent) => {
    const row = statesByThreshold.get(thresholdPercent);
    return {
      threshold_percent: thresholdPercent,
      threshold_inserted_count: rotationThreshold(capacityLimit, thresholdPercent),
      observed_inserted_count: row ? row.inserted_count : null,
      observed_load_percent: row ? row.load_percent : null,
      zero_bytes_remaining: row ? row.zero_bytes_remaining : null,
      zero_bytes_remaining_percent: row ? row.zero_bytes_remaining_percent : null,
      total_bytes: row ? row.total_bytes : null,
      filter_status: row ? row.filter_status : "n/a",
      batch_no: row ? row.batch_no : null,
    };
  });
}

function padCell(value, width, align) {
  const raw = String(value);
  if (raw.length >= width) return raw;
  if (align === "right") return `${" ".repeat(width - raw.length)}${raw}`;
  return `${raw}${" ".repeat(width - raw.length)}`;
}
function formatThresholdTableRows(rows) {
  return rows.map((row) => ({
    faixa: `${row.threshold_percent}%`,
    alvo: formatInt(row.threshold_inserted_count),
    observado: row.observed_inserted_count == null ? "-" : formatInt(row.observed_inserted_count),
    carga: row.observed_load_percent == null ? "-" : formatPercent(row.observed_load_percent),
    bytes_00: row.zero_bytes_remaining == null ? "-" : formatInt(row.zero_bytes_remaining),
    pct_00: row.zero_bytes_remaining_percent == null ? "-" : formatPercent(row.zero_bytes_remaining_percent),
    status: row.filter_status,
    lote: row.batch_no == null ? "-" : formatInt(row.batch_no),
  }));
}

function renderPrettyTable(rows) {
  const columns = [
    { key: "faixa", title: "Faixa", align: "right" },
    { key: "alvo", title: "Alvo", align: "right" },
    { key: "observado", title: "Observado", align: "right" },
    { key: "carga", title: "Carga", align: "right" },
    { key: "bytes_00", title: "Bytes 00", align: "right" },
    { key: "pct_00", title: "% 00", align: "right" },
    { key: "status", title: "Status", align: "left" },
    { key: "lote", title: "Lote", align: "right" },
  ];

  const formattedRows = formatThresholdTableRows(rows);
  const widths = columns.map((column) => {
    const values = formattedRows.map((row) => String(row[column.key]));
    return Math.max(column.title.length, ...values.map((value) => value.length));
  });

  const horizontal = `+${widths.map((width) => "-".repeat(width + 2)).join("+")}+`;
  const header = `| ${columns
    .map((column, idx) => padCell(column.title, widths[idx], column.align))
    .join(" | ")} |`;
  const body = formattedRows.map((row) =>
    `| ${columns
      .map((column, idx) => padCell(row[column.key], widths[idx], column.align))
      .join(" | ")} |`
  );

  return [horizontal, header, horizontal, ...body, horizontal].join("\n");
}

function renderMarkdownTable(prettyTable) {
  return ["```text", prettyTable, "```"].join("\n");
}

(async () => {
  assert(Number.isInteger(BATCH_SIZE) && BATCH_SIZE > 0, "BATCH_SIZE deve ser inteiro positivo");
  assert(Number.isInteger(INTERVAL_PERCENT) && INTERVAL_PERCENT > 0, "INTERVAL_PERCENT deve ser inteiro positivo");
  assert(
    Number.isInteger(TARGET_CLOSE_PERCENT) && TARGET_CLOSE_PERCENT >= INTERVAL_PERCENT && TARGET_CLOSE_PERCENT <= 100,
    "TARGET_CLOSE_PERCENT deve ser inteiro entre INTERVAL_PERCENT e 100"
  );
  if (TEST_FILTER_M_BITS != null) {
    assert(Number.isInteger(TEST_FILTER_M_BITS) && TEST_FILTER_M_BITS > 0, "TEST_FILTER_M_BITS inválido");
  }

  const runId = `${Date.now()}_${process.pid}`;
  const outDir = path.join(__dirname, "out");
  mkdirp(outDir);

  const reportJsonFile = path.join(outDir, `revocation_55_bloom_zero_bytes_${runId}.json`);
  const reportMdFile = path.join(outDir, `revocation_55_bloom_zero_bytes_${runId}.md`);

  console.log("============================================================");
  console.log("🧪 TESTE REVOGAÇÃO 55: saturação do Bloom + bytes 00 remanescentes");
  console.log("Config:", {
    BFILTER_BASE_URL,
    BATCH_SIZE,
    INTERVAL_PERCENT,
    TARGET_CLOSE_PERCENT,
    TEST_FILTER_M_BITS,
    adminToken: "***",
  });
  console.log("============================================================");

  console.log("1) Resetando o bfilter em modo de testes...");
  const resetResponse = await resetBfilterForSaturation(BFILTER_BASE_URL, BFILTER_ADMIN_TOKEN, TEST_FILTER_M_BITS);
  const manifestAfterReset = { ok: true, manifest: resetResponse.manifest };
  const initialFilter = getActiveFilter(manifestAfterReset);
  const initialFilterId = initialFilter.filter_id;
  const targetThreshold = rotationThreshold(initialFilter.capacity_limit, TARGET_CLOSE_PERCENT);
  const thresholdPercents = makeThresholdPercents(INTERVAL_PERCENT, TARGET_CLOSE_PERCENT);

  console.log("Filtro inicial:", {
    filter_id: initialFilter.filter_id,
    m_bits: initialFilter.m_bits,
    k: initialFilter.k,
    capacity_limit: initialFilter.capacity_limit,
    rotate_threshold: targetThreshold,
  });

  console.log("2) Capturando estado inicial do filtro...");
  const batchHistory = [];
  const statesByThreshold = new Map();

  function captureThresholdsFromState(state) {
    for (const thresholdPercent of thresholdPercents) {
      if (statesByThreshold.has(thresholdPercent)) continue;
      const thresholdInsertedCount = rotationThreshold(state.capacity_limit, thresholdPercent);
      if (state.inserted_count >= thresholdInsertedCount) {
        statesByThreshold.set(thresholdPercent, { ...state });
      }
    }
  }

  let currentState = await captureState(BFILTER_BASE_URL, initialFilterId, 0, 0);
  batchHistory.push(currentState);
  captureThresholdsFromState(currentState);

  console.log("Estado inicial:", {
    inserted_count: currentState.inserted_count,
    zero_bytes_remaining: currentState.zero_bytes_remaining,
    total_bytes: currentState.total_bytes,
    load_percent: Number(currentState.load_percent.toFixed(2)),
  });

  console.log("3) Preenchendo o filtro em lotes de 1000 até o fechamento automático...");
  let totalKeysRequested = 0;
  let batchNo = 0;
  while (
    currentState.filter_status !== "closed" &&
    currentState.inserted_count < targetThreshold
  ) {
    batchNo += 1;
    await writeDummyRevocations({
      baseUrl: BFILTER_BASE_URL,
      adminToken: BFILTER_ADMIN_TOKEN,
      runId,
      batchNo,
      count: BATCH_SIZE,
    });

    totalKeysRequested += BATCH_SIZE;
    currentState = await captureState(BFILTER_BASE_URL, initialFilterId, batchNo, totalKeysRequested);
    batchHistory.push(currentState);
    captureThresholdsFromState(currentState);

    const crossedThresholds = thresholdPercents.filter(
      (pct) =>
        statesByThreshold.get(pct) &&
        statesByThreshold.get(pct).batch_no === batchNo
    );

    if (batchNo === 1 || batchNo % 10 === 0 || crossedThresholds.length > 0 || currentState.filter_status === "closed") {
      console.log(`Lote ${batchNo}:`, {
        inserted_count: currentState.inserted_count,
        load_percent: Number(currentState.load_percent.toFixed(2)),
        zero_bytes_remaining: currentState.zero_bytes_remaining,
        status: currentState.filter_status,
        crossed_thresholds: crossedThresholds,
      });
    }
  }

  assert(
    currentState.inserted_count >= targetThreshold,
    `o filtro inicial deveria atingir pelo menos ${TARGET_CLOSE_PERCENT}% da capacidade`
  );
  assert(
    currentState.filter_status === "closed",
    `o filtro inicial deveria estar fechado após atingir ${TARGET_CLOSE_PERCENT}%, veio ${currentState.filter_status}`
  );
  assert(
    statesByThreshold.has(TARGET_CLOSE_PERCENT),
    `a linha de ${TARGET_CLOSE_PERCENT}% deveria ter sido capturada`
  );

  const finalManifest = await fetchManifestEnvelope(BFILTER_BASE_URL);
  const newActiveFilter = getActiveFilter(finalManifest);
  assert(
    newActiveFilter.filter_id !== initialFilterId,
    "após o fechamento do filtro inicial deveria existir um novo filtro ativo"
  );
  const thresholdRows = buildThresholdRows(statesByThreshold, thresholdPercents, currentState.capacity_limit);
  const prettyTable = renderPrettyTable(thresholdRows);
  const markdownTable = renderMarkdownTable(prettyTable);

  const report = {
    ok: true,
    generated_at: nowIso(),
    config: {
      BFILTER_BASE_URL,
      BATCH_SIZE,
      INTERVAL_PERCENT,
      TARGET_CLOSE_PERCENT,
      TEST_FILTER_M_BITS,
    },
    initial_filter: {
      filter_id: initialFilter.filter_id,
      m_bits: Number(initialFilter.m_bits || 0),
      k: Number(initialFilter.k || 0),
      capacity_limit: Number(initialFilter.capacity_limit || 0),
      rotate_threshold: targetThreshold,
    },
    final_closed_filter: {
      filter_id: currentState.filter_id,
      inserted_count: currentState.inserted_count,
      capacity_limit: currentState.capacity_limit,
      load_percent: currentState.load_percent,
      zero_bytes_remaining: currentState.zero_bytes_remaining,
      zero_bytes_remaining_percent: currentState.zero_bytes_remaining_percent,
      total_bytes: currentState.total_bytes,
      status: currentState.filter_status,
      download_url: currentState.download_url,
    },
    new_active_filter: {
      filter_id: newActiveFilter.filter_id,
      inserted_count: Number(newActiveFilter.inserted_count || 0),
      capacity_limit: Number(newActiveFilter.capacity_limit || 0),
      status: String(newActiveFilter.status || ""),
    },
    threshold_table: thresholdRows,
    batch_history: batchHistory,
    pretty_table: prettyTable,
    markdown_table: markdownTable,
  };

  fs.writeFileSync(reportJsonFile, JSON.stringify(report, null, 2), "utf8");
  fs.writeFileSync(
    reportMdFile,
    [
      "# Teste Revogação 55",
      "",
      "Tabela de saturação do Bloom Filter com contagem de bytes `00` remanescentes.",
      "",
      markdownTable,
      "",
      "Resumo final:",
      "",
      `- Filtro fechado: \`${currentState.filter_id}\``,
      `- inserted_count final: ${formatInt(currentState.inserted_count)}`,
      `- capacity_limit: ${formatInt(currentState.capacity_limit)}`,
      `- carga observada final: ${formatPercent(currentState.load_percent)}`,
      `- bytes \`00\` restantes: ${formatInt(currentState.zero_bytes_remaining)} de ${formatInt(currentState.total_bytes)}`,
      `- percentual de bytes \`00\` restantes: ${formatPercent(currentState.zero_bytes_remaining_percent)}`,
      `- novo filtro ativo: \`${newActiveFilter.filter_id}\``,
    ].join("\n"),
    "utf8"
  );

  console.log("\n============================================================");
  console.log("📊 TABELA RESUMIDA (5% em 5%)");
  console.log(prettyTable);
  console.log("\n📌 RESUMO FINAL");
  console.log({
    filter_id_closed: currentState.filter_id,
    inserted_count_final: currentState.inserted_count,
    capacity_limit: currentState.capacity_limit,
    load_percent_final: Number(currentState.load_percent.toFixed(2)),
    zero_bytes_remaining_final: currentState.zero_bytes_remaining,
    zero_bytes_remaining_percent_final: Number(currentState.zero_bytes_remaining_percent.toFixed(2)),
    new_active_filter_id: newActiveFilter.filter_id,
  });
  console.log(`📄 Relatório JSON salvo em: ${reportJsonFile}`);
  console.log(`📄 Relatório Markdown salvo em: ${reportMdFile}`);
  console.log("============================================================");
  console.log("✅ OK: TESTE REVOGAÇÃO 55 passou.");
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 55:", e && e.stack ? e.stack : e);
  process.exit(1);
});
