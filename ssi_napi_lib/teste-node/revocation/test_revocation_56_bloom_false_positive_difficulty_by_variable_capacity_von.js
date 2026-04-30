/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
TEST_FILTER_SIZES="256,512,1024,2048,4096,8192,16384,200000,300000" \
node teste-node/revocation/test_revocation_56_bloom_false_positive_difficulty_by_variable_capacity_von.js

Para subir o bfilter em modo de testes:
cd /home/yugi/programacao/bfilter
BFILTER_ENABLE_TEST_API=1 \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
cargo run

ENV OPCIONAIS:
- TEST_FILTER_SIZES="256,512,1024,2048,4096,8192,16384"
- TEST_FILTER_K=3
- TRIALS_PER_SIZE=3
- MAX_LOAD_PERCENT=95
- TARGET_WINDOW_START=1767225600
- OUT_DIR=teste-node/revocation/out
*/

/*
Teste experimental de facilidade para encontrar falso positivo
em Bloom Filters de capacidades diferentes.

Baseado na estrategia do teste 51, mas sem fluxo de revogacao SSI.

O teste:
- reseta o bfilter com varios tamanhos de filtro (m_bits);
- le o capacity_limit real exposto no manifesto apos cada reset;
- escolhe uma chave-alvo que nunca e inserida;
- injeta chaves dummy, uma a uma, no mesmo filtro e mesma janela;
- mede em que carga o Bloom passa a responder maybe_present=true;
- repete varias rodadas por tamanho;
- imprime no final uma tabela resumindo a facilidade/dificuldade.

Interpretacao:
- quanto menor a carga media necessaria para o primeiro falso positivo,
  mais facil foi encontrar o falso positivo naquele tamanho de filtro;
- se o falso positivo nao aparece ate MAX_LOAD_PERCENT da capacidade,
  o teste marca como "muito dificil" dentro do budget configurado.
*/

const fs = require("fs");
const path = require("path");

const BFILTER_BASE_URL = (process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080").replace(/\/+$/, "");
const BFILTER_ADMIN_TOKEN = process.env.BFILTER_ADMIN_TOKEN || "dev-admin-token";
const TEST_FILTER_SIZES = parsePositiveIntList(
  process.env.TEST_FILTER_SIZES || "256,512,1024,2048,4096,8192,16384"
);
const TEST_FILTER_K = Number(process.env.TEST_FILTER_K || "3");
const TRIALS_PER_SIZE = Number(process.env.TRIALS_PER_SIZE || "3");
const MAX_LOAD_PERCENT = Number(process.env.MAX_LOAD_PERCENT || "95");
const TARGET_WINDOW_START = Number(process.env.TARGET_WINDOW_START || "1767225600");
const OUT_DIR = process.env.OUT_DIR || path.join("teste-node", "revocation", "out");

function assert(cond, msg) {
  if (!cond) {
    throw new Error(msg);
  }
}

function parsePositiveIntList(raw) {
  return String(raw)
    .split(",")
    .map((item) => Number(String(item).trim()))
    .filter((value) => Number.isInteger(value) && value > 0);
}

function nowIso() {
  return new Date().toISOString();
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

function formatRatio(hitCount, total) {
  return `${formatInt(hitCount)}/${formatInt(total)}`;
}

function percentOf(value, total) {
  if (!Number(total)) return 0;
  return (Number(value) / Number(total)) * 100;
}

function bloomFpEstimate(mBits, k, insertedCount) {
  const m = Number(mBits);
  const hashes = Number(k);
  const n = Number(insertedCount);
  if (!m || !hashes || n < 0) return 0;
  return Math.pow(1 - Math.exp((-hashes * n) / m), hashes);
}

function classifyDifficulty(hitRatePercent, loadPercentAverage) {
  if (hitRatePercent === 0) return "muito dificil";
  if (loadPercentAverage <= 20) return "muito facil";
  if (loadPercentAverage <= 40) return "facil";
  if (loadPercentAverage <= 65) return "moderado";
  if (loadPercentAverage <= 85) return "dificil";
  return hitRatePercent >= 100 ? "dificil" : "muito dificil";
}

function average(values) {
  if (!values.length) return null;
  return values.reduce((acc, item) => acc + Number(item), 0) / values.length;
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

function mkdirp(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
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

async function fetchManifestEnvelope(baseUrl) {
  const resp = await fetch(`${baseUrl}/manifest`);
  const body = await readJsonResponse(resp, "GET /manifest");
  assert(resp.ok, `Falha GET /manifest: ${resp.status} ${JSON.stringify(body)}`);
  assert(body && body.ok === true, "manifesto deveria retornar ok=true");
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

async function resetBfilterForTests(baseUrl, adminToken, mBits, k) {
  const resp = await fetch(`${baseUrl}/test/reset`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${adminToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      filter_id: `test-fp-difficulty-${mBits}-${Date.now()}`,
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

async function checkRevocationKey({ baseUrl, filterId, revocationKey, windowStart }) {
  const resp = await fetch(`${baseUrl}/check`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      filter_id: filterId,
      revocation_keys: [revocationKey],
      encoding: "utf8",
      window_start: windowStart,
    }),
  });

  const body = await readJsonResponse(resp, "POST /check");
  assert(resp.ok, `Falha POST /check: ${resp.status} ${JSON.stringify(body)}`);
  assert(body && body.ok === true, "consulta /check deveria retornar ok=true");
  assert(Array.isArray(body.results) && body.results.length === 1, "/check deveria retornar 1 resultado");
  return body.results[0];
}

async function writeDummyRevocation({
  baseUrl,
  adminToken,
  filterId,
  targetWindowStart,
  runId,
  sequenceNo,
}) {
  const resp = await fetch(`${baseUrl}/admin/revocations/v2`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${adminToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      filter_id: filterId,
      revocation_keys: [`fp-study-${runId}-${String(sequenceNo).padStart(6, "0")}`],
      window_starts: [targetWindowStart],
      reason: "measure-false-positive-difficulty",
      requested_by: "teste-node-revocation-56",
    }),
  });

  const body = await readJsonResponse(resp, "POST /admin/revocations/v2");
  assert(resp.ok, `Falha POST /admin/revocations/v2: ${resp.status} ${JSON.stringify(body)}`);
  assert(body && body.ok === true, "escrita dummy no Bloom deveria retornar ok=true");
  return body;
}

async function runTrial({ mBits, k, trialIndex, maxLoadPercent }) {
  await resetBfilterForTests(BFILTER_BASE_URL, BFILTER_ADMIN_TOKEN, mBits, k);
  const manifestEnvelope = await fetchManifestEnvelope(BFILTER_BASE_URL);
  const activeFilter = getActiveFilter(manifestEnvelope);
  const filterId = activeFilter.filter_id;
  const capacityLimit = Number(activeFilter.capacity_limit || 0);
  const insertedAtStart = Number(activeFilter.inserted_count || 0);
  const targetInsertionsBudget = Math.max(
    1,
    Math.floor((capacityLimit * Number(maxLoadPercent || 0)) / 100)
  );
  const runId = `${mBits}-trial-${trialIndex}-${Date.now()}`;
  const targetKey = `target-fp-study-${runId}`;
  const windowStart = TARGET_WINDOW_START + mBits * 1000 + trialIndex;

  assert(capacityLimit > 0, `capacity_limit invalido para m_bits=${mBits}: ${capacityLimit}`);
  assert(insertedAtStart === 0, `filtro deveria iniciar vazio apos reset, mas inserted_count=${insertedAtStart}`);

  const baseline = await checkRevocationKey({
    baseUrl: BFILTER_BASE_URL,
    filterId,
    revocationKey: targetKey,
    windowStart,
  });
  assert(baseline.maybe_present === false, "a chave-alvo nao deveria aparecer antes das escritas");

  for (let insertionNo = 1; insertionNo <= targetInsertionsBudget; insertionNo++) {
    await writeDummyRevocation({
      baseUrl: BFILTER_BASE_URL,
      adminToken: BFILTER_ADMIN_TOKEN,
      filterId,
      targetWindowStart: windowStart,
      runId,
      sequenceNo: insertionNo,
    });

    const check = await checkRevocationKey({
      baseUrl: BFILTER_BASE_URL,
      filterId,
      revocationKey: targetKey,
      windowStart,
    });

    if (check.maybe_present === true) {
      const manifestAfterHit = await fetchManifestEnvelope(BFILTER_BASE_URL);
      const filterAfterHit = getFilterById(manifestAfterHit, filterId);
      const insertedCount = Number(filterAfterHit.inserted_count || insertionNo);
      const loadPercent = percentOf(insertedCount, capacityLimit);
      const theoreticalFpPercent = bloomFpEstimate(filterAfterHit.m_bits, filterAfterHit.k, insertedCount) * 100;

      return {
        found_false_positive: true,
        m_bits: Number(filterAfterHit.m_bits || mBits),
        k: Number(filterAfterHit.k || k),
        filter_id: filterId,
        capacity_limit: capacityLimit,
        trial_index: trialIndex,
        inserted_count_at_hit: insertedCount,
        local_insertions_until_hit: insertionNo,
        load_percent_at_hit: loadPercent,
        theoretical_fp_percent_at_hit: theoreticalFpPercent,
        budget_insertions: targetInsertionsBudget,
        budget_load_percent: percentOf(targetInsertionsBudget, capacityLimit),
        recorded_at: nowIso(),
      };
    }
  }

  const manifestAfterBudget = await fetchManifestEnvelope(BFILTER_BASE_URL);
  const filterAfterBudget = getFilterById(manifestAfterBudget, filterId);

  return {
    found_false_positive: false,
    m_bits: Number(filterAfterBudget.m_bits || mBits),
    k: Number(filterAfterBudget.k || k),
    filter_id: filterId,
    capacity_limit: capacityLimit,
    trial_index: trialIndex,
    inserted_count_at_hit: null,
    local_insertions_until_hit: null,
    load_percent_at_hit: null,
    theoretical_fp_percent_at_hit: null,
    budget_insertions: targetInsertionsBudget,
    budget_load_percent: percentOf(targetInsertionsBudget, capacityLimit),
    inserted_count_at_budget: Number(filterAfterBudget.inserted_count || targetInsertionsBudget),
    theoretical_fp_percent_at_budget:
      bloomFpEstimate(filterAfterBudget.m_bits, filterAfterBudget.k, Number(filterAfterBudget.inserted_count || targetInsertionsBudget)) *
      100,
    recorded_at: nowIso(),
  };
}

function summarizeSizeResults(sizeResults) {
  const hitResults = sizeResults.filter((item) => item.found_false_positive);
  const hitLoads = hitResults.map((item) => item.load_percent_at_hit);
  const hitInsertions = hitResults.map((item) => item.local_insertions_until_hit);
  const hitFpTheory = hitResults.map((item) => item.theoretical_fp_percent_at_hit);
  const budgetFpTheory = sizeResults
    .map((item) => item.theoretical_fp_percent_at_budget)
    .filter((value) => value !== null && value !== undefined);
  const trialCount = sizeResults.length;
  const hitCount = hitResults.length;
  const capacityLimit = Number(sizeResults[0].capacity_limit || 0);
  const k = Number(sizeResults[0].k || 0);
  const mBits = Number(sizeResults[0].m_bits || 0);
  const hitRatePercent = percentOf(hitCount, trialCount);
  const difficultyLoadReference =
    average(hitLoads) !== null ? average(hitLoads) : Number(sizeResults[0].budget_load_percent || 100);

  return {
    m_bits: mBits,
    capacity_limit: capacityLimit,
    k,
    trials: trialCount,
    hits: hitCount,
    hit_rate_percent: hitRatePercent,
    avg_insertions_to_hit: average(hitInsertions),
    min_insertions_to_hit: hitInsertions.length ? Math.min(...hitInsertions) : null,
    max_insertions_to_hit: hitInsertions.length ? Math.max(...hitInsertions) : null,
    avg_load_percent_to_hit: average(hitLoads),
    avg_theoretical_fp_percent_at_hit: average(hitFpTheory),
    avg_theoretical_fp_percent_at_budget: average(budgetFpTheory),
    difficulty: classifyDifficulty(hitRatePercent, difficultyLoadReference),
    budget_load_percent: Number(sizeResults[0].budget_load_percent || 0),
    budget_insertions: Number(sizeResults[0].budget_insertions || 0),
  };
}

function toDisplayRow(summary) {
  const semFpAteCapacidade = `sem FP observado ate ${formatPercent(summary.budget_load_percent)} da capacidade`;
  return {
    m_bits: formatInt(summary.m_bits),
    capacidade: formatInt(summary.capacity_limit),
    k: formatInt(summary.k),
    rodadas_com_fp:
      summary.hits === 0
        ? `${formatRatio(summary.hits, summary.trials)} (nenhum)`
        : formatRatio(summary.hits, summary.trials),
    primeiro_fp_apos:
      summary.avg_insertions_to_hit === null
        ? `nao observado ate >${formatInt(summary.budget_insertions)}`
        : formatInt(summary.avg_insertions_to_hit),
    carga_no_hit:
      summary.avg_load_percent_to_hit === null
        ? `nao observado ate >${formatPercent(summary.budget_load_percent)}`
        : formatPercent(summary.avg_load_percent_to_hit),
    fp_teorica_ref:
      summary.avg_theoretical_fp_percent_at_hit === null
        ? `ate budget: ${formatPercent(summary.avg_theoretical_fp_percent_at_budget)}`
        : formatPercent(summary.avg_theoretical_fp_percent_at_hit),
    leitura: summary.hits === 0 ? semFpAteCapacidade : summary.difficulty,
  };
}

(async () => {
  assert(TEST_FILTER_SIZES.length > 0, "TEST_FILTER_SIZES deve conter pelo menos 1 tamanho valido");
  assert(Number.isInteger(TEST_FILTER_K) && TEST_FILTER_K > 0, "TEST_FILTER_K deve ser inteiro positivo");
  assert(Number.isInteger(TRIALS_PER_SIZE) && TRIALS_PER_SIZE > 0, "TRIALS_PER_SIZE deve ser inteiro positivo");
  assert(MAX_LOAD_PERCENT > 0 && MAX_LOAD_PERCENT <= 100, "MAX_LOAD_PERCENT deve ficar entre 1 e 100");

  console.log("🚀 TESTE REVOGACAO 56: dificuldade para encontrar falso positivo por capacidade de Bloom Filter");
  console.log("Configuracao:", {
    base_url: BFILTER_BASE_URL,
    test_filter_sizes: TEST_FILTER_SIZES,
    test_filter_k: TEST_FILTER_K,
    trials_per_size: TRIALS_PER_SIZE,
    max_load_percent: MAX_LOAD_PERCENT,
    target_window_start: TARGET_WINDOW_START,
  });

  const allResults = [];

  for (const mBits of TEST_FILTER_SIZES) {
    console.log(`\n1) Rodando m_bits=${mBits}...`);
    for (let trialIndex = 1; trialIndex <= TRIALS_PER_SIZE; trialIndex++) {
      console.log(`   - rodada ${trialIndex}/${TRIALS_PER_SIZE}`);
      const trialResult = await runTrial({
        mBits,
        k: TEST_FILTER_K,
        trialIndex,
        maxLoadPercent: MAX_LOAD_PERCENT,
      });
      allResults.push(trialResult);

      if (trialResult.found_false_positive) {
        console.log("     falso positivo encontrado:", {
          capacity_limit: trialResult.capacity_limit,
          insertions_until_hit: trialResult.local_insertions_until_hit,
          load_percent_at_hit: Number(trialResult.load_percent_at_hit.toFixed(2)),
          theoretical_fp_percent_at_hit: Number(trialResult.theoretical_fp_percent_at_hit.toFixed(4)),
        });
      } else {
        console.log("     falso positivo nao encontrado dentro do budget:", {
          capacity_limit: trialResult.capacity_limit,
          budget_insertions: trialResult.budget_insertions,
          budget_load_percent: Number(trialResult.budget_load_percent.toFixed(2)),
        });
      }
    }
  }

  const groupedBySize = TEST_FILTER_SIZES.map((mBits) => allResults.filter((item) => item.m_bits === mBits));
  const summaries = groupedBySize.map(summarizeSizeResults);
  const displayRows = summaries.map(toDisplayRow);

  const summaryTable = makeMarkdownTable(displayRows, [
    { key: "m_bits", label: "m_bits" },
    { key: "capacidade", label: "Capacidade" },
    { key: "k", label: "k" },
    { key: "rodadas_com_fp", label: "Rodadas c/ FP" },
    { key: "primeiro_fp_apos", label: "1o FP apos" },
    { key: "carga_no_hit", label: "Carga no 1o FP" },
    { key: "fp_teorica_ref", label: "FP teorica ref." },
    { key: "leitura", label: "Leitura" },
  ]);
  const summaryHtmlTable = makeHtmlTable(displayRows, [
    { key: "m_bits", label: "m_bits" },
    { key: "capacidade", label: "Capacidade" },
    { key: "k", label: "k" },
    { key: "rodadas_com_fp", label: "Rodadas c/ FP" },
    { key: "primeiro_fp_apos", label: "1o FP apos" },
    { key: "carga_no_hit", label: "Carga no 1o FP" },
    { key: "fp_teorica_ref", label: "FP teorica ref." },
    { key: "leitura", label: "Leitura" },
  ]);

  mkdirp(OUT_DIR);
  const stamp = `${Date.now()}_${process.pid}`;
  const jsonPath = path.join(OUT_DIR, `revocation_56_false_positive_difficulty_${stamp}.json`);
  const mdPath = path.join(OUT_DIR, `revocation_56_false_positive_difficulty_${stamp}.md`);
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
          max_load_percent: MAX_LOAD_PERCENT,
          target_window_start: TARGET_WINDOW_START,
        },
        results: allResults,
        summary: summaries,
      },
      null,
      2
    )
  );
  fs.writeFileSync(
    mdPath,
    [
      "# Teste 56 - Dificuldade de falso positivo por capacidade",
      "",
      `Gerado em: ${nowIso()}`,
      "",
      summaryHtmlTable,
      "",
      "## Legenda",
      "",
      "- `Rodadas c/ FP`: em quantas rodadas apareceu pelo menos um falso positivo dentro do budget. Ex.: `0/3` significa que em 3 tentativas nenhum falso positivo apareceu ate o limite configurado.",
      "- `1o FP apos`: media de insercoes dummy necessarias ate o primeiro falso positivo. Se vier `nao observado ate >X`, significa que o teste foi ate esse ponto e mesmo assim nao houve hit.",
      "- `Carga no 1o FP`: percentual medio de ocupacao do filtro quando o primeiro falso positivo apareceu. Se nao apareceu, mostra ate qual carga o teste foi sem observar falso positivo.",
      "- `FP teorica ref.`: estimativa teorica da taxa de falso positivo. Quando houve hit, mostra a media no ponto do hit. Quando nao houve hit, mostra a estimativa no budget maximo testado.",
      "- `Leitura`: resumo direto da conclusao da linha. Ex.: `sem FP observado ate 95.0% da capacidade`.",
      "",
    ].join("\n")
  );

  console.log("\n2) Tabela final de facilidade/dificuldade:");
  console.log(summaryTable);
  console.log("\n✅ OK: TESTE REVOGACAO 56 passou.");
  console.log("Arquivos gerados:", {
    json: jsonPath,
    markdown: mdPath,
  });
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGACAO 56:", e && e.stack ? e.stack : e);
  process.exit(1);
});
