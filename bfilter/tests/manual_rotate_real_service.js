/*
PARA RODAR:
cd /home/yugi/programacao/bfilter
BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
BFILTER_DATA_DIR="./data" \
BFILTER_ROTATE_AT_PERCENT="95" \
BATCH_SIZE="5000" \
node tests/manual_rotate_real_service.js

O que este script faz:
- consulta o manifesto da instância real do bfilter
- calcula quanto falta para atingir 95% da capacidade do filtro ativo
- escreve revogações em lotes até forçar a rotação automática
- verifica que o filtro antigo foi fechado e um novo foi aberto
- mostra os arquivos .bloom em data/filters
- calcula o hash do manifest.json atualizado, pronto para ser reancorado no ledger pelo emissor

ATENÇÃO:
este script altera a instância real do serviço e cria entradas reais de revogação.
*/

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const BFILTER_BASE_URL = (process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080").replace(/\/+$/, "");
const BFILTER_ADMIN_TOKEN = process.env.BFILTER_ADMIN_TOKEN || "dev-admin-token";
const BFILTER_DATA_DIR = process.env.BFILTER_DATA_DIR || path.join(process.cwd(), "data");
const BFILTER_ROTATE_AT_PERCENT = Number(process.env.BFILTER_ROTATE_AT_PERCENT || "95");
const BATCH_SIZE = Number(process.env.BATCH_SIZE || "5000");

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function sha256Base64(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("base64");
}

function rotationThreshold(capacityLimit, percent) {
  return Math.floor((capacityLimit * percent + 99) / 100);
}

async function getManifest() {
  const resp = await fetch(`${BFILTER_BASE_URL}/manifest`);
  assert(resp.ok, `Falha GET /manifest: ${resp.status}`);
  const body = await resp.json();
  assert(body.ok === true, "manifesto deveria retornar ok=true");
  return body.manifest;
}

function getActiveFilter(manifest) {
  const activeId = manifest.active_filter_id;
  const active = (manifest.filters || []).find((item) => item.filter_id === activeId);
  assert(active, `Filtro ativo não encontrado no manifesto: ${activeId}`);
  return active;
}

async function writeRevocations(keys) {
  const resp = await fetch(`${BFILTER_BASE_URL}/admin/revocations/v2`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${BFILTER_ADMIN_TOKEN}`,
    },
    body: JSON.stringify({
      revocation_keys: keys,
      requested_by: "manual-rotate-real-service",
      reason: "force-rotation-at-threshold",
    }),
  });
  const body = await resp.json();
  assert(resp.ok, `Falha POST /admin/revocations/v2: ${resp.status} ${JSON.stringify(body)}`);
  assert(body.ok === true, "resposta de revogação deveria retornar ok=true");
  return body;
}

function listBloomFiles(filtersDir) {
  if (!fs.existsSync(filtersDir)) return [];
  return fs
    .readdirSync(filtersDir)
    .filter((name) => name.endsWith(".bloom"))
    .sort();
}

(async () => {
  console.log("============================================================");
  console.log("🧪 MANUAL BFILTER ROTATION AGAINST REAL SERVICE");
  console.log("Config:", {
    BFILTER_BASE_URL,
    BFILTER_DATA_DIR,
    BFILTER_ROTATE_AT_PERCENT,
    BATCH_SIZE,
    adminToken: "***",
  });
  console.log("============================================================");

  const manifestPath = path.join(BFILTER_DATA_DIR, "manifest.json");
  const filtersDir = path.join(BFILTER_DATA_DIR, "filters");

  assert(fs.existsSync(manifestPath), `manifest.json não encontrado em ${manifestPath}`);
  assert(fs.existsSync(filtersDir), `pasta filters não encontrada em ${filtersDir}`);

  const manifestBeforeHttp = await getManifest();
  const activeBefore = getActiveFilter(manifestBeforeHttp);
  const manifestBeforeDisk = fs.readFileSync(manifestPath);
  const manifestBeforeHash = sha256Base64(manifestBeforeDisk);
  const filesBefore = listBloomFiles(filtersDir);

  const threshold = rotationThreshold(activeBefore.capacity_limit, BFILTER_ROTATE_AT_PERCENT);
  const insertedBefore = Number(activeBefore.inserted_count || 0);
  const keysNeeded = Math.max(1, threshold - insertedBefore);

  console.log("Filtro ativo antes:", {
    filter_id: activeBefore.filter_id,
    status: activeBefore.status,
    inserted_count: insertedBefore,
    capacity_limit: activeBefore.capacity_limit,
    rotate_threshold: threshold,
    keys_needed_to_rotate: keysNeeded,
  });
  console.log("Arquivos .bloom antes:", filesBefore);

  let written = 0;
  let batchNo = 0;
  while (written < keysNeeded) {
    batchNo += 1;
    const remaining = keysNeeded - written;
    const batchSize = Math.min(BATCH_SIZE, remaining);
    const keys = Array.from({ length: batchSize }, (_, idx) =>
      `manual-rotate-${Date.now()}-${process.pid}-${batchNo}-${written + idx}`
    );
    const response = await writeRevocations(keys);
    written += batchSize;
    console.log(`Lote ${batchNo}:`, {
      batch_size: batchSize,
      inserted_total: written,
      written_into_filter_id: response.filter_id,
    });
  }

  const manifestAfterHttp = await getManifest();
  const manifestAfterDisk = fs.readFileSync(manifestPath);
  const manifestAfterHash = sha256Base64(manifestAfterDisk);
  const filesAfter = listBloomFiles(filtersDir);

  const oldFilterAfter = (manifestAfterHttp.filters || []).find(
    (item) => item.filter_id === activeBefore.filter_id
  );
  assert(oldFilterAfter, "Filtro antigo deveria continuar presente no manifesto");
  assert(oldFilterAfter.status === "closed", `Filtro antigo deveria estar closed, veio ${oldFilterAfter.status}`);
  assert(oldFilterAfter.closed_at, "Filtro antigo deveria ter closed_at");

  const newActive = getActiveFilter(manifestAfterHttp);
  assert(
    newActive.filter_id !== activeBefore.filter_id,
    "O filtro ativo deveria ter mudado após a rotação"
  );
  assert(newActive.status === "active", `Novo filtro deveria estar active, veio ${newActive.status}`);
  assert(Number(newActive.inserted_count || 0) === 0, "Novo filtro deveria começar com inserted_count=0");
  assert(
    fs.existsSync(path.join(filtersDir, oldFilterAfter.file_name)),
    "Arquivo do filtro antigo deveria continuar visível em data/filters"
  );
  assert(
    fs.existsSync(path.join(filtersDir, newActive.file_name)),
    "Arquivo do novo filtro deveria existir em data/filters"
  );
  assert(
    manifestBeforeHash !== manifestAfterHash,
    "O hash do manifest.json deveria mudar após a rotação"
  );

  console.log("\n============================================================");
  console.log("✅ ROTAÇÃO CONFIRMADA");
  console.log("Filtro antigo:", {
    filter_id: oldFilterAfter.filter_id,
    status: oldFilterAfter.status,
    inserted_count: oldFilterAfter.inserted_count,
    closed_at: oldFilterAfter.closed_at,
    file_name: oldFilterAfter.file_name,
  });
  console.log("Novo filtro ativo:", {
    filter_id: newActive.filter_id,
    status: newActive.status,
    inserted_count: newActive.inserted_count,
    file_name: newActive.file_name,
  });
  console.log("Arquivos .bloom depois:", filesAfter);
  console.log("Manifest path:", manifestPath);
  console.log("Manifest sha256 base64 (para reancorar no ledger):", manifestAfterHash);
  console.log("============================================================");
})().catch((err) => {
  console.error("❌ FALHA NO SCRIPT MANUAL DE ROTAÇÃO:", err && err.stack ? err.stack : err);
  process.exit(1);
});
