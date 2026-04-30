/*
PARA RODAR:
cd /home/yugi/programacao/bfilter
BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
BFILTER_DATA_DIR="./data" \
BFILTER_ROTATE_AT_PERCENT="95" \
BATCH_SIZE="5000" \
node tests/manual_rotate_real_service_boundary_94_to_95.js

O que este script faz:
- consulta o manifesto da instância real do bfilter
- calcula o limiar de rotação em 95%
- escreve revogações só até 94% da capacidade e confirma que NÃO houve rotação
- escreve o lote final mínimo para atingir/cruzar 95%
- confirma que a rotação automática aconteceu
- mostra os arquivos .bloom em data/filters
- mostra o hash final do manifest.json, pronto para reancoragem no ledger

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

function thresholdAtPercent(capacityLimit, percent) {
  return Math.floor((capacityLimit * percent + 99) / 100);
}

function thresholdAt94(capacityLimit) {
  return Math.floor((capacityLimit * 94 + 99) / 100);
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

async function writeRevocations(keys, label) {
  const resp = await fetch(`${BFILTER_BASE_URL}/admin/revocations/v2`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${BFILTER_ADMIN_TOKEN}`,
    },
    body: JSON.stringify({
      revocation_keys: keys,
      requested_by: "manual-rotate-boundary-94-to-95",
      reason: label,
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

async function writeInBatches(totalKeys, reasonPrefix) {
  let written = 0;
  let batchNo = 0;
  while (written < totalKeys) {
    batchNo += 1;
    const remaining = totalKeys - written;
    const batchSize = Math.min(BATCH_SIZE, remaining);
    const keys = Array.from({ length: batchSize }, (_, idx) =>
      `manual-boundary-${Date.now()}-${process.pid}-${reasonPrefix}-${batchNo}-${written + idx}`
    );
    const response = await writeRevocations(keys, `${reasonPrefix}-batch-${batchNo}`);
    written += batchSize;
    console.log(`Lote ${reasonPrefix}/${batchNo}:`, {
      batch_size: batchSize,
      inserted_total: written,
      written_into_filter_id: response.filter_id,
    });
  }
}

(async () => {
  console.log("============================================================");
  console.log("🧪 MANUAL BFILTER ROTATION BOUNDARY 94% -> 95%");
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

  const manifestBefore = await getManifest();
  const activeBefore = getActiveFilter(manifestBefore);
  const insertedBefore = Number(activeBefore.inserted_count || 0);
  const capacityLimit = Number(activeBefore.capacity_limit || 0);
  const rotateThreshold = thresholdAtPercent(capacityLimit, BFILTER_ROTATE_AT_PERCENT);
  const noRotateThreshold = thresholdAt94(capacityLimit);
  const keysNeededTo94 = Math.max(0, noRotateThreshold - insertedBefore);
  const keysNeededTo95 = Math.max(0, rotateThreshold - (insertedBefore + keysNeededTo94));

  console.log("Filtro ativo antes:", {
    filter_id: activeBefore.filter_id,
    status: activeBefore.status,
    inserted_count: insertedBefore,
    capacity_limit: capacityLimit,
    threshold_94: noRotateThreshold,
    threshold_95: rotateThreshold,
    keys_needed_to_94: keysNeededTo94,
    keys_needed_to_95_after_94: keysNeededTo95,
  });
  console.log("Arquivos .bloom antes:", listBloomFiles(filtersDir));

  if (keysNeededTo94 > 0) {
    console.log("\n1) Levando até 94% sem rotacionar...");
    await writeInBatches(keysNeededTo94, "to94");
  } else {
    console.log("\n1) O filtro atual já está em 94% ou mais; pulando etapa intermediária.");
  }

  const manifestAfter94 = await getManifest();
  const activeAfter94 = getActiveFilter(manifestAfter94);
  const oldFilterAfter94 = (manifestAfter94.filters || []).find(
    (item) => item.filter_id === activeBefore.filter_id
  );
  assert(oldFilterAfter94, "Filtro antigo deveria continuar no manifesto após 94%");
  assert(
    activeAfter94.filter_id === activeBefore.filter_id,
    "Não deveria haver rotação ainda ao final da etapa de 94%"
  );
  assert(
    oldFilterAfter94.status === "active",
    `Filtro antigo deveria continuar active em 94%, veio ${oldFilterAfter94.status}`
  );
  assert(
    Number(oldFilterAfter94.inserted_count) < rotateThreshold,
    "O inserted_count em 94% ainda deveria estar abaixo do limiar de rotação"
  );

  console.log("Manifesto após 94%:", {
    active_filter_id: manifestAfter94.active_filter_id,
    old_filter_status: oldFilterAfter94.status,
    old_filter_inserted_count: oldFilterAfter94.inserted_count,
  });

  assert(
    keysNeededTo95 > 0,
    "Não há chaves restantes para demonstrar a transição 94% -> 95%; use uma instância com inserted_count menor"
  );

  console.log("\n2) Escrevendo o lote final para atingir 95% e disparar a rotação...");
  await writeInBatches(keysNeededTo95, "to95");

  const manifestAfter95 = await getManifest();
  const oldFilterAfter95 = (manifestAfter95.filters || []).find(
    (item) => item.filter_id === activeBefore.filter_id
  );
  const newActive = getActiveFilter(manifestAfter95);
  assert(oldFilterAfter95, "Filtro antigo deveria continuar no manifesto após rotação");
  assert(oldFilterAfter95.status === "closed", `Filtro antigo deveria estar closed, veio ${oldFilterAfter95.status}`);
  assert(oldFilterAfter95.closed_at, "Filtro antigo deveria ter closed_at após rotação");
  assert(
    newActive.filter_id !== activeBefore.filter_id,
    "O filtro ativo deveria mudar ao atingir 95%"
  );
  assert(newActive.status === "active", `Novo filtro deveria estar active, veio ${newActive.status}`);
  assert(Number(newActive.inserted_count || 0) === 0, "Novo filtro deveria iniciar com inserted_count=0");

  const manifestAfterDisk = fs.readFileSync(manifestPath);
  const manifestAfterHash = sha256Base64(manifestAfterDisk);

  console.log("\n============================================================");
  console.log("✅ TRANSIÇÃO 94% -> 95% CONFIRMADA");
  console.log("Filtro antigo:", {
    filter_id: oldFilterAfter95.filter_id,
    status: oldFilterAfter95.status,
    inserted_count: oldFilterAfter95.inserted_count,
    closed_at: oldFilterAfter95.closed_at,
    file_name: oldFilterAfter95.file_name,
  });
  console.log("Novo filtro ativo:", {
    filter_id: newActive.filter_id,
    status: newActive.status,
    inserted_count: newActive.inserted_count,
    file_name: newActive.file_name,
  });
  console.log("Arquivos .bloom depois:", listBloomFiles(filtersDir));
  console.log("Manifest path:", manifestPath);
  console.log("Manifest sha256 base64 (para reancorar no ledger):", manifestAfterHash);
  console.log("============================================================");
})().catch((err) => {
  console.error("❌ FALHA NO SCRIPT MANUAL DE FRONTEIRA 94->95:", err && err.stack ? err.stack : err);
  process.exit(1);
});
