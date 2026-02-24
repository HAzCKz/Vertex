/*
PARA RODAR:
WALLET_PASS="minha_senha_teste" RESET_WALLET=1 node teste-node/test_wallet/test_wallet_auto_timeout_simulated.js
*/

const path = require("path");
const fs = require("fs");
const addon = require("../../index.node");

function must(cond, msg) {
  if (!cond) throw new Error(msg);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function rmWalletArtifacts(walletDbPath) {
  const kdf = `${walletDbPath}.kdf.json`;
  try { fs.unlinkSync(walletDbPath); } catch (_) { }
  try { fs.unlinkSync(kdf); } catch (_) { }
  try { fs.unlinkSync(`${kdf}.tmp`); } catch (_) { }
  try { fs.unlinkSync(`${walletDbPath}-shm`); } catch (_) { }
  try { fs.unlinkSync(`${walletDbPath}-wal`); } catch (_) { }

  // compat com versões antigas
  try { fs.unlinkSync(`${walletDbPath}.sidecar.json`); } catch (_) { }
  try { fs.unlinkSync(`${walletDbPath}.passbackup.json`); } catch (_) { }
  try { fs.unlinkSync(`${walletDbPath}.sidecar`); } catch (_) { }
}

/**
 * Simulador de Auto-Timeout (lado JS).
 * - start(): inicia timer
 * - touch(): reseta timer (simula atividade do usuário)
 * - stop(): cancela timer
 *
 * Quando estoura: chama agent.walletLock() e marca locked=true.
 */
function makeAutoLock(agent, timeoutMs) {
  let t = null;
  let lockedCount = 0;
  let stopped = false;

  async function doLock() {
    if (stopped) return;
    try {
      await agent.walletLock();
      lockedCount += 1;
      console.log(`🔒 auto-lock disparou (count=${lockedCount})`);
    } catch (e) {
      // Se já estiver fechada, não é um erro prático para UI; mas loga
      console.log("⚠️ auto-lock tentou travar e falhou (talvez já fechada):", String(e.message || e));
    }
  }

  function arm() {
    if (t) clearTimeout(t);
    t = setTimeout(() => { void doLock(); }, timeoutMs);
  }

  function start() {
    stopped = false;
    arm();
  }

  function touch(label = "") {
    // simula ação do usuário que mantém wallet desbloqueada
    console.log(`🖱️ atividade detectada ${label ? "(" + label + ")" : ""} -> reset timer`);
    arm();
  }

  function stop() {
    stopped = true;
    if (t) clearTimeout(t);
    t = null;
  }

  function getLockedCount() {
    return lockedCount;
  }

  return { start, touch, stop, getLockedCount };
}

async function main() {
  const WALLET_PASS = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET_WALLET = process.env.RESET_WALLET === "1";

  const walletPath = path.resolve("./teste-node/wallets/test_wallet_auto_timeout.db");

  if (RESET_WALLET) {
    console.log("🧹 RESET_WALLET=1: limpando artefatos...");
    rmWalletArtifacts(walletPath);
  }

  const agent = new addon.IndyAgent();

  console.log("1) Criando wallet...");
  await agent.walletCreate(walletPath, WALLET_PASS);

  console.log("2) Unlock (abrindo wallet)...");
  await agent.walletUnlock(walletPath, WALLET_PASS);

  console.log("3) Verificando status aberto...");
  let info = JSON.parse(await agent.walletInfo(walletPath));
  must(info.status.is_open_for_path === true, "wallet deveria estar aberta após unlock");

  // Timeout pequeno para teste (ex.: 800ms)
  const TIMEOUT_MS = 800;
  const auto = makeAutoLock(agent, TIMEOUT_MS);

  console.log(`4) Iniciando auto-timeout: ${TIMEOUT_MS}ms`);
  auto.start();

  console.log("5) Simulando atividade ANTES do timeout (deve impedir auto-lock)...");
  await sleep(400);
  auto.touch("t=400ms");

  console.log("6) Esperando menos que o timeout novamente (ainda não deve travar)...");
  await sleep(500); // total desde touch: 500ms < 800ms
  must(auto.getLockedCount() === 0, "não deveria ter auto-lock ainda");

  console.log("7) Agora esperando PASSAR do timeout sem atividade (deve travar)...");
  await sleep(900); // agora deve disparar

  // pequena folga pro callback assíncrono do lock rodar
  await sleep(200);

  must(auto.getLockedCount() >= 1, "auto-lock deveria ter disparado pelo menos 1 vez");

  console.log("8) Verificando status fechado...");
  info = JSON.parse(await agent.walletInfo(walletPath));
  must(info.status.is_open_any === false, "wallet deveria estar fechada após auto-lock");
  must(info.status.is_open_for_path === false, "wallet deveria estar fechada para o path");

  console.log("9) Unlock novamente (simula usuário digitando senha após travar)...");
  await agent.walletUnlock(walletPath, WALLET_PASS);

  info = JSON.parse(await agent.walletInfo(walletPath));
  must(info.status.is_open_for_path === true, "wallet deveria abrir novamente após unlock");

  console.log("10) Encerrando auto-timeout e fechando...");
  auto.stop();
  await agent.walletClose();

  console.log("✅ OK: teste auto-timeout (simulado no JS) passou.");
}

main().catch((e) => {
  console.error("❌ FALHA:", e);
  process.exit(1);
});
