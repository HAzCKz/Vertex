/*
PARA RODAR:
WALLET_PASS="minha_senha_teste" RESET_WALLET=1 node teste-node/test_wallet/test_wallet_auto_timeout_activity_loop.js
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
      console.log("⚠️ auto-lock falhou (talvez já fechada):", String(e.message || e));
    }
  }

  function arm() {
    if (t) clearTimeout(t);
    t = setTimeout(() => { void doLock(); }, timeoutMs);
  }

  return {
    start() { stopped = false; arm(); },
    touch(label = "") {
      console.log(`🖱️ atividade ${label ? "(" + label + ")" : ""} -> reset timer`);
      arm();
    },
    stop() {
      stopped = true;
      if (t) clearTimeout(t);
      t = null;
    },
    getLockedCount() { return lockedCount; }
  };
}

async function main() {
  const WALLET_PASS = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET_WALLET = process.env.RESET_WALLET === "1";

  const walletPath = path.resolve("./teste-node/wallets/test_wallet_auto_timeout_loop.db");

  if (RESET_WALLET) {
    console.log("🧹 RESET_WALLET=1: limpando artefatos...");
    rmWalletArtifacts(walletPath);
  }

  const agent = new addon.IndyAgent();

  console.log("1) Criando wallet...");
  await agent.walletCreate(walletPath, WALLET_PASS);

  console.log("2) Unlock (abrindo wallet)...");
  await agent.walletUnlock(walletPath, WALLET_PASS);

  console.log("3) Configurando auto-timeout...");
  const TIMEOUT_MS = 800;
  const TOUCH_EVERY_MS = 200;   // menor que TIMEOUT_MS
  const LOOP_COUNT = 10;        // 10 toques -> ~2s de atividade

  const auto = makeAutoLock(agent, TIMEOUT_MS);
  auto.start();

  console.log(`4) Atividade em loop: ${LOOP_COUNT} touches a cada ${TOUCH_EVERY_MS}ms (timeout=${TIMEOUT_MS}ms)`);
  for (let i = 1; i <= LOOP_COUNT; i++) {
    await sleep(TOUCH_EVERY_MS);
    auto.touch(`loop#${i}`);
    must(auto.getLockedCount() === 0, "não deveria ter auto-lock durante atividade em loop");
    const info = JSON.parse(await agent.walletInfo(walletPath));
    must(info.status.is_open_for_path === true, "wallet deveria permanecer aberta durante atividade");
  }

  console.log("5) Parando atividade e aguardando timeout + folga (deve travar uma vez)...");
  await sleep(TIMEOUT_MS + 300);

  // folga pro callback async rodar
  await sleep(200);

  must(auto.getLockedCount() === 1, "auto-lock deveria disparar exatamente 1 vez após parar atividade");

  console.log("6) Confirmando wallet fechada...");
  const info2 = JSON.parse(await agent.walletInfo(walletPath));
  must(info2.status.is_open_any === false, "wallet deveria estar fechada após auto-lock");
  must(info2.status.is_open_for_path === false, "wallet deveria estar fechada para o path");

  console.log("7) Unlock novamente e finalizando...");
  await agent.walletUnlock(walletPath, WALLET_PASS);
  auto.stop();
  await agent.walletClose();

  console.log("✅ OK: teste auto-timeout com atividade em loop passou.");
}

main().catch((e) => {
  console.error("❌ FALHA:", e);
  process.exit(1);
});
