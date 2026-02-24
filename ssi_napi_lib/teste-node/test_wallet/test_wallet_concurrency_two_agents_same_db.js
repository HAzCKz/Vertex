/*
PARA RODAR:
WALLET_PASS="minha_senha_teste" RESET_WALLET=1 node teste-node/test_wallet/test_wallet_concurrency_two_agents_same_db.js
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

function fmtErr(e) {
  const msg = String(e?.message || e);
  return msg.length > 500 ? msg.slice(0, 500) + "..." : msg;
}

function looksLikeBusyOrLocked(msg) {
  const s = (msg || "").toLowerCase();
  // cobre sqlite, askar e erros genéricos
  return (
    s.includes("busy") ||
    s.includes("locked") ||
    s.includes("database is locked") ||
    s.includes("sqlite") && s.includes("locked") ||
    s.includes("walletopenfailed") ||
    s.includes("failed to open") ||
    s.includes("io error") ||
    s.includes("permission denied")
  );
}

async function main() {
  const WALLET_PASS = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET_WALLET = process.env.RESET_WALLET === "1";

  const walletPath = path.resolve("./teste-node/wallets/test_wallet_concurrency_same_db.db");

  if (RESET_WALLET) {
    console.log("🧹 RESET_WALLET=1: limpando artefatos...");
    rmWalletArtifacts(walletPath);
  }

  const agentA = new addon.IndyAgent();
  const agentB = new addon.IndyAgent();

  console.log("1) Criando wallet (uma vez só)...");
  await agentA.walletCreate(walletPath, WALLET_PASS);

  console.log("2) Agent A: unlock (abre a wallet e mantém aberta)...");
  await agentA.walletUnlock(walletPath, WALLET_PASS);

  console.log("3) Agent A: wallet_info (aberta)...");
  const infoA1 = JSON.parse(await agentA.walletInfo(walletPath));
  must(infoA1.status.is_open_for_path === true, "Agent A deveria estar com a wallet aberta");

  console.log("4) Agent B: tentando unlock enquanto Agent A está aberto...");
  let bOpenedWhileAOpen = false;
  try {
    await agentB.walletUnlock(walletPath, WALLET_PASS);
    bOpenedWhileAOpen = true;
    console.log("⚠️ Agent B conseguiu abrir enquanto A estava aberto (depende do locking/askar/sqlite).");
  } catch (e) {
    const msg = fmtErr(e);
    console.log("✅ Agent B falhou ao abrir enquanto A está aberto (esperado em concorrência):", msg);
    must(
      looksLikeBusyOrLocked(msg) || msg.includes("WalletOpenFailed") || msg.includes("GenericFailure"),
      "Falha do Agent B não parece relacionada a concorrência/lock (ver msg acima)."
    );
  }

  console.log("5) Agent B: wallet_lock mesmo sem estar aberto (idempotente)...");
  const lockB = await agentB.walletLock();
  must(lockB === true, "walletLock do Agent B deveria retornar true (mesmo se não abriu)");

  if (bOpenedWhileAOpen) {
    console.log("6) Agent B abriu; fechando B para seguir o teste...");
    await agentB.walletClose();

    const infoB1 = JSON.parse(await agentB.walletInfo(walletPath));
    must(infoB1.status.is_open_any === false, "Agent B deveria estar fechado após close");
  }

  console.log("7) Agent A: lock (fecha a wallet)...");
  const lockA = await agentA.walletLock();
  must(lockA === true, "walletLock do Agent A deveria retornar true");

  console.log("8) Pequena folga para liberar locks do SQLite...");
  await sleep(150);

  console.log("9) Agent B: tentando unlock novamente (agora deve abrir)...");
  await agentB.walletUnlock(walletPath, WALLET_PASS);

  const infoB2 = JSON.parse(await agentB.walletInfo(walletPath));
  must(infoB2.status.is_open_for_path === true, "Agent B deveria conseguir abrir após A fechar");

  console.log("10) Fechando tudo...");
  await agentB.walletClose();

  console.log("✅ OK: teste concorrência 2 agentes (mesmo SQLite) passou.");
}

main().catch((e) => {
  console.error("❌ FALHA:", e);
  process.exit(1);
});
