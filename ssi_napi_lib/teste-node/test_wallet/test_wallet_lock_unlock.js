/*
PARA RODAR:
WALLET_PASS="minha_senha_teste" RESET_WALLET=1 node teste-node/test_wallet/test_wallet_lock_unlock.js
*/

const path = require("path");
const fs = require("fs");
const addon = require("../../index.node");

function must(cond, msg) {
  if (!cond) throw new Error(msg);
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

async function main() {
  const WALLET_PASS = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET_WALLET = process.env.RESET_WALLET === "1";

  const walletPath = path.resolve("./teste-node/wallets/test_wallet_lock_unlock.db");

  if (RESET_WALLET) {
    console.log("🧹 RESET_WALLET=1: limpando artefatos...");
    rmWalletArtifacts(walletPath);
  }

  const agent = new addon.IndyAgent();

  console.log("1) Criando wallet...");
  await agent.walletCreate(walletPath, WALLET_PASS);

  console.log("2) unlock (open)...");
  const u1 = await agent.walletUnlock(walletPath, WALLET_PASS);
  must(u1 === true, "walletUnlock deveria retornar true");

  console.log("3) wallet_info deve indicar aberta...");
  const info1 = JSON.parse(await agent.walletInfo(walletPath));
  must(info1.status.is_open_any === true, "deveria haver wallet aberta");
  must(info1.status.is_open_for_path === true, "deveria estar aberta para o path");

  console.log("4) lock (close)...");
  const l1 = await agent.walletLock();
  must(l1 === true, "walletLock deveria retornar true");

  console.log("5) wallet_info deve indicar fechada...");
  const info2 = JSON.parse(await agent.walletInfo(walletPath));
  must(info2.status.is_open_any === false, "não deveria haver wallet aberta");
  must(info2.status.is_open_for_path === false, "não deveria estar aberta para o path");

  console.log("6) lock novamente (idempotente: não deve falhar)...");
  const l2 = await agent.walletLock();
  must(l2 === true, "walletLock (2x) deveria retornar true");

  console.log("7) unlock novamente...");
  const u2 = await agent.walletUnlock(walletPath, WALLET_PASS);
  must(u2 === true, "walletUnlock (2x) deveria retornar true");

  console.log("8) fechando via walletClose (compat)...");
  await agent.walletClose();

  console.log("✅ OK: teste lock/unlock passou.");
}

main().catch((e) => {
  console.error("❌ FALHA:", e);
  process.exit(1);
});
