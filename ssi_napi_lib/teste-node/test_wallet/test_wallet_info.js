/*
PARA RODAR:
WALLET_PASS="minha_senha_teste" RESET_WALLET=1 node teste-node/test_wallet/test_wallet_info.js
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

  const walletPath = path.resolve("./teste-node/wallets/test_wallet_info.db");

  if (RESET_WALLET) {
    console.log("🧹 RESET_WALLET=1: limpando artefatos...");
    rmWalletArtifacts(walletPath);
  }

  const agent = new addon.IndyAgent();

  console.log("1) wallet_info em wallet inexistente (não deve explodir)...");
  const info0 = JSON.parse(await agent.walletInfo(walletPath));
  must(info0.ok === true, "info0.ok deveria ser true");
  must(info0.files.db_exists === false, "db_exists deveria ser false para inexistente");

  console.log("2) Criando wallet...");
  await agent.walletCreate(walletPath, WALLET_PASS);

  console.log("3) wallet_info após criação (fechada)...");
  const info1 = JSON.parse(await agent.walletInfo(walletPath));
  must(info1.files.db_exists === true, "db_exists deveria ser true");
  must(info1.files.sidecar_exists === true, "sidecar_exists deveria ser true");
  must(info1.sidecar.parse_ok === true, "sidecar.parse_ok deveria ser true");
  must(info1.status.is_open_any === false, "wallet não deveria estar aberta ainda");
  must(info1.status.is_open_for_path === false, "não deveria estar aberta para o path");

  console.log("4) Abrindo wallet...");
  await agent.walletOpen(walletPath, WALLET_PASS);

  console.log("5) wallet_info com wallet aberta...");
  const info2 = JSON.parse(await agent.walletInfo(walletPath));
  must(info2.status.is_open_any === true, "deveria haver wallet aberta");
  must(info2.status.is_open_for_path === true, "deveria estar aberta para este path");

  console.log("6) Fechando wallet...");
  await agent.walletClose();

  console.log("7) wallet_info após close...");
  const info3 = JSON.parse(await agent.walletInfo(walletPath));
  must(info3.status.is_open_any === false, "não deveria haver wallet aberta");
  must(info3.status.is_open_for_path === false, "não deveria estar aberta para o path");

  console.log("✅ OK: teste wallet_info passou.");
}

main().catch((e) => {
  console.error("❌ FALHA:", e);
  process.exit(1);
});
