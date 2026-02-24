/*
PARA RODAR:
WALLET_PASS="minha_senha_teste" RESET_WALLET=1 node teste-node/test_wallet/test_wallet_bundle_export_import.js
*/

const path = require("path");
const fs = require("fs");
const os = require("os");

const addon = require("../../index.node");

function must(cond, msg) {
  if (!cond) throw new Error(msg);
}

function tmpFile(name) {
  return path.join(os.tmpdir(), name);
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

  const walletSrc = path.resolve("./teste-node/wallets/test_wallet_bundle_src.db");
  const walletDst = path.resolve("./teste-node/wallets/test_wallet_bundle_dst.db");

  const bundlePass = "bundle_pass_123";
  const bundlePath = tmpFile("wallet_bundle_export.ssibundle.json");

  if (RESET_WALLET) {
    console.log("🧹 RESET_WALLET=1: limpando artefatos...");
    rmWalletArtifacts(walletSrc);
    rmWalletArtifacts(walletDst);
    try { fs.unlinkSync(bundlePath); } catch (_) { }
    try { fs.unlinkSync(`${bundlePath}.tmp`); } catch (_) { }
  }

  const agent = new addon.IndyAgent();

  // SRC = origem
  // DST = Destino

  console.log("1) Criando wallet SRC...");
  await agent.walletCreate(walletSrc, WALLET_PASS);

  console.log("2) Abrindo SRC (só para validar senha)...");
  await agent.walletOpen(walletSrc, WALLET_PASS);

  console.log("3) Fechando wallet para permitir export...");
  await agent.walletClose();

  console.log("4) Export bundle...");
  const okExp = await agent.walletExportBundle(walletSrc, bundlePath, bundlePass);
  must(okExp === true, "walletExportBundle deveria retornar true");
  must(fs.existsSync(bundlePath), "bundle não foi criado no disco");
  console.log("   bundle:", bundlePath);

  console.log("5) Import bundle para DST (overwrite=false)...");
  rmWalletArtifacts(walletDst); // garante destino vazio
  const okImp = await agent.walletImportBundle(bundlePath, walletDst, bundlePass);
  must(okImp === true, "walletImportBundle deveria retornar true");
  must(fs.existsSync(walletDst), "wallet DST não foi criada");
  must(fs.existsSync(`${walletDst}.kdf.json`), "sidecar DST não foi criado");

  console.log("6) Abrindo DST com WALLET_PASS (deve funcionar)...");
  await agent.walletOpen(walletDst, WALLET_PASS);
  await agent.walletClose();

  console.log("7) Import DST novamente com overwrite=false (deve falhar)...");
  let failed = false;
  try {
    await agent.walletImportBundle(bundlePath, walletDst, bundlePass); // sem overwrite
  } catch (e) {
    failed = true;
    console.log("   esperado falhar:", String(e.message || e));
  }
  must(failed === true, "Import sem overwrite deveria falhar quando destino existe.");

  console.log("8) Import DST novamente com overwrite=true (deve sobrescrever e funcionar)...");
  const okImp2 = await agent.walletImportBundle(bundlePath, walletDst, bundlePass, true);
  must(okImp2 === true, "walletImportBundle overwrite=true deveria retornar true");

  console.log("9) Abrindo DST após overwrite...");
  await agent.walletOpen(walletDst, WALLET_PASS);
  await agent.walletClose();

  console.log("✅ OK: teste export/import bundle passou.");
}

main().catch((e) => {
  console.error("❌ FALHA:", e);
  process.exit(1);
});
