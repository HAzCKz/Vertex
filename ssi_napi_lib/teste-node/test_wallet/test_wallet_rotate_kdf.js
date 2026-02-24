/*
PARA RODAR:
WALLET_PASS="minha_senha_teste" RESET_WALLET=1 node teste-node/test_wallet/test_wallet_rotate_kdf.js
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

function readSidecar(walletPath) {
  const p = `${walletPath}.kdf.json`;
  must(fs.existsSync(p), `sidecar não existe: ${p}`);
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

async function main() {
  const WALLET_PASS = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET_WALLET = process.env.RESET_WALLET === "1";

  const walletPath = path.resolve("./teste-node/wallets/test_wallet_rotate_kdf.db");

  if (RESET_WALLET) {
    console.log("🧹 RESET_WALLET=1: limpando artefatos...");
    rmWalletArtifacts(walletPath);
  }

  const agent = new addon.IndyAgent();

  console.log("1) Criando wallet...");
  await agent.walletCreate(walletPath, WALLET_PASS);

  console.log("2) Lendo sidecar inicial...");
  const sc1 = readSidecar(walletPath);
  must(sc1.kdf === "argon2id", "sidecar inicial deveria ser argon2id");

  console.log("3) Rotacionando KDF (mesma senha, params diferentes)...");
  // muda params para garantir que houve upgrade/alteração
  const NEW_M = 131072; // 128 MiB
  const NEW_T = 4;
  const NEW_P = 1;

  const ok = await agent.walletRotateKdf(walletPath, WALLET_PASS, NEW_M, NEW_T, NEW_P);
  must(ok === true, "walletRotateKdf deveria retornar true");

  console.log("4) Lendo sidecar após rotação...");
  const sc2 = readSidecar(walletPath);

  must(sc2.kdf === "argon2id", "sidecar após rotação deveria ser argon2id");
  must(sc2.m_cost_kib === NEW_M, "m_cost_kib não foi atualizado");
  must(sc2.t_cost === NEW_T, "t_cost não foi atualizado");
  must(sc2.p_cost === NEW_P, "p_cost não foi atualizado");
  must(sc2.salt_b64 && sc1.salt_b64 && sc2.salt_b64 !== sc1.salt_b64, "salt não foi rotacionado");

  console.log("5) Verificando que a senha antiga ainda abre (verify_pass)...");
  const v1 = await agent.walletVerifyPass(walletPath, WALLET_PASS);
  must(v1 === true, "walletVerifyPass deveria retornar true após rotação");

  console.log("6) Verificando senha errada (verify_pass=false)...");
  const v2 = await agent.walletVerifyPass(walletPath, "senha_errada");
  must(v2 === false, "walletVerifyPass deveria retornar false com senha errada");

  console.log("7) Abrindo e fechando wallet após rotação...");
  await agent.walletOpen(walletPath, WALLET_PASS);
  await agent.walletClose();

  console.log("✅ OK: teste rotação de KDF passou.");
}

main().catch((e) => {
  console.error("❌ FALHA:", e);
  process.exit(1);
});
