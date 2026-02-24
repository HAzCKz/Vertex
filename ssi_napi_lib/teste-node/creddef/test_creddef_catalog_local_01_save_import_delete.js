/* 
PARA RODAR:
WALLET_PASS="minha_senha_teste" RESET_WALLET=1 node teste-node/creddef/test_creddef_catalog_local_01_save_import_delete.js
*/

// Esse teste garante que seu módulo de CredDef “local catalog” atende requisitos típicos de MVP
// offline-first:
// persistência local confiável
// operações idempotentes (save e delete)
// portabilidade via export/import entre instâncias
// resolução de colisão no import (não sobrescreve sem querer)

const path = require("path");
const fs = require("fs");
const os = require("os");

const addon = require("../../index.node"); // ajuste se seu binding for outro caminho

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

  // compat com versões antigas, se existirem no seu ambiente
  try { fs.unlinkSync(`${walletDbPath}.sidecar.json`); } catch (_) { }
  try { fs.unlinkSync(`${walletDbPath}.passbackup.json`); } catch (_) { }
  try { fs.unlinkSync(`${walletDbPath}.sidecar`); } catch (_) { }
}

async function main() {
  const WALLET_PASS = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET_WALLET = process.env.RESET_WALLET === "1";

  const walletA = path.resolve("./teste-node/wallets/test_wallet_creddef_cat_A.db");
  const walletB = path.resolve("./teste-node/wallets/test_wallet_creddef_cat_B.db");

  if (RESET_WALLET) {
    console.log("🧹 RESET_WALLET=1: removendo wallet artifacts...");
    rmWalletArtifacts(walletA);
    rmWalletArtifacts(walletB);
  }

  const agentA = new addon.IndyAgent();
  const agentB = new addon.IndyAgent();

  console.log("1) Criando wallets...");
  await agentA.walletCreate(walletA, WALLET_PASS);
  await agentB.walletCreate(walletB, WALLET_PASS);

  console.log("2) Abrindo wallets...");
  await agentA.walletOpen(walletA, WALLET_PASS);
  await agentB.walletOpen(walletB, WALLET_PASS);

  // Dados “fake” (catálogo local não exige ledger)
  // Importante: como é “catálogo local”, esses identificadores não precisam existir no ledger. É um teste de persistência/gestão local.
  const issuerDid = "V4SGRU86Z58d6TV7PBUe6f";
  const schemaId = "schema:local:cpf-v1";
  const tag = "TAG1";
  const env = "test";

  console.log("3) Save local (idempotente)...");
  const a1 = await agentA.creddefSaveLocal(issuerDid, schemaId, tag, false, env);
  const a2 = await agentA.creddefSaveLocal(issuerDid, schemaId, tag, false, env);

  const r1 = JSON.parse(a1);
  const r2 = JSON.parse(a2);

  // ✅ Isso valida que salvar a mesma CredDef local duas vezes não duplica: retorna o mesmo id_local.
  // Ou seja: “mesma chave lógica” → “mesmo registro local”.
  must(r1.id_local === r2.id_local, "Save não foi idempotente (id_local diferente).");

  console.log("4) Export -> arquivo...");

  // Isso valida que existe um “pacote” exportável (provavelmente com campos como issuer_did, 
  // schema_id, tag, etc.) para transportar para outra instância.
  const exported = await agentA.creddefExportLocal(r1.id_local);
  const pkgPath = tmpFile("creddef_export_pkg.json");
  fs.writeFileSync(pkgPath, exported, "utf8");
  console.log("   pkg:", pkgPath);

  console.log("5) Import no B (new_id em colisão)...");
  // Import repetido não sobrescreve o anterior: cria um novo id_local quando há colisão.
  const imported1 = await agentB.creddefImportLocal(fs.readFileSync(pkgPath, "utf8"));
  const imported2 = await agentB.creddefImportLocal(fs.readFileSync(pkgPath, "utf8"));

  const i1 = JSON.parse(imported1);
  const i2 = JSON.parse(imported2);

  must(i1.id_local !== i2.id_local, "Import não gerou new_id em colisão (id_local igual).");
  must(i1.issuer_did === issuerDid, "issuer_did inconsistente no import.");
  must(i1.schema_id === schemaId, "schema_id inconsistente no import.");
  must(i1.tag === tag, "tag inconsistente no import.");

  console.log("6) Delete local...");
  const del1 = await agentB.creddefDeleteLocal(i1.id_local);
  const del2 = await agentB.creddefDeleteLocal(i1.id_local);

  // Isso valida que delete é idempotente: repetir não dá erro e sinaliza corretamente.
  must(del1 === true, "Delete deveria retornar true na primeira vez.");
  must(del2 === false, "Delete deveria retornar false na segunda vez (idempotente).");

  console.log("✅ OK: teste catálogo CredDef local passou.");

  console.log("7) Fechando wallets...");
  await agentA.walletClose();
  await agentB.walletClose();
}

main().catch((e) => {
  console.error("❌ FALHA:", e);
  process.exit(1);
});
