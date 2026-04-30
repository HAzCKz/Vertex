/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
RESET_WALLET=1 \
WALLET_PASS="minha_senha_teste" \
GENESIS_FILE=./von_genesis.txn \
TRUSTEE_SEED="000000000000000000000000Trustee1" \
TRUSTEE_DID="V4SGRU86Z58d6TV7PBUe6f" \
node teste-node/revocation/test_revocation_35_duplicate_k_index_rejected_von.js
*/

/*
Teste negativo de verificação com índice K duplicado.

O fluxo:
- cria um contexto de verificação com prova válida;
- clona a prova original;
- adultera a lista k_indices para repetir um índice já usado;
- envia a prova alterada para verificação.

Depois valida:
- a verificação falha como esperado;
- a biblioteca rejeita a prova com erro;
- a mensagem informa que há índice repetido.

Foco do teste:
validar que verifyPresentationRevocationProof rejeita
provas com k_indices duplicados.
*/
const { assert } = require("./_helpers");
const { createNegativeVerificationContext } = require("./_negative_verification_von_helper");

(async () => {
  const ctx = await createNegativeVerificationContext("neg_idx_dup_35");
  try {
    console.log("🚀 TESTE REVOGAÇÃO 35: índice K repetido deve ser rejeitado");

    const tamperedProof = JSON.parse(JSON.stringify(ctx.proof));
    tamperedProof.t_entry.k_indices[1] = tamperedProof.t_entry.k_indices[0];

    let error = null;
    try {
      await ctx.verifyPresentationRevocationProof(JSON.stringify(tamperedProof));
    } catch (e) {
      error = e;
    }

    assert(error, "a verificação deveria falhar com índice duplicado");
    assert(
      /repetido/i.test(String(error.message || error)),
      "a mensagem deveria indicar índice repetido"
    );

    console.log("✅ OK: TESTE REVOGAÇÃO 35 passou.");
  } finally {
    await ctx.close();
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 35:", e && e.stack ? e.stack : e);
  process.exit(1);
});
