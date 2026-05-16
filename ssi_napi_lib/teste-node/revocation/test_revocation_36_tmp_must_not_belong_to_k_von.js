/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
RESET_WALLET=1 \
WALLET_PASS="minha_senha_teste" \
GENESIS_FILE=./von_genesis.txn \
TRUSTEE_SEED="000000000000000000000000Trustee1" \
TRUSTEE_DID="V4SGRU86Z58d6TV7PBUe6f" \
node teste-node/revocation/test_revocation_36_tmp_must_not_belong_to_k_von.js
*/

/*
Teste negativo de verificação com tmp_i inválido.

O fluxo:
- cria um contexto de verificação com prova válida;
- clona a prova original;
- adultera tmp_b64 para usar um valor que pertence ao vetor K;
- envia a prova alterada para verificação.

Depois valida:
- a verificação falha como esperado;
- a biblioteca rejeita a prova com erro;
- a mensagem informa que tmp_i não pode pertencer ao vetor K.

Foco do teste:
validar que verifyPresentationRevocationProof rejeita
provas em que tmp_i reutiliza um valor do vetor K.
*/

const { assert } = require("./_helpers");
const { createNegativeVerificationContext } = require("./_negative_verification_von_helper");

(async () => {
  const ctx = await createNegativeVerificationContext("neg_tmp_in_k_36");
  try {
    console.log("🚀 TESTE REVOGAÇÃO 36: tmp_i pertencendo a K deve ser rejeitado");

    const tamperedProof = JSON.parse(JSON.stringify(ctx.proof));
    tamperedProof.t_entry.tmp_b64 = ctx.kVectorValues[0];

    let error = null;
    try {
      await ctx.verifyPresentationRevocationProof(JSON.stringify(tamperedProof));
    } catch (e) {
      error = e;
    }

    assert(error, "a verificação deveria falhar quando tmp_i pertence a K");
    assert(
      /tmp_i pertence ao vetor K/i.test(String(error.message || error)),
      "a mensagem deveria indicar tmp_i pertencendo a K"
    );

    console.log("✅ OK: TESTE REVOGAÇÃO 36 passou.");
  } finally {
    await ctx.close();
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 36:", e && e.stack ? e.stack : e);
  process.exit(1);
});
