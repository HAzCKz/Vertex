/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
RESET_WALLET=1 \
WALLET_PASS="minha_senha_teste" \
GENESIS_FILE=./von_genesis.txn \
TRUSTEE_SEED="000000000000000000000000Trustee1" \
TRUSTEE_DID="V4SGRU86Z58d6TV7PBUe6f" \
node teste-node/revocation/test_revocation_37_l_value_mismatch_rejected_von.js
*/

/*
Teste negativo de verificação com l_value incompatível.

O fluxo:
- cria um contexto de verificação com prova válida;
- clona a prova original;
- adultera o l_value para um valor aleatório incompatível com K + tmp_i;
- envia a prova alterada para verificação.

Depois valida:
- a verificação retorna verified=false;
- a prova é tratada como inválida;
- a mensagem indica incompatibilidade entre o l_value informado
  e o valor recomposto a partir de K + tmp_i.

Foco do teste:
validar que verifyPresentationRevocationProof detecta
quando o l_value da prova não corresponde ao K e tmp_i.
*/

const { assert, makeKValues, parseJsonSafe } = require("./_helpers");
const { createNegativeVerificationContext } = require("./_negative_verification_von_helper");

(async () => {
  const ctx = await createNegativeVerificationContext("neg_l_mismatch_37");
  try {
    console.log("🚀 TESTE REVOGAÇÃO 37: l_value incompatível com K + tmp_i deve ser rejeitado");

    const tamperedProof = JSON.parse(JSON.stringify(ctx.proof));
    tamperedProof.l_value = makeKValues(1)[0];

    const response = parseJsonSafe(
      await ctx.verifyPresentationRevocationProof(JSON.stringify(tamperedProof)),
      "verify_response"
    );

    assert(
      response.status.verified === false,
      "a verificação deveria marcar a prova como inválida"
    );
    assert(
      /l_value.*recomposto|recomposto.*K e tmp/i.test(String(response.status.details || "")),
      "a mensagem deveria indicar incompatibilidade entre l_value e K + tmp_i"
    );

    console.log("✅ OK: TESTE REVOGAÇÃO 37 passou.");
  } finally {
    await ctx.close();
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 37:", e && e.stack ? e.stack : e);
  process.exit(1);
});
