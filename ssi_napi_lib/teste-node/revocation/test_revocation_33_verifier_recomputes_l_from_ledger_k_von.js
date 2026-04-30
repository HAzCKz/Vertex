/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
RESET_WALLET=1 \
WALLET_PASS="minha_senha_teste" \
GENESIS_FILE=./von_genesis.txn \
TRUSTEE_SEED="000000000000000000000000Trustee1" \
TRUSTEE_DID="V4SGRU86Z58d6TV7PBUe6f" \
node teste-node/revocation/test_revocation_33_verifier_recomputes_l_from_ledger_k_von.js
*/

/*
Teste de verificação local em que o verifier recompõe L_i
usando o vetor K obtido do ledger.

O fluxo:
- cria um contexto de verificação com prova válida e vetor K já resolvido;
- recompõe em JavaScript o valor L_i a partir dos índices K e do tmp da prova;
- compara o L_i recomposto com o l_value enviado na prova;
- envia a prova para a verificação normal da biblioteca.

Depois valida:
- o L_i recomposto localmente coincide com o l_value da prova;
- a resposta da biblioteca retorna ok=true;
- a prova é aceita com verified=true;
- sem manifesto/Bloom, o status permanece revoked=false.

Foco do teste:
validar que o verifier consegue recomputar o L_i corretamente
a partir do K do ledger e confirmar a consistência da prova.
*/

const crypto = require("crypto");
const { assert, parseJsonSafe } = require("./_helpers");
const { createNegativeVerificationContext } = require("./_negative_verification_von_helper");

function recomputeLValueFromProofAndK(proof, kVectorValues) {
  const buffers = [];
  for (const idx of proof.t_entry.k_indices) {
    const valueB64 = kVectorValues[idx];
    if (!valueB64) {
      throw new Error(`Índice K ausente na recomputação local: ${idx}`);
    }
    buffers.push(Buffer.from(valueB64, "base64"));
  }
  buffers.push(Buffer.from(proof.t_entry.tmp_b64, "base64"));

  return crypto
    .createHash("sha3-256")
    .update(Buffer.concat(buffers))
    .digest("base64");
}

(async () => {
  const ctx = await createNegativeVerificationContext("pos_recompute_l_33");
  try {
    console.log("🚀 TESTE REVOGAÇÃO 33: verifier recompõe L_i a partir do K do ledger");

    const recomputedL = recomputeLValueFromProofAndK(ctx.proof, ctx.kVectorValues);
    assert(
      recomputedL === ctx.proof.l_value,
      "o L_i recomposto em JS deveria coincidir com o l_value da prova"
    );

    const response = parseJsonSafe(
      await ctx.verifyPresentationRevocationProof(JSON.stringify(ctx.proof)),
      "verify_response"
    );

    assert(response.ok === true, "a resposta deveria vir com ok=true");
    assert(
      response.status.verified === true,
      "a prova válida deveria ser aceita após a recomputação de L_i com o K do ledger"
    );
    assert(
      response.status.revoked === false,
      "sem manifesto/Bloom a prova válida não deveria aparecer como revogada"
    );

    console.log("✅ OK: TESTE REVOGAÇÃO 33 passou.");
  } finally {
    await ctx.close();
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 33:", e && e.stack ? e.stack : e);
  process.exit(1);
});
