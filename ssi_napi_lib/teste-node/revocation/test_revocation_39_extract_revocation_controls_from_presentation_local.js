/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
node teste-node/revocation/test_revocation_39_extract_revocation_controls_from_presentation_local.js
*/

/*
Teste local de extração dos controles de revogação
a partir de uma apresentação SSI.

O fluxo:
- monta uma apresentação com atributos revelados simples e em grupo;
- inclui 2 credenciais revogáveis e 1 credencial normal;
- chama extractRevocationControlsFromPresentation(...);
- analisa o resultado extraído por sub_proof_index.

Depois valida:
- o retorno vem com ok=true;
- apenas as 2 credenciais revogáveis são extraídas;
- seed, unit_of_time e root_merkle_L são recuperados corretamente;
- o cred_def_id de cada credencial é associado corretamente;
- o slot de origem de cada root_merkle_L é identificado corretamente.

Foco do teste:
validar que extractRevocationControlsFromPresentation
detecta e extrai corretamente os controles de revogação
presentes na apresentação.
*/
const { assert, loadIndyAgent, fn, parseJsonSafe } = require("./_helpers");

(async () => {
  const IndyAgent = loadIndyAgent();
  const agent = new IndyAgent();
  const extractRevocationControlsFromPresentation = fn(
    agent,
    "extractRevocationControlsFromPresentation",
    "extract_revocation_controls_from_presentation"
  );

  try {
    console.log("🚀 TESTE REVOGAÇÃO 39: extração dos controles de revogação da apresentação");

    const presentation = {
      requested_proof: {
        revealed_attrs: {
          nome_referent: { sub_proof_index: 0, raw: "Alice", encoded: "123" },
          seed: { sub_proof_index: 0, raw: "seed-cred-1", encoded: "1" },
          start_time: { sub_proof_index: 0, raw: "1700000000", encoded: "1700000000" },
          unit_of_time: { sub_proof_index: 0, raw: "days", encoded: "1" },
          time_window: { sub_proof_index: 0, raw: "30", encoded: "30" },
          root_merkle_L: { sub_proof_index: 0, raw: "root-cred-1", encoded: "2" },
          curso_referent: { sub_proof_index: 2, raw: "Computacao", encoded: "999" },
        },
        revealed_attr_groups: {
          rev_group_2: {
            sub_proof_index: 1,
            values: {
              seed: { raw: "seed-cred-2", encoded: "11" },
              start_time: { raw: "1800000000", encoded: "1800000000" },
              unit_of_time: { raw: "months", encoded: "12" },
              time_window: { raw: "2", encoded: "2" },
              root_merkle_L: { raw: "root-cred-2", encoded: "22" },
              email: { raw: "alice@example.org", encoded: "33" },
            },
          },
        },
      },
      identifiers: [
        {
          schema_id: "schema:revocable:1",
          cred_def_id: "creddef:revocable:1",
          issuer_id: "issuer:1",
        },
        {
          schema_id: "schema:revocable:2",
          cred_def_id: "creddef:revocable:2",
          issuer_id: "issuer:2",
        },
        {
          schema_id: "schema:normal:1",
          cred_def_id: "creddef:normal:1",
          issuer_id: "issuer:3",
        },
      ],
    };

    const raw = await extractRevocationControlsFromPresentation(
      JSON.stringify(presentation)
    );
    const extracted = parseJsonSafe(raw, "extract_revocation_controls");

    assert(extracted.ok === true, "retorno deveria ter ok=true");
    assert(
      Array.isArray(extracted.revocable_credentials),
      "revocable_credentials deveria ser array"
    );
    assert(
      extracted.revocable_credentials.length === 2,
      `esperado 2 credenciais revogáveis, obtido ${extracted.revocable_credentials.length}`
    );

    const first = extracted.revocable_credentials.find((item) => item.sub_proof_index === 0);
    const second = extracted.revocable_credentials.find((item) => item.sub_proof_index === 1);

    assert(first, "credencial revogável do sub_proof_index 0 não encontrada");
    assert(second, "credencial revogável do sub_proof_index 1 não encontrada");

    assert(first.controls.seed === "seed-cred-1", "seed da primeira credencial incorreto");
    assert(first.controls.unit_of_time === "days", "unit_of_time da primeira credencial incorreto");
    assert(first.controls.root_merkle_L === "root-cred-1", "root_merkle_L da primeira credencial incorreto");
    assert(first.credential_hint.cred_def_id === "creddef:revocable:1", "cred_def_id da primeira credencial incorreto");
    assert(first.slot === "root_merkle_L", `slot inesperado para primeira credencial: ${first.slot}`);

    assert(second.controls.seed === "seed-cred-2", "seed da segunda credencial incorreto");
    assert(second.controls.unit_of_time === "months", "unit_of_time da segunda credencial incorreto");
    assert(second.controls.root_merkle_L === "root-cred-2", "root_merkle_L da segunda credencial incorreto");
    assert(second.credential_hint.cred_def_id === "creddef:revocable:2", "cred_def_id da segunda credencial incorreto");
    assert(
      second.slot === "rev_group_2.root_merkle_L",
      `slot inesperado para segunda credencial: ${second.slot}`
    );

    console.log("✅ OK: TESTE REVOGAÇÃO 39 passou.");
  } catch (e) {
    console.error("❌ FALHA TESTE REVOGAÇÃO 39:", e);
    process.exitCode = 1;
  }
})();
