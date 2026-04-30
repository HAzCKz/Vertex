/*
Este teste valida a qualidade da aleatoriedade local usada na geração de um
pacote de credencial revogável, sem depender de ledger, verifier ou serviço
externo de Bloom. O foco é a função createRevocableCredentialPackage(), que
gera, para várias janelas temporais, subconjuntos de índices K, valores
temporários tmp e valores finais Li. O teste verifica se o número de janelas
gerado corresponde ao valor configurado em REVOCATION_RANDOM_WINDOWS, se cada
janela contém exatamente 32 índices válidos e sem repetição interna, se não há
repetição do mesmo subconjunto K entre janelas diferentes, se cada tmp e cada
Li é distinto por janela, e se todos os elementos do vetor K aparecem ao menos
uma vez ao longo da execução. Além disso, ele mede propriedades estatísticas da
distribuição: calcula a frequência de uso de cada índice de K, o qui-quadrado
em relação à frequência esperada, a frequência mínima e máxima observadas, a
sobreposição média entre subconjuntos consecutivos e a proporção de bits 1 nos
valores Li. Com isso, o teste tenta detectar vieses, repetição indevida,
cobertura insuficiente do vetor K ou padrões anormais nos valores gerados,
funcionando como um teste estatístico/sanitário da entropia operacional do
mecanismo local de revogação.
*/
/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
RESET_WALLET=1 \
WALLET_PASS="minha_senha_teste" \
REVOCATION_RANDOM_WINDOWS=2048 \
node teste-node/revocation/test_revocation_30_li_randomness_local.js
*/

/*
Teste local de sanidade estatística da aleatoriedade
usada na geração de pacotes de credenciais revogáveis.

O fluxo:
- cria/abre a wallet do emissor;
- gera um pacote revogável com múltiplas janelas temporais;
- extrai os subconjuntos K, os valores tmp e os valores Li;
- mede cobertura, repetição, sobreposição e distribuição dos dados gerados.

Depois valida:
- o número de janelas gerado confere com o configurado;
- cada janela possui 32 índices K válidos e sem repetição interna;
- não há repetição do mesmo subconjunto K entre janelas;
- tmp e Li são distintos em cada janela;
- todos os elementos do vetor K aparecem ao menos uma vez;
- as métricas estatísticas ficam dentro de faixas aceitáveis
  (qui-quadrado, frequência mínima/máxima, sobreposição média e proporção de bits 1).

Foco do teste:
validar a qualidade da aleatoriedade local de
createRevocableCredentialPackage(), sem depender de ledger,
verifier ou serviço externo de Bloom.
*/
const path = require("path");
const {
  assert,
  loadIndyAgent,
  fn,
  parseJsonSafe,
  walletCreateOpenIdempotent,
  cleanupWalletFamily,
  ensureWalletDir,
  makeKValues,
  sampleManifest,
  sampleKLedgerAnchor,
  sampleCredentialJson,
} = require("./_helpers");

const REQUIRED_EXTRA_WINDOWS_FOR_FP = 10;

const BIT_COUNTS = new Uint8Array(256);
for (let i = 0; i < 256; i += 1) {
  let count = 0;
  let value = i;
  while (value) {
    value &= value - 1;
    count += 1;
  }
  BIT_COUNTS[i] = count;
}

function countOnes(buffer) {
  let total = 0;
  for (const byte of buffer) total += BIT_COUNTS[byte];
  return total;
}

function signatureForSubset(indices) {
  return [...indices].sort((a, b) => a - b).join(",");
}

function overlapSize(a, b) {
  let total = 0;
  for (const value of a) {
    if (b.has(value)) total += 1;
  }
  return total;
}

(async () => {
  const IndyAgent = loadIndyAgent();
  const pass = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET = process.env.RESET_WALLET === "1";
  const N = Number(process.env.REVOCATION_RANDOM_WINDOWS || "2048");

  if (!Number.isInteger(N) || N < 128) {
    throw new Error("REVOCATION_RANDOM_WINDOWS deve ser inteiro >= 128");
  }

  const walletDir = ensureWalletDir();
  const issuerDb =
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_randomness_30.db");

  if (RESET) cleanupWalletFamily(issuerDb);

  const issuer = new IndyAgent();
  await walletCreateOpenIdempotent(issuer, issuerDb, pass);

  try {
    const createRevocableCredentialPackage = fn(
      issuer,
      "createRevocableCredentialPackage",
      "create_revocable_credential_package"
    );

    console.log("🚀 TESTE REVOGAÇÃO 30: aleatoriedade dos subconjuntos de K e dos Li");

    const now = Math.floor(Date.now() / 1000);
    const validityEnd = now + ((N - 1) * 3600);
    const issuerDid = "did:example:issuer:randomness:001";
    const kValues = makeKValues();
    const kLedgerAnchor = sampleKLedgerAnchor(issuerDid, {
      k_vector_id: `k-vector-randomness-${Date.now()}`,
    });

    const packageJson = await createRevocableCredentialPackage(
      `revocable-randomness-${Date.now()}`,
      "did:example:holder:randomness",
      "mock:creddef:randomness:001",
      "mock:schema:randomness:001",
      sampleCredentialJson(),
      issuerDid,
      JSON.stringify(kValues),
      now,
      validityEnd,
      "hours",
      1,
      REQUIRED_EXTRA_WINDOWS_FOR_FP,
      JSON.stringify(sampleManifest(issuerDid)),
      JSON.stringify(kLedgerAnchor)
    );

    const pkg = parseJsonSafe(packageJson, "revocable_package_randomness");
    const holderBundle = pkg.holder_bundle;
    const tEntries = holderBundle.t_entries;
    const lValues = holderBundle.l_values;
    const tmpVector = holderBundle.tmp_vector_b64;
    const windowCount = pkg.control_values.window_count;

    assert(windowCount === N + REQUIRED_EXTRA_WINDOWS_FOR_FP, `window_count deveria ser ${N + REQUIRED_EXTRA_WINDOWS_FOR_FP}, veio ${windowCount}`);
    assert(tEntries.length === windowCount, "t_entries deveria acompanhar window_count");
    assert(lValues.length === windowCount, "l_values deveria acompanhar window_count");
    assert(tmpVector.length === windowCount, "tmp_vector_b64 deveria acompanhar window_count");

    const subsetSignatures = new Set();
    const tmpSet = new Set();
    const liSet = new Set();
    const indexFrequencies = new Array(kValues.length).fill(0);
    let totalDraws = 0;
    let previousSubset = null;
    let overlapSum = 0;
    let overlapPairs = 0;

    for (const [windowIndex, entry] of tEntries.entries()) {
      assert(Array.isArray(entry.k_indices), `k_indices inválido na janela ${windowIndex}`);
      assert(entry.k_indices.length === 32, `janela ${windowIndex} deveria ter 32 índices`);

      const subset = new Set(entry.k_indices);
      assert(subset.size === 32, `janela ${windowIndex} possui índices repetidos dentro do subconjunto`);

      for (const idx of entry.k_indices) {
        assert(Number.isInteger(idx), `índice não inteiro na janela ${windowIndex}`);
        assert(idx >= 0 && idx < kValues.length, `índice fora da faixa na janela ${windowIndex}: ${idx}`);
        indexFrequencies[idx] += 1;
        totalDraws += 1;
      }

      const signature = signatureForSubset(entry.k_indices);
      assert(
        subsetSignatures.has(signature) === false,
        `subconjunto K repetido entre janelas na assinatura ${signature}`
      );
      subsetSignatures.add(signature);

      const tmpBytes = Buffer.from(entry.tmp_b64, "base64");
      assert(tmpBytes.length === 32, `tmp inválido na janela ${windowIndex}`);
      tmpSet.add(entry.tmp_b64);

      const liBytes = Buffer.from(lValues[windowIndex], "base64");
      assert(liBytes.length === 32, `Li inválido na janela ${windowIndex}`);
      liSet.add(lValues[windowIndex]);

      if (previousSubset) {
        overlapSum += overlapSize(previousSubset, subset);
        overlapPairs += 1;
      }
      previousSubset = subset;
    }

    assert(tmpSet.size === windowCount, "tmp_vector_b64 deveria ter um tmp distinto por janela");
    assert(liSet.size === windowCount, "os valores Li deveriam ser distintos entre si");
    assert(indexFrequencies.every((count) => count > 0), "todo elemento de K deveria aparecer ao menos uma vez");

    const expectedFrequency = totalDraws / kValues.length;
    const chiSquare = indexFrequencies.reduce((sum, observed) => {
      const delta = observed - expectedFrequency;
      return sum + (delta * delta) / expectedFrequency;
    }, 0);
    const minFrequency = Math.min(...indexFrequencies);
    const maxFrequency = Math.max(...indexFrequencies);
    const averageOverlap = overlapPairs > 0 ? overlapSum / overlapPairs : 0;

    let ones = 0;
    let totalBits = 0;
    for (const value of lValues) {
      const bytes = Buffer.from(value, "base64");
      ones += countOnes(bytes);
      totalBits += bytes.length * 8;
    }
    const oneRatio = ones / totalBits;

    console.log("📊 Métricas de aleatoriedade:");
    console.log({
      windows: N,
      subset_signatures: subsetSignatures.size,
      distinct_tmp: tmpSet.size,
      distinct_l: liSet.size,
      total_draws: totalDraws,
      expected_frequency: expectedFrequency,
      min_frequency: minFrequency,
      max_frequency: maxFrequency,
      chi_square: Number(chiSquare.toFixed(3)),
      average_overlap_between_consecutive_windows: Number(averageOverlap.toFixed(3)),
      one_ratio_in_l_bits: Number(oneRatio.toFixed(6)),
    });

    assert(
      chiSquare < 1500,
      `chi-square alto demais para os índices de K: ${chiSquare.toFixed(3)}`
    );
    assert(
      minFrequency >= expectedFrequency * 0.45,
      `frequência mínima muito baixa: ${minFrequency} (esperado ~ ${expectedFrequency})`
    );
    assert(
      maxFrequency <= expectedFrequency * 1.75,
      `frequência máxima muito alta: ${maxFrequency} (esperado ~ ${expectedFrequency})`
    );
    assert(
      averageOverlap >= 0.4 && averageOverlap <= 2.5,
      `sobreposição média suspeita entre subconjuntos consecutivos: ${averageOverlap}`
    );
    assert(
      oneRatio >= 0.49 && oneRatio <= 0.51,
      `proporção de bits 1 em Li fora da faixa esperada: ${oneRatio}`
    );

    console.log("✅ OK: TESTE REVOGAÇÃO 30 passou.");
  } finally {
    try { await issuer.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 30:", e && e.stack ? e.stack : e);
  process.exit(1);
});
