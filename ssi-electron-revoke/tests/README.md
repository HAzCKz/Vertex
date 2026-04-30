# BlindRevoke Benchmarks

Esta pasta concentra os scripts de benchmark para a seção de avaliacao experimental do BlindRevoke.

## Arquivos

- `blindrevoke-bench.js`: CLI principal para executar os benchmarks.
- `blindrevoke.config.example.json`: modelo de configuracao.
- `benchmarks/utils.js`: utilitarios de serializacao, estatistica e escrita de resultados.

## Preparacao

1. Crie uma copia do arquivo de exemplo:

```bash
cp tests/blindrevoke.config.example.json tests/blindrevoke.config.json
```

2. Ajuste pelo menos:

- `walletPath`
- `walletPass`
- `genesisPath`
- `manifestUrl`
- `bloomAdminToken`
- `bloomBootstrap.resetBeforeRun`
- `identities.submitter.seed`
- `identities.submitter.did` se o DID derivado da seed no seu ledger nao for o padrao

Os caminhos do JSON de configuracao agora sao resolvidos priorizando a raiz do projeto atual. Assim, `./genesis.txn` funciona como esperado quando voce roda os comandos a partir de `/home/yugi/programacao/ssi-electron`.

Se o seu ledger nao usa o Trustee padrao, troque o bloco:

```json
"identities": {
  "submitter": {
    "seed": "SUA_SEED_PRIVILEGIADA",
    "did": "SEU_DID_PRIVILEGIADO"
  },
  "issuer": {
    "role": "ENDORSER",
    "registerOnLedger": true
  }
}
```

Por padrao, o benchmark registra o DID do emissor com `role = ENDORSER`, porque esse papel costuma ser necessario para publicar `SCHEMA`, `CRED_DEF` e escrever `ATTRIB` no ledger.

Ao criar o schema automaticamente, o benchmark tambem injeta os atributos obrigatorios do BlindRevoke:

- `seed`
- `start_time`
- `unit_of_time`
- `time_window`
- `root_merkle_L`

Assim, em `schema.attributes` voce precisa informar apenas os atributos de negocio. Os atributos de controle sao acrescentados automaticamente para permitir a emissao de credenciais revogaveis.

Antes de iniciar a campanha, o benchmark agora faz um preflight automatico do servico Bloom:

- reseta o filtro usando `POST /test/reset`
- invalida o setup de revogacao em cache
- reancora no ledger o manifesto lido em `manifestUrl`

Esse comportamento fica ativo por padrao quando `bloomBootstrap.resetBeforeRun = true`. Se voce quiser desativar o reset automatico, ajuste esse campo para `false`.

Para a campanha nao ficar artificialmente lenta, o benchmark nao reancora o manifesto no ledger a cada revogacao por padrao. Isso fica controlado por `revocation.anchorManifestAfterWrite`, que sai como `false` porque as medicoes de escrita/leitura do Bloom nao devem incluir o custo extra de um `ATTRIB` no ledger. O manifesto continua sendo refrescado antes das verificacoes para manter consistencia.

Se voce ja possui um DID emissor registrado no ledger, pode evitar o registro automatico:

```json
"identities": {
  "submitter": {
    "seed": "SUA_SEED_PRIVILEGIADA",
    "did": "SEU_DID_PRIVILEGIADO"
  },
  "issuer": {
    "did": "DID_EMISSOR_JA_REGISTRADO",
    "verkey": "VERKEY_DO_EMISSOR",
    "role": "ENDORSER",
    "registerOnLedger": false
  }
}
```

3. Para o experimento de falso positivo, configure `filterProfiles.falsePositive.manifestUrl` apontando para um servico Bloom com filtro menor e informe tambem `filterBits` (e opcionalmente `kHashes`), pois o benchmark agora envia esses parametros no `POST /test/reset`. O perfil padrao `m = 16777216` e `345238` entradas tende a produzir poucos falsos positivos observaveis.
4. Garanta tambem um `falsePositive.fillerCredentialCount` maior que zero, porque sao esses fillers revogados que carregam o Bloom para o experimento de falso positivo.

Se esse segundo servico Bloom nao estiver ativo, a campanha `bench:all` pode continuar mesmo assim quando `falsePositive.skipIfServiceUnavailable = true`. Nesse caso, o benchmark de falso positivo sai no relatorio com status `skipped` e o motivo correspondente.

## Comandos

### Forma mais simples

Depois de criar `tests/blindrevoke.config.json`, voce pode rodar tudo com:

```bash
npm run bench:campaign
npm run bench:all
```

Isso executa a campanha completa e gera automaticamente:

- os JSONs brutos de cada benchmark
- os CSVs de apoio
- um relatorio consolidado em `report/paper-summary.md`
- tabelas separadas em Markdown e CSV prontas para o paper

Ou executar apenas um bloco especifico:

```bash
npm run bench:issue
npm run bench:verify
npm run bench:false-positive
npm run bench:proof-size
npm run bench:throughput
npm run bench:k-ledger
```

### Launcher direto

Tambem da para usar o launcher de shell, que facilita automacao em script, cron ou CI:

```bash
./tests/run-blindrevoke-bench.sh
./tests/run-blindrevoke-bench.sh campaign
./tests/run-blindrevoke-bench.sh verify-latency
```

Por padrao ele usa `tests/blindrevoke.config.json`.

Se quiser trocar config ou pasta de saida sem editar o comando:

```bash
BLINDREVOKE_BENCH_CONFIG=tests/blindrevoke.config.json \
BLINDREVOKE_BENCH_OUTPUT_DIR=tests/results/manual \
./tests/run-blindrevoke-bench.sh campaign
```

### Comandos completos

```bash
npm run bench:blindrevoke -- campaign --config tests/blindrevoke.config.json
npm run bench:blindrevoke -- all --config tests/blindrevoke.config.json
npm run bench:blindrevoke -- issue-metrics --config tests/blindrevoke.config.json
npm run bench:blindrevoke -- verify-latency --config tests/blindrevoke.config.json
npm run bench:blindrevoke -- false-positive --config tests/blindrevoke.config.json
npm run bench:blindrevoke -- proof-payload-size --config tests/blindrevoke.config.json
npm run bench:blindrevoke -- bloom-throughput --config tests/blindrevoke.config.json
npm run bench:blindrevoke -- k-vector-ledger-write --config tests/blindrevoke.config.json
```

## O que cada benchmark mede

### `issue-metrics`

Gera credenciais revogaveis com diferentes quantidades de janelas e coleta:

- tempo de emissao da credencial revogavel
- tamanho do pacote revogavel
- tamanho do `holder_bundle`
- tamanho do envelope authcrypt enviado ao holder
- `manifestBytes`
- `chunkCount` do vetor `K`

### `verify-latency`

Para `100`, `365`, `1000`, `5000` e `10000` janelas, mede:

- tempo total de verificacao
- numero de janelas efetivamente consultadas
- modo usado: `binary_window_search` ou `full_window_scan`
- cenarios `not_revoked`, `revoked_early`, `revoked_middle` e `revoked_late`
- repeticoes controladas por `verifyIterations`, com aquecimentos em `verifyWarmups`

### `false-positive`

Executa verificacoes em credenciais nao revogadas e observa:

- falsos positivos confirmados e depois refutados
- falsos positivos que escapariam da refutacao
- latencia e quantidade de janelas consultadas

### `proof-payload-size`

Mede o tamanho do pacote completo de apresentacao entregue pelo Holder ao Verifier:

- payload completo de apresentacao revogavel
- envelope criptografado via `authcrypt`
- todas as janelas disponiveis daquela credencial, incluindo as janelas extras de confirmacao de falso positivo
- tempo total de montagem e sua divisao entre prova revogavel, serializacao do payload e `authcrypt`
- tabela diagnostica adicional com tempos separados de `createPresentation`, `primary proof` e `buildPresentationRevocationProofV2` completo
- o tempo de confirmacoes e mostrado como estimativa: `sequencia_total - primary_proof`
- tabela complementar com entrega parcial ao Verifier, usando 1% das janelas totais do pacote e minimo de 1 janela entregue
- repeticoes controladas por `proofIterations`

Os cenarios padrao usam credenciais com:

- 1 janela valida
- 10 janelas validas
- 100 janelas validas
- 365 janelas validas
- 1000 janelas validas
- 5000 janelas validas
- 10000 janelas validas
- 25000 janelas validas

### `bloom-throughput`

Mede operacoes sequenciais sem paralelismo:

- throughput de escrita usando `revokeIssuedCredentialFromWindow`
- throughput de escrita efetiva no Bloom em `ops/s`, calculado pelo total de chaves realmente inseridas
- throughput de leitura usando `verifyPresentationRevocationProofV2`
- amostras controladas por `throughput.sampleCredentialCount`

### `k-vector-ledger-write`

Mede o tempo gasto pelo emissor para publicar o vetor `K` no ledger via `ATTRIBs`:

- cria um DID de emissor temporario por execucao para que cada registro do `K` seja realmente novo no ledger
- mede separadamente o `setup` local de `revocationSetupCreateK` e a escrita no ledger de `revocationWriteKVectorOnLedger`
- coleta `chunk_count`, `chunk_size_bytes`, `total_bytes` e uma estimativa de quantos `ATTRIBs` foram escritos
- por padrao usa o chunk size do addon; se quiser comparar estrategias de fragmentacao, configure `kVectorLedger.chunkSizeBytesList` com valores como `[null, 2048, 1024]`
- as repeticoes sao controladas por `kVectorLedger.iterations`
- o tempo de registro do DID do emissor no ledger fica fora da janela medida, para o benchmark refletir apenas a publicacao do vetor `K`

### `issuer-revocation`

Mede o tempo gasto pelo emissor para revogar uma credencial em diferentes pontos da sua linha do tempo:

- tamanhos de credencial com `100`, `365`, `1000`, `5000` e `10000` janelas
- revogacao na janela inicial, na janela do meio e na ultima janela
- tempo total de `revokeIssuedCredentialFromWindow`
- quantidade de chaves de revogacao esperadas e efetivamente escritas
- repeticoes controladas por `issuerRevocationIterations`

### Controle de repeticoes

Os principais parametros para controlar a quantidade de execucoes sao:

- `issueIterations`: repeticoes por linha da Tabela 1
- `verifyIterations`: repeticoes medidas por linha da Tabela 2
- `verifyWarmups`: aquecimentos por linha da Tabela 2
- `falsePositive.trialCredentialCount`: testes por linha da Tabela 3
- `falsePositive.fillerCredentialCount`: fillers usados na Tabela 3
- `proofIterations`: repeticoes por linha das Tabelas 4, 4B e 7
- `throughput.sampleCredentialCount`: amostras da Tabela 5
- `issuerRevocationIterations`: repeticoes por linha da Tabela 6

## Resultados

Cada execucao cria uma pasta em `tests/results/<timestamp>/` com:

- `_run.json`
- `_summary.json`
- `_report.json`
- arquivos `.json` completos por benchmark
- arquivos `.csv` resumidos para tabelas e graficos
- `report/paper-summary.md`
- `report/table-1-issue.md`
- `report/table-2-verify.md`
- `report/table-3-false-positive.md`
- `report/table-4-proof-size.md`
- `report/table-5-throughput.md`
- `latest-run.json` na pasta pai de resultados, apontando para a ultima campanha executada

## Observacoes

- O script abre a wallet configurada e tenta criar os artefatos necessarios automaticamente.
- Se o ledger local nao estiver disponivel, a execucao vai falhar cedo no bootstrap.
- O benchmark de verificacao usa a mesma estrategia do front-end: busca binaria confirmada acima do limiar configurado e fallback para varredura completa quando necessario.
