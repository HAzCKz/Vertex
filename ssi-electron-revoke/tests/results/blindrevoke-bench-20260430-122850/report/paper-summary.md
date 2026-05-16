# BlindRevoke Experimental Summary

- Generated at: 2026-04-30T12:34:15.414Z
- Config: /home/yugi/programacao/ssi-electron-revoke/tests/blindrevoke.config.json
- Output: /home/yugi/programacao/ssi-electron-revoke/tests/results/blindrevoke-bench-20260430-122850
- Default filter profile: m16777216-cap345238
- Tempo total de processamento: 05:24.161

## Amostragem dos Experimentos

- Tabela 1: 3 emissão(ões) por configuração de janelas.
- Tabela 2: 10 verificação(ões) medidas por linha, com 1 aquecimento(s) não contabilizado(s).
- Tabela 3: 20 teste(s) em credenciais-alvo, com 8 filler(s) revogado(s).
- Tabelas 4, 4B e 7: 3 montagem(ens) por configuração de janelas.
- Tabela 5: 20 amostra(s) de credencial para escrita e 20 para leitura.
- Tabela 5B: 1 registro(s) do vetor K por configuração de chunk.
- Tabela 6: 3 revogação(ões) por linha.

## Tabela 1. Emissão da Credencial Revogável

| Janelas | Experimentos | Janelas válidas | Confirmação | Emissão (ms) | Envelope Holder (bytes) | Bundle (bytes) | Manifesto (bytes) | Chunks K |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 100 | 3 | 100 | 10 | 80.258 | 78815 | 33588 | 614 | 11 |
| 365 | 3 | 365 | 10 | 185.604 | 198707 | 111045 | 614 | 11 |
| 1000 | 3 | 1000 | 10 | 443.713 | 485951 | 296621 | 614 | 11 |
| 5000 | 3 | 5000 | 10 | 2007.743 | 2295742 | 1465950 | 614 | 11 |
| 10000 | 3 | 10000 | 10 | 3937.393 | 4558007 | 2927631 | 614 | 11 |


## Tabela 2. Latência de Verificação

| Janelas | Cenário | Experimentos | Warmups | Janela revogação | Mediana (ms) | P95 (ms) | Janelas consultadas | Modo dominante |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 100 | not_revoked | 10 | 1 | - | 102.029 | 106.289 | 18 | binary_window_search |
| 100 | revoked_early | 10 | 1 | 0 | 60.816 | 65.069 | 12 | binary_window_search |
| 100 | revoked_middle | 10 | 1 | 50 | 52.995 | 60.842 | 11 | binary_window_search |
| 100 | revoked_late | 10 | 1 | 99 | 19.263 | 28.705 | 8 | binary_window_search |
| 365 | not_revoked | 10 | 1 | - | 127.786 | 133.594 | 20 | binary_window_search |
| 365 | revoked_early | 10 | 1 | 0 | 97.975 | 102.302 | 16 | binary_window_search |
| 365 | revoked_middle | 10 | 1 | 182 | 30.39 | 37.964 | 10 | binary_window_search |
| 365 | revoked_late | 10 | 1 | 364 | 32.139 | 42.849 | 10 | binary_window_search |
| 1000 | not_revoked | 10 | 1 | - | 174.574 | 195.187 | 21 | binary_window_search |
| 1000 | revoked_early | 10 | 1 | 0 | 143.697 | 159.209 | 18 | binary_window_search |
| 1000 | revoked_middle | 10 | 1 | 500 | 136.206 | 152.269 | 17 | binary_window_search |
| 1000 | revoked_late | 10 | 1 | 999 | 58.27 | 63.453 | 11 | binary_window_search |
| 5000 | not_revoked | 10 | 1 | - | 443.667 | 469.5 | 24 | binary_window_search |
| 5000 | revoked_early | 10 | 1 | 0 | 448.851 | 466.897 | 24 | binary_window_search |
| 5000 | revoked_middle | 10 | 1 | 2500 | 432.583 | 453.546 | 23 | binary_window_search |
| 5000 | revoked_late | 10 | 1 | 4999 | 233.457 | 245.272 | 14 | binary_window_search |
| 10000 | not_revoked | 10 | 1 | - | 730.603 | 763.091 | 25 | binary_window_search |
| 10000 | revoked_early | 10 | 1 | 0 | 781.106 | 811.197 | 26 | binary_window_search |
| 10000 | revoked_middle | 10 | 1 | 5000 | 742.147 | 764.326 | 25 | binary_window_search |
| 10000 | revoked_late | 10 | 1 | 9999 | 429.347 | 456.131 | 15 | binary_window_search |


## Tabela 3. Falso Positivo

| Status | Manifesto | Motivo | Fillers | Testes | FP observados | Taxa FP | FP escaparam | Taxa escaparam | Latência mediana (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ok | http://127.0.0.1:8081/manifest | - | 8 | 20 | 0 | 0 | 0 | 0 | 169.318 |


## Tabela 4. Tamanho do Pacote Completo de Apresentação

| Janelas válidas | Experimentos | Janelas extras FP | Janelas totais no pacote | Total (ms) | Prova revogável (ms) | Serialização payload (ms) | Authcrypt envelope (ms) | Payload apresentação (bytes) | Envelope criptografado (bytes) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 | 10 | 11 | 14.944 | 13.812 | 0.144 | 0.748 | 25842 | 35576 |
| 10 | 3 | 10 | 20 | 18.901 | 17.463 | 0.148 | 0.865 | 40965 | 55741 |
| 100 | 3 | 10 | 110 | 23.503 | 19.875 | 0.768 | 2.177 | 197633 | 264630 |
| 365 | 3 | 10 | 375 | 29.622 | 19.724 | 2.549 | 5.106 | 688048 | 918516 |
| 1000 | 3 | 10 | 1010 | 53.481 | 27.502 | 5.921 | 16.186 | 1892439 | 2524375 |
| 5000 | 3 | 10 | 5010 | 231.589 | 94.484 | 43.455 | 70.359 | 10068909 | 13426335 |
| 10000 | 3 | 10 | 10010 | 499.463 | 206.792 | 81.166 | 155.549 | 20621274 | 27496156 |
| 25000 | 3 | 10 | 25010 | 1289.757 | 524.601 | 217.881 | 418.935 | 52726321 | 70302883 |


## Tabela 4B. Decomposição Diagnóstica da Prova Revogável

| Janelas válidas | Experimentos | Janelas totais no pacote | Apresentação anoncreds (ms) | Primary proof (ms) | Sequência revogável total (ms) | Confirmações estimadas (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 | 11 | 13.247 | 0.575 | 0.434 | 0 |
| 10 | 3 | 20 | 15.671 | 0.488 | 0.669 | 0.146 |
| 100 | 3 | 110 | 12.506 | 0.704 | 2.05 | 1.059 |
| 365 | 3 | 375 | 17.75 | 1.679 | 7.024 | 5.056 |
| 1000 | 3 | 1010 | 14.151 | 3.905 | 17.058 | 13.153 |
| 5000 | 3 | 5010 | 15.482 | 14.867 | 92.322 | 77.455 |
| 10000 | 3 | 10010 | 15.024 | 26.717 | 178.13 | 151.254 |
| 25000 | 3 | 25010 | 15.382 | 62.825 | 498.601 | 435.776 |


## Tabela 5. Throughput do Bloom

| Amostras | Janelas/credencial | Janela revogação | Escritas/credencial | Escrita (ops/s) | Leitura (ops/s) | Escrita mediana (ms/op) | Leitura mediana (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 20 | 100 | 0 | 110 | 1396.501793 | 444.983072 | 0.675 | 0.984 |


## Tabela 5B. Tempo de Registro do Vetor K no Ledger

| Chunk solicitado | Experimentos | Registro K (ms) | Setup K (ms) | ATTRIBs estimados | Chunks K | Chunk efetivo (bytes) | Total K (bytes) | Valores K |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| default | 1 | 39136.026 | 1.717 | 13 | 11 | 3045 | 32768 | 1024 |


## Tabela 6. Tempo de Revogação da Credencial pelo Issuer

| Janelas | Cenário | Experimentos | Janela revogação | Revogação (ms) | Chaves esperadas | Chaves escritas |
| --- | --- | --- | --- | --- | --- | --- |
| 100 | revoked_early | 3 | 0 | 79.225 | 110 | 110 |
| 100 | revoked_middle | 3 | 50 | 71.502 | 60 | 60 |
| 100 | revoked_late | 3 | 99 | 66.63 | 11 | 11 |
| 365 | revoked_early | 3 | 0 | 93.076 | 375 | 375 |
| 365 | revoked_middle | 3 | 182 | 81.028 | 193 | 193 |
| 365 | revoked_late | 3 | 364 | 67.987 | 11 | 11 |
| 1000 | revoked_early | 3 | 0 | 147.649 | 1010 | 1010 |
| 1000 | revoked_middle | 3 | 500 | 109.849 | 510 | 510 |
| 1000 | revoked_late | 3 | 999 | 69.846 | 11 | 11 |
| 5000 | revoked_early | 3 | 0 | 431.664 | 5010 | 5010 |
| 5000 | revoked_middle | 3 | 2500 | 260.586 | 2510 | 2510 |
| 5000 | revoked_late | 3 | 4999 | 74.529 | 11 | 11 |
| 10000 | revoked_early | 3 | 0 | 785.984 | 10010 | 10010 |
| 10000 | revoked_middle | 3 | 5000 | 423.801 | 5010 | 5010 |
| 10000 | revoked_late | 3 | 9999 | 80.99 | 11 | 11 |


## Tabela 7. Tamanho do Pacote de Apresentação com Entrega Parcial de Janelas

| Janelas válidas | Experimentos | Janelas extras FP | Janelas entregues ao Verificador | Total (ms) | Prova revogável (ms) | Serialização payload (ms) | Authcrypt envelope (ms) | Payload apresentação (bytes) | Envelope criptografado (bytes) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 | 10 | 1 | 18.508 | 17.546 | 0.063 | 0.774 | 10140 | 14640 |
| 10 | 3 | 10 | 1 | 14.918 | 14.049 | 0.062 | 0.714 | 10215 | 14741 |
| 100 | 3 | 10 | 1 | 15.327 | 14.456 | 0.047 | 0.491 | 10340 | 14906 |
| 365 | 3 | 10 | 3 | 16.688 | 15.79 | 0.081 | 0.627 | 14013 | 19803 |
| 1000 | 3 | 10 | 10 | 17.914 | 16.8 | 0.088 | 0.858 | 27265 | 37475 |
| 5000 | 3 | 10 | 50 | 34.81 | 32.472 | 0.43 | 1.742 | 108920 | 146347 |
| 10000 | 3 | 10 | 100 | 47.39 | 40.768 | 0.578 | 2.651 | 214401 | 286992 |
| 25000 | 3 | 10 | 250 | 91.966 | 83.995 | 1.897 | 5.186 | 535157 | 714664 |


