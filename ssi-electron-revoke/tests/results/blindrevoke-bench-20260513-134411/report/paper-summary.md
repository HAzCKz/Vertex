# BlindRevoke Experimental Summary

- Generated at: 2026-05-13T13:49:11.575Z
- Config: /home/yugi/programacao/ssi-electron-revoke/tests/blindrevoke.config.json
- Output: /home/yugi/programacao/ssi-electron-revoke/tests/results/blindrevoke-bench-20260513-134411
- Default filter profile: m16777216-cap345238
- Tempo total de processamento: 04:59.298

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
| 100 | 3 | 100 | 10 | 66.097 | 78847 | 33607 | 614 | 11 |
| 365 | 3 | 365 | 10 | 155.005 | 198727 | 111054 | 614 | 11 |
| 1000 | 3 | 1000 | 10 | 370.095 | 486023 | 296666 | 614 | 11 |
| 5000 | 3 | 5000 | 10 | 1709.387 | 2295682 | 1465911 | 614 | 11 |
| 10000 | 3 | 10000 | 10 | 3395.347 | 4557919 | 2927572 | 614 | 11 |


## Tabela 2. Latência de Verificação

| Janelas | Cenário | Experimentos | Warmups | Janela revogação | Mediana (ms) | P95 (ms) | Janelas consultadas | Modo dominante |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 100 | not_revoked | 10 | 1 | - | 96.173 | 141.121 | 18 | binary_window_search |
| 100 | revoked_early | 10 | 1 | 0 | 63.137 | 69.939 | 12 | binary_window_search |
| 100 | revoked_middle | 10 | 1 | 50 | 61.978 | 70.701 | 11 | binary_window_search |
| 100 | revoked_late | 10 | 1 | 99 | 19.46 | 27.324 | 8 | binary_window_search |
| 365 | not_revoked | 10 | 1 | - | 152.513 | 184.333 | 20 | binary_window_search |
| 365 | revoked_early | 10 | 1 | 0 | 106.004 | 154.43 | 16 | binary_window_search |
| 365 | revoked_middle | 10 | 1 | 182 | 40.451 | 45.013 | 10 | binary_window_search |
| 365 | revoked_late | 10 | 1 | 364 | 32.467 | 51.954 | 10 | binary_window_search |
| 1000 | not_revoked | 10 | 1 | - | 190.97 | 223.482 | 21 | binary_window_search |
| 1000 | revoked_early | 10 | 1 | 0 | 189.344 | 207.512 | 18 | binary_window_search |
| 1000 | revoked_middle | 10 | 1 | 500 | 144.606 | 192.319 | 17 | binary_window_search |
| 1000 | revoked_late | 10 | 1 | 999 | 70.695 | 84.34 | 11 | binary_window_search |
| 5000 | not_revoked | 10 | 1 | - | 397.075 | 444.542 | 24 | binary_window_search |
| 5000 | revoked_early | 10 | 1 | 0 | 399.546 | 410.246 | 24 | binary_window_search |
| 5000 | revoked_middle | 10 | 1 | 2500 | 386.983 | 396.733 | 23 | binary_window_search |
| 5000 | revoked_late | 10 | 1 | 4999 | 193.826 | 206.421 | 14 | binary_window_search |
| 10000 | not_revoked | 10 | 1 | - | 668.028 | 682.188 | 25 | binary_window_search |
| 10000 | revoked_early | 10 | 1 | 0 | 707.884 | 728.296 | 26 | binary_window_search |
| 10000 | revoked_middle | 10 | 1 | 5000 | 680.018 | 693.583 | 25 | binary_window_search |
| 10000 | revoked_late | 10 | 1 | 9999 | 355.207 | 360.195 | 15 | binary_window_search |


## Tabela 3. Falso Positivo

| Status | Manifesto | Motivo | Fillers | Testes | FP observados | Taxa FP | FP escaparam | Taxa escaparam | Latência mediana (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ok | http://127.0.0.1:8081/manifest | - | 8 | 20 | 0 | 0 | 0 | 0 | 183.953 |


## Tabela 4. Tamanho do Pacote Completo de Apresentação

| Janelas válidas | Experimentos | Janelas extras FP | Janelas totais no pacote | Total (ms) | Prova revogável (ms) | Serialização payload (ms) | Authcrypt envelope (ms) | Payload apresentação (bytes) | Envelope criptografado (bytes) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 | 10 | 11 | 14.398 | 12.994 | 0.087 | 1.211 | 25873 | 35614 |
| 10 | 3 | 10 | 20 | 14.733 | 13.042 | 0.131 | 1.28 | 40989 | 55771 |
| 100 | 3 | 10 | 110 | 17.266 | 14.14 | 0.484 | 2.302 | 197630 | 264625 |
| 365 | 3 | 10 | 375 | 25.797 | 16.968 | 1.537 | 4.813 | 688923 | 919686 |
| 1000 | 3 | 10 | 1010 | 48.83 | 24.871 | 6.191 | 12.185 | 1892489 | 2524439 |
| 5000 | 3 | 10 | 5010 | 211.882 | 90.38 | 35 | 69.164 | 10069201 | 13426723 |
| 10000 | 3 | 10 | 10010 | 431.601 | 167.947 | 65.54 | 138.235 | 20621118 | 27495948 |
| 25000 | 3 | 10 | 25010 | 1065.742 | 402.782 | 174.707 | 375.028 | 52726248 | 70302787 |


## Tabela 4B. Decomposição Diagnóstica da Prova Revogável

| Janelas válidas | Experimentos | Janelas totais no pacote | Apresentação anoncreds (ms) | Primary proof (ms) | Sequência revogável total (ms) | Confirmações estimadas (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 | 11 | 12.577 | 0.92 | 0.727 | 0 |
| 10 | 3 | 20 | 13.883 | 0.858 | 0.672 | 0 |
| 100 | 3 | 110 | 14.483 | 1.074 | 1.745 | 0.568 |
| 365 | 3 | 375 | 12.668 | 1.479 | 4.853 | 3.44 |
| 1000 | 3 | 1010 | 12.306 | 3.184 | 12.373 | 9.222 |
| 5000 | 3 | 5010 | 12.148 | 12.108 | 78.843 | 66.735 |
| 10000 | 3 | 10010 | 12.401 | 21.207 | 159.635 | 138.428 |
| 25000 | 3 | 25010 | 12.457 | 51.414 | 431.676 | 379.996 |


## Tabela 5. Throughput do Bloom

| Amostras | Janelas/credencial | Janela revogação | Escritas/credencial | Escrita (ops/s) | Leitura (ops/s) | Escrita mediana (ms/op) | Leitura mediana (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 20 | 100 | 0 | 110 | 1519.58025 | 517.483959 | 0.613 | 0.925 |


## Tabela 5B. Tempo de Registro do Vetor K no Ledger

| Chunk solicitado | Experimentos | Escritas K | K reutilizados | Status | Registro K (ms) | Setup K (ms) | ATTRIBs estimados | Chunks K | Chunk efetivo (bytes) | Total K (bytes) | Valores K |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| default | 1 | 1 | 0 | written | 39120.707 | 0.984 | 13 | 11 | 3045 | 32768 | 1024 |


## Tabela 6. Tempo de Revogação da Credencial pelo Issuer

| Janelas | Cenário | Experimentos | Janela revogação | Revogação (ms) | Chaves esperadas | Chaves escritas |
| --- | --- | --- | --- | --- | --- | --- |
| 100 | revoked_early | 3 | 0 | 67.698 | 110 | 110 |
| 100 | revoked_middle | 3 | 50 | 65.018 | 60 | 60 |
| 100 | revoked_late | 3 | 99 | 63.067 | 11 | 11 |
| 365 | revoked_early | 3 | 0 | 85.203 | 375 | 375 |
| 365 | revoked_middle | 3 | 182 | 73.709 | 193 | 193 |
| 365 | revoked_late | 3 | 364 | 61.437 | 11 | 11 |
| 1000 | revoked_early | 3 | 0 | 123.265 | 1010 | 1010 |
| 1000 | revoked_middle | 3 | 500 | 92.722 | 510 | 510 |
| 1000 | revoked_late | 3 | 999 | 66.129 | 11 | 11 |
| 5000 | revoked_early | 3 | 0 | 364.395 | 5010 | 5010 |
| 5000 | revoked_middle | 3 | 2500 | 216.905 | 2510 | 2510 |
| 5000 | revoked_late | 3 | 4999 | 81.745 | 11 | 11 |
| 10000 | revoked_early | 3 | 0 | 680.629 | 10010 | 10010 |
| 10000 | revoked_middle | 3 | 5000 | 369.34 | 5010 | 5010 |
| 10000 | revoked_late | 3 | 9999 | 73.676 | 11 | 11 |


## Tabela 7. Tamanho do Pacote de Apresentação com Entrega Parcial de Janelas

| Janelas válidas | Experimentos | Janelas extras FP | Janelas entregues ao Verificador | Total (ms) | Prova revogável (ms) | Serialização payload (ms) | Authcrypt envelope (ms) | Payload apresentação (bytes) | Envelope criptografado (bytes) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 | 10 | 1 | 13.644 | 12.504 | 0.047 | 0.925 | 10169 | 14676 |
| 10 | 3 | 10 | 1 | 14.171 | 12.811 | 0.047 | 1.148 | 10236 | 14768 |
| 100 | 3 | 10 | 1 | 14.168 | 13.128 | 0.042 | 0.932 | 10336 | 14902 |
| 365 | 3 | 10 | 3 | 14.671 | 13.601 | 0.052 | 0.878 | 14075 | 19886 |
| 1000 | 3 | 10 | 10 | 16.723 | 15.086 | 0.103 | 1.4 | 27272 | 37483 |
| 5000 | 3 | 10 | 50 | 26.707 | 24.018 | 0.259 | 2.16 | 108953 | 146391 |
| 10000 | 3 | 10 | 100 | 38.947 | 35.589 | 0.48 | 2.458 | 214357 | 286932 |
| 25000 | 3 | 10 | 250 | 72.984 | 66.253 | 1.164 | 4.158 | 535082 | 714562 |


