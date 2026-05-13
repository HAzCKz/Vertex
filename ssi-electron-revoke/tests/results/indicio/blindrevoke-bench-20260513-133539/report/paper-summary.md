# BlindRevoke Experimental Summary

- Generated at: 2026-05-13T13:44:03.078Z
- Config: /home/yugi/programacao/ssi-electron-revoke/tests/blindrevoke-indicio.config.json
- Output: /home/yugi/programacao/ssi-electron-revoke/tests/results/indicio/blindrevoke-bench-20260513-133539
- Default filter profile: m16777216-cap345238
- Tempo total de processamento: 08:23.412

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
| 100 | 3 | 100 | 10 | 69.119 | 78935 | 33634 | 614 | 11 |
| 365 | 3 | 365 | 10 | 156.984 | 198789 | 111077 | 614 | 11 |
| 1000 | 3 | 1000 | 10 | 369.96 | 486051 | 296647 | 614 | 11 |
| 5000 | 3 | 5000 | 10 | 1714.764 | 2295811 | 1465972 | 614 | 11 |
| 10000 | 3 | 10000 | 10 | 3406.087 | 4557811 | 2927430 | 614 | 11 |


## Tabela 2. Latência de Verificação

| Janelas | Cenário | Experimentos | Warmups | Janela revogação | Mediana (ms) | P95 (ms) | Janelas consultadas | Modo dominante |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 100 | not_revoked | 10 | 1 | - | 134.775 | 170.602 | 18 | binary_window_search |
| 100 | revoked_early | 10 | 1 | 0 | 67.777 | 85.409 | 12 | binary_window_search |
| 100 | revoked_middle | 10 | 1 | 50 | 55.784 | 71.106 | 11 | binary_window_search |
| 100 | revoked_late | 10 | 1 | 99 | 18.46 | 28.119 | 8 | binary_window_search |
| 365 | not_revoked | 10 | 1 | - | 147.778 | 205.035 | 20 | binary_window_search |
| 365 | revoked_early | 10 | 1 | 0 | 106.632 | 138.896 | 16 | binary_window_search |
| 365 | revoked_middle | 10 | 1 | 182 | 32.474 | 58.96 | 10 | binary_window_search |
| 365 | revoked_late | 10 | 1 | 364 | 47.153 | 59.488 | 10 | binary_window_search |
| 1000 | not_revoked | 10 | 1 | - | 191.012 | 243.588 | 21 | binary_window_search |
| 1000 | revoked_early | 10 | 1 | 0 | 170.122 | 232.158 | 18 | binary_window_search |
| 1000 | revoked_middle | 10 | 1 | 500 | 150.863 | 189.689 | 17 | binary_window_search |
| 1000 | revoked_late | 10 | 1 | 999 | 69.63 | 87.907 | 11 | binary_window_search |
| 5000 | not_revoked | 10 | 1 | - | 409.562 | 420.474 | 24 | binary_window_search |
| 5000 | revoked_early | 10 | 1 | 0 | 406.783 | 425.754 | 24 | binary_window_search |
| 5000 | revoked_middle | 10 | 1 | 2500 | 385.181 | 397.502 | 23 | binary_window_search |
| 5000 | revoked_late | 10 | 1 | 4999 | 187.343 | 204.483 | 14 | binary_window_search |
| 10000 | not_revoked | 10 | 1 | - | 670.809 | 688.994 | 25 | binary_window_search |
| 10000 | revoked_early | 10 | 1 | 0 | 708.066 | 721.897 | 26 | binary_window_search |
| 10000 | revoked_middle | 10 | 1 | 5000 | 685.44 | 704.427 | 25 | binary_window_search |
| 10000 | revoked_late | 10 | 1 | 9999 | 357.985 | 368.226 | 15 | binary_window_search |


## Tabela 3. Falso Positivo

| Status | Manifesto | Motivo | Fillers | Testes | FP observados | Taxa FP | FP escaparam | Taxa escaparam | Latência mediana (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ok | http://127.0.0.1:8081/manifest | - | 8 | 20 | 0 | 0 | 0 | 0 | 202.114 |


## Tabela 4. Tamanho do Pacote Completo de Apresentação

| Janelas válidas | Experimentos | Janelas extras FP | Janelas totais no pacote | Total (ms) | Prova revogável (ms) | Serialização payload (ms) | Authcrypt envelope (ms) | Payload apresentação (bytes) | Envelope criptografado (bytes) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 | 10 | 11 | 14.602 | 13.091 | 0.098 | 1.269 | 25909 | 35664 |
| 10 | 3 | 10 | 20 | 15.603 | 13.656 | 0.337 | 1.429 | 40990 | 55771 |
| 100 | 3 | 10 | 110 | 20.92 | 16.212 | 0.965 | 2.533 | 197563 | 264537 |
| 365 | 3 | 10 | 375 | 34.769 | 18.879 | 4.51 | 8.974 | 688544 | 919177 |
| 1000 | 3 | 10 | 1010 | 51.093 | 25.516 | 5.034 | 11.249 | 1892527 | 2524490 |
| 5000 | 3 | 10 | 5010 | 212.097 | 84.941 | 38.638 | 64.814 | 10069452 | 13427059 |
| 10000 | 3 | 10 | 10010 | 430.845 | 167.763 | 71.02 | 141.594 | 20621154 | 27495996 |
| 25000 | 3 | 10 | 25010 | 1100.588 | 444.947 | 177.188 | 382.668 | 52727082 | 70303900 |


## Tabela 4B. Decomposição Diagnóstica da Prova Revogável

| Janelas válidas | Experimentos | Janelas totais no pacote | Apresentação anoncreds (ms) | Primary proof (ms) | Sequência revogável total (ms) | Confirmações estimadas (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 | 11 | 20.083 | 1.033 | 0.854 | 0 |
| 10 | 3 | 20 | 18.897 | 1.004 | 0.814 | 0 |
| 100 | 3 | 110 | 18.327 | 1.091 | 2.226 | 0.84 |
| 365 | 3 | 375 | 18.642 | 1.899 | 5.357 | 3.365 |
| 1000 | 3 | 1010 | 17.965 | 3.621 | 13.51 | 10.207 |
| 5000 | 3 | 5010 | 17.055 | 12.06 | 73.087 | 60.287 |
| 10000 | 3 | 10010 | 18.791 | 21.996 | 161.747 | 140.94 |
| 25000 | 3 | 25010 | 17.32 | 52.129 | 430.704 | 375.463 |


## Tabela 5. Throughput do Bloom

| Amostras | Janelas/credencial | Janela revogação | Escritas/credencial | Escrita (ops/s) | Leitura (ops/s) | Escrita mediana (ms/op) | Leitura mediana (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 20 | 100 | 0 | 110 | 1444.001362 | 381.831575 | 0.631 | 1.098 |


## Tabela 5B. Tempo de Registro do Vetor K no Ledger

| Chunk solicitado | Experimentos | Escritas K | K reutilizados | Status | Registro K (ms) | Setup K (ms) | ATTRIBs estimados | Chunks K | Chunk efetivo (bytes) | Total K (bytes) | Valores K |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| default | 1 | 0 | 1 | reused_existing | 0 | 0 | 13 | 11 | 3045 | 32768 | 1024 |


## Tabela 6. Tempo de Revogação da Credencial pelo Issuer

| Janelas | Cenário | Experimentos | Janela revogação | Revogação (ms) | Chaves esperadas | Chaves escritas |
| --- | --- | --- | --- | --- | --- | --- |
| 100 | revoked_early | 3 | 0 | 67.379 | 110 | 110 |
| 100 | revoked_middle | 3 | 50 | 68.401 | 60 | 60 |
| 100 | revoked_late | 3 | 99 | 62.24 | 11 | 11 |
| 365 | revoked_early | 3 | 0 | 87.879 | 375 | 375 |
| 365 | revoked_middle | 3 | 182 | 72.837 | 193 | 193 |
| 365 | revoked_late | 3 | 364 | 62.919 | 11 | 11 |
| 1000 | revoked_early | 3 | 0 | 123.262 | 1010 | 1010 |
| 1000 | revoked_middle | 3 | 500 | 91.578 | 510 | 510 |
| 1000 | revoked_late | 3 | 999 | 62.423 | 11 | 11 |
| 5000 | revoked_early | 3 | 0 | 380.373 | 5010 | 5010 |
| 5000 | revoked_middle | 3 | 2500 | 215.61 | 2510 | 2510 |
| 5000 | revoked_late | 3 | 4999 | 68.804 | 11 | 11 |
| 10000 | revoked_early | 3 | 0 | 670.008 | 10010 | 10010 |
| 10000 | revoked_middle | 3 | 5000 | 367.973 | 5010 | 5010 |
| 10000 | revoked_late | 3 | 9999 | 70.99 | 11 | 11 |


## Tabela 7. Tamanho do Pacote de Apresentação com Entrega Parcial de Janelas

| Janelas válidas | Experimentos | Janelas extras FP | Janelas entregues ao Verificador | Total (ms) | Prova revogável (ms) | Serialização payload (ms) | Authcrypt envelope (ms) | Payload apresentação (bytes) | Envelope criptografado (bytes) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 | 10 | 1 | 15.014 | 13.633 | 0.055 | 1.226 | 10192 | 14706 |
| 10 | 3 | 10 | 1 | 16.07 | 14.439 | 0.05 | 1.477 | 10250 | 14784 |
| 100 | 3 | 10 | 1 | 14.451 | 12.855 | 0.053 | 0.96 | 10372 | 14949 |
| 365 | 3 | 10 | 3 | 15.63 | 13.966 | 0.067 | 1.311 | 14074 | 19884 |
| 1000 | 3 | 10 | 10 | 16.187 | 15.163 | 0.086 | 0.994 | 27310 | 37535 |
| 5000 | 3 | 10 | 50 | 28.061 | 25.228 | 0.262 | 1.855 | 108993 | 146445 |
| 10000 | 3 | 10 | 100 | 45.602 | 41.716 | 0.593 | 2.839 | 214404 | 286996 |
| 25000 | 3 | 10 | 250 | 72.638 | 66.602 | 1.201 | 3.946 | 535240 | 714776 |


