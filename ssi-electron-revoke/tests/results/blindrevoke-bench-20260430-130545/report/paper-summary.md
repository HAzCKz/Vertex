# BlindRevoke Experimental Summary

- Generated at: 2026-04-30T13:10:42.712Z
- Config: /home/yugi/programacao/ssi-electron-revoke/tests/blindrevoke.config.json
- Output: /home/yugi/programacao/ssi-electron-revoke/tests/results/blindrevoke-bench-20260430-130545
- Default filter profile: m16777216-cap345238
- Tempo total de processamento: 04:56.390

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
| 100 | 3 | 100 | 10 | 65.291 | 78827 | 33600 | 614 | 11 |
| 365 | 3 | 365 | 10 | 157.51 | 198763 | 111109 | 614 | 11 |
| 1000 | 3 | 1000 | 10 | 379.426 | 486003 | 296660 | 614 | 11 |
| 5000 | 3 | 5000 | 10 | 1728.239 | 2295721 | 1465936 | 614 | 11 |
| 10000 | 3 | 10000 | 10 | 3407.178 | 4557647 | 2927371 | 614 | 11 |


## Tabela 2. Latência de Verificação

| Janelas | Cenário | Experimentos | Warmups | Janela revogação | Mediana (ms) | P95 (ms) | Janelas consultadas | Modo dominante |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 100 | not_revoked | 10 | 1 | - | 88.425 | 107.938 | 18 | binary_window_search |
| 100 | revoked_early | 10 | 1 | 0 | 57.79 | 70.013 | 12 | binary_window_search |
| 100 | revoked_middle | 10 | 1 | 50 | 47.627 | 59.632 | 11 | binary_window_search |
| 100 | revoked_late | 10 | 1 | 99 | 23.245 | 28.816 | 8 | binary_window_search |
| 365 | not_revoked | 10 | 1 | - | 104.336 | 133.238 | 20 | binary_window_search |
| 365 | revoked_early | 10 | 1 | 0 | 79.891 | 118.641 | 16 | binary_window_search |
| 365 | revoked_middle | 10 | 1 | 182 | 25.088 | 47.371 | 10 | binary_window_search |
| 365 | revoked_late | 10 | 1 | 364 | 35.206 | 41.762 | 10 | binary_window_search |
| 1000 | not_revoked | 10 | 1 | - | 172.313 | 242.72 | 21 | binary_window_search |
| 1000 | revoked_early | 10 | 1 | 0 | 135.486 | 147.561 | 18 | binary_window_search |
| 1000 | revoked_middle | 10 | 1 | 500 | 136.406 | 191.953 | 17 | binary_window_search |
| 1000 | revoked_late | 10 | 1 | 999 | 68.97 | 77.176 | 11 | binary_window_search |
| 5000 | not_revoked | 10 | 1 | - | 391.244 | 420.325 | 24 | binary_window_search |
| 5000 | revoked_early | 10 | 1 | 0 | 396.256 | 407.692 | 24 | binary_window_search |
| 5000 | revoked_middle | 10 | 1 | 2500 | 382.327 | 399.46 | 23 | binary_window_search |
| 5000 | revoked_late | 10 | 1 | 4999 | 192.536 | 200.105 | 14 | binary_window_search |
| 10000 | not_revoked | 10 | 1 | - | 660.696 | 674.368 | 25 | binary_window_search |
| 10000 | revoked_early | 10 | 1 | 0 | 689.916 | 717.889 | 26 | binary_window_search |
| 10000 | revoked_middle | 10 | 1 | 5000 | 672.876 | 683.467 | 25 | binary_window_search |
| 10000 | revoked_late | 10 | 1 | 9999 | 360.689 | 377.601 | 15 | binary_window_search |


## Tabela 3. Falso Positivo

| Status | Manifesto | Motivo | Fillers | Testes | FP observados | Taxa FP | FP escaparam | Taxa escaparam | Latência mediana (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ok | http://127.0.0.1:8081/manifest | - | 8 | 20 | 0 | 0 | 0 | 0 | 218.714 |


## Tabela 4. Tamanho do Pacote Completo de Apresentação

| Janelas válidas | Experimentos | Janelas extras FP | Janelas totais no pacote | Total (ms) | Prova revogável (ms) | Serialização payload (ms) | Authcrypt envelope (ms) | Payload apresentação (bytes) | Envelope criptografado (bytes) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 | 10 | 11 | 14.726 | 13.119 | 0.108 | 1.459 | 25831 | 35559 |
| 10 | 3 | 10 | 20 | 15.493 | 13.517 | 0.121 | 1.647 | 40960 | 55733 |
| 100 | 3 | 10 | 110 | 17.714 | 14.159 | 0.463 | 2.544 | 197634 | 264634 |
| 365 | 3 | 10 | 375 | 25.405 | 17.858 | 1.559 | 4.849 | 688897 | 919650 |
| 1000 | 3 | 10 | 1010 | 48.697 | 26.423 | 4.637 | 12.534 | 1892536 | 2524503 |
| 5000 | 3 | 10 | 5010 | 204.922 | 86.079 | 35.057 | 65.761 | 10069247 | 13426783 |
| 10000 | 3 | 10 | 10010 | 400.636 | 172.202 | 60.785 | 123.798 | 20621218 | 27496080 |
| 25000 | 3 | 10 | 25010 | 1102.276 | 461.161 | 174.545 | 368.301 | 52725673 | 70302020 |


## Tabela 4B. Decomposição Diagnóstica da Prova Revogável

| Janelas válidas | Experimentos | Janelas totais no pacote | Apresentação anoncreds (ms) | Primary proof (ms) | Sequência revogável total (ms) | Confirmações estimadas (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 | 11 | 15.948 | 0.814 | 0.82 | 0 |
| 10 | 3 | 20 | 13.486 | 0.836 | 0.89 | 0.163 |
| 100 | 3 | 110 | 12.3 | 0.973 | 1.806 | 0.874 |
| 365 | 3 | 375 | 13.878 | 1.692 | 5.108 | 3.434 |
| 1000 | 3 | 1010 | 12.69 | 3.89 | 14.275 | 11.561 |
| 5000 | 3 | 5010 | 12.803 | 11.535 | 73.692 | 62.339 |
| 10000 | 3 | 10010 | 13.458 | 21.738 | 161.22 | 140.296 |
| 25000 | 3 | 25010 | 12.365 | 54.306 | 411.422 | 354.507 |


## Tabela 5. Throughput do Bloom

| Amostras | Janelas/credencial | Janela revogação | Escritas/credencial | Escrita (ops/s) | Leitura (ops/s) | Escrita mediana (ms/op) | Leitura mediana (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 20 | 100 | 0 | 110 | 1504.668176 | 634.587789 | 0.64 | 0.831 |


## Tabela 5B. Tempo de Registro do Vetor K no Ledger

| Chunk solicitado | Experimentos | Registro K (ms) | Setup K (ms) | ATTRIBs estimados | Chunks K | Chunk efetivo (bytes) | Total K (bytes) | Valores K |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| default | 1 | 39126.128 | 1.07 | 13 | 11 | 3045 | 32768 | 1024 |


## Tabela 6. Tempo de Revogação da Credencial pelo Issuer

| Janelas | Cenário | Experimentos | Janela revogação | Revogação (ms) | Chaves esperadas | Chaves escritas |
| --- | --- | --- | --- | --- | --- | --- |
| 100 | revoked_early | 3 | 0 | 67.579 | 110 | 110 |
| 100 | revoked_middle | 3 | 50 | 66.48 | 60 | 60 |
| 100 | revoked_late | 3 | 99 | 63.433 | 11 | 11 |
| 365 | revoked_early | 3 | 0 | 84.993 | 375 | 375 |
| 365 | revoked_middle | 3 | 182 | 72.683 | 193 | 193 |
| 365 | revoked_late | 3 | 364 | 61.863 | 11 | 11 |
| 1000 | revoked_early | 3 | 0 | 121.917 | 1010 | 1010 |
| 1000 | revoked_middle | 3 | 500 | 96.444 | 510 | 510 |
| 1000 | revoked_late | 3 | 999 | 64.144 | 11 | 11 |
| 5000 | revoked_early | 3 | 0 | 380.1 | 5010 | 5010 |
| 5000 | revoked_middle | 3 | 2500 | 213.762 | 2510 | 2510 |
| 5000 | revoked_late | 3 | 4999 | 78.808 | 11 | 11 |
| 10000 | revoked_early | 3 | 0 | 670.915 | 10010 | 10010 |
| 10000 | revoked_middle | 3 | 5000 | 369.067 | 5010 | 5010 |
| 10000 | revoked_late | 3 | 9999 | 71.67 | 11 | 11 |


## Tabela 7. Tamanho do Pacote de Apresentação com Entrega Parcial de Janelas

| Janelas válidas | Experimentos | Janelas extras FP | Janelas entregues ao Verificador | Total (ms) | Prova revogável (ms) | Serialização payload (ms) | Authcrypt envelope (ms) | Payload apresentação (bytes) | Envelope criptografado (bytes) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 | 10 | 1 | 14.754 | 13.14 | 0.045 | 1.059 | 10157 | 14660 |
| 10 | 3 | 10 | 1 | 14.728 | 13.194 | 0.047 | 1.093 | 10208 | 14728 |
| 100 | 3 | 10 | 1 | 14.918 | 13.524 | 0.046 | 0.959 | 10328 | 14890 |
| 365 | 3 | 10 | 3 | 14.964 | 13.637 | 0.059 | 1.137 | 14051 | 19854 |
| 1000 | 3 | 10 | 10 | 16.236 | 15.081 | 0.082 | 1.046 | 27264 | 37475 |
| 5000 | 3 | 10 | 50 | 27.99 | 25.71 | 0.266 | 1.745 | 108935 | 146367 |
| 10000 | 3 | 10 | 100 | 39.714 | 34.552 | 0.483 | 3.051 | 214373 | 286952 |
| 25000 | 3 | 10 | 250 | 75.349 | 69.147 | 1.217 | 3.854 | 535100 | 714587 |


