# BlindRevoke Experimental Summary

- Generated at: 2026-05-13T13:20:34.465Z
- Config: /home/yugi/programacao/ssi-electron-revoke/tests/blindrevoke.config.json
- Output: /home/yugi/programacao/ssi-electron-revoke/tests/results/blindrevoke-bench-20260513-131532
- Default filter profile: m16777216-cap345238
- Tempo total de processamento: 05:01.362

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
| 100 | 3 | 100 | 10 | 70.622 | 78800 | 33574 | 614 | 11 |
| 365 | 3 | 365 | 10 | 159.357 | 198676 | 111034 | 614 | 11 |
| 1000 | 3 | 1000 | 10 | 371.306 | 486039 | 296679 | 614 | 11 |
| 5000 | 3 | 5000 | 10 | 1714.427 | 2295540 | 1465802 | 614 | 11 |
| 10000 | 3 | 10000 | 10 | 3388.213 | 4557846 | 2927517 | 614 | 11 |


## Tabela 2. Latência de Verificação

| Janelas | Cenário | Experimentos | Warmups | Janela revogação | Mediana (ms) | P95 (ms) | Janelas consultadas | Modo dominante |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 100 | not_revoked | 10 | 1 | - | 115.616 | 127.691 | 18 | binary_window_search |
| 100 | revoked_early | 10 | 1 | 0 | 69.901 | 91.223 | 12 | binary_window_search |
| 100 | revoked_middle | 10 | 1 | 50 | 47.393 | 65.791 | 11 | binary_window_search |
| 100 | revoked_late | 10 | 1 | 99 | 26.775 | 31.799 | 8 | binary_window_search |
| 365 | not_revoked | 10 | 1 | - | 161.292 | 193.044 | 20 | binary_window_search |
| 365 | revoked_early | 10 | 1 | 0 | 125.432 | 139.824 | 16 | binary_window_search |
| 365 | revoked_middle | 10 | 1 | 182 | 39.238 | 52.197 | 10 | binary_window_search |
| 365 | revoked_late | 10 | 1 | 364 | 35.295 | 52.108 | 10 | binary_window_search |
| 1000 | not_revoked | 10 | 1 | - | 194.683 | 233.242 | 21 | binary_window_search |
| 1000 | revoked_early | 10 | 1 | 0 | 170.519 | 211.675 | 18 | binary_window_search |
| 1000 | revoked_middle | 10 | 1 | 500 | 150.971 | 196.011 | 17 | binary_window_search |
| 1000 | revoked_late | 10 | 1 | 999 | 70.469 | 87.821 | 11 | binary_window_search |
| 5000 | not_revoked | 10 | 1 | - | 397.687 | 413.288 | 24 | binary_window_search |
| 5000 | revoked_early | 10 | 1 | 0 | 405.71 | 434.292 | 24 | binary_window_search |
| 5000 | revoked_middle | 10 | 1 | 2500 | 381.468 | 397.631 | 23 | binary_window_search |
| 5000 | revoked_late | 10 | 1 | 4999 | 191.491 | 196.39 | 14 | binary_window_search |
| 10000 | not_revoked | 10 | 1 | - | 662.244 | 680.459 | 25 | binary_window_search |
| 10000 | revoked_early | 10 | 1 | 0 | 711.895 | 724.101 | 26 | binary_window_search |
| 10000 | revoked_middle | 10 | 1 | 5000 | 678.597 | 696.408 | 25 | binary_window_search |
| 10000 | revoked_late | 10 | 1 | 9999 | 357.082 | 370.417 | 15 | binary_window_search |


## Tabela 3. Falso Positivo

| Status | Manifesto | Motivo | Fillers | Testes | FP observados | Taxa FP | FP escaparam | Taxa escaparam | Latência mediana (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ok | http://127.0.0.1:8081/manifest | - | 8 | 20 | 0 | 0 | 0 | 0 | 200.884 |


## Tabela 4. Tamanho do Pacote Completo de Apresentação

| Janelas válidas | Experimentos | Janelas extras FP | Janelas totais no pacote | Total (ms) | Prova revogável (ms) | Serialização payload (ms) | Authcrypt envelope (ms) | Payload apresentação (bytes) | Envelope criptografado (bytes) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 | 10 | 11 | 16.85 | 14.983 | 0.094 | 1.416 | 25855 | 35589 |
| 10 | 3 | 10 | 20 | 14.319 | 12.892 | 0.118 | 1.275 | 40981 | 55758 |
| 100 | 3 | 10 | 110 | 18.336 | 14.043 | 0.796 | 2.819 | 197601 | 264586 |
| 365 | 3 | 10 | 375 | 24.932 | 17.243 | 1.575 | 4.951 | 688935 | 919699 |
| 1000 | 3 | 10 | 1010 | 45.755 | 27.522 | 4.161 | 11.138 | 1892630 | 2524623 |
| 5000 | 3 | 10 | 5010 | 208.621 | 87.406 | 36.737 | 67.143 | 10068981 | 13426428 |
| 10000 | 3 | 10 | 10010 | 416.498 | 170.665 | 63.553 | 141.342 | 20621456 | 27496393 |
| 25000 | 3 | 10 | 25010 | 1101.464 | 443.043 | 180.031 | 379.512 | 52726399 | 70302985 |


## Tabela 4B. Decomposição Diagnóstica da Prova Revogável

| Janelas válidas | Experimentos | Janelas totais no pacote | Apresentação anoncreds (ms) | Primary proof (ms) | Sequência revogável total (ms) | Confirmações estimadas (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 | 11 | 12.722 | 0.978 | 0.679 | 0 |
| 10 | 3 | 20 | 13.906 | 0.816 | 0.619 | 0 |
| 100 | 3 | 110 | 12.269 | 0.957 | 2.168 | 1.211 |
| 365 | 3 | 375 | 15.324 | 1.582 | 4.996 | 3.408 |
| 1000 | 3 | 1010 | 14.163 | 3.227 | 14.348 | 11.121 |
| 5000 | 3 | 5010 | 12.236 | 11.7 | 70.08 | 59.04 |
| 10000 | 3 | 10010 | 12.542 | 21.323 | 160.765 | 137.248 |
| 25000 | 3 | 25010 | 12.319 | 51.48 | 436.226 | 384.747 |


## Tabela 5. Throughput do Bloom

| Amostras | Janelas/credencial | Janela revogação | Escritas/credencial | Escrita (ops/s) | Leitura (ops/s) | Escrita mediana (ms/op) | Leitura mediana (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 20 | 100 | 0 | 110 | 1478.133469 | 297.993801 | 0.643 | 1.566 |


## Tabela 5B. Tempo de Registro do Vetor K no Ledger

| Chunk solicitado | Experimentos | Escritas K | K reutilizados | Status | Registro K (ms) | Setup K (ms) | ATTRIBs estimados | Chunks K | Chunk efetivo (bytes) | Total K (bytes) | Valores K |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| default | 1 | 1 | 0 | written | 41288.712 | 1.662 | 13 | 11 | 3045 | 32768 | 1024 |


## Tabela 6. Tempo de Revogação da Credencial pelo Issuer

| Janelas | Cenário | Experimentos | Janela revogação | Revogação (ms) | Chaves esperadas | Chaves escritas |
| --- | --- | --- | --- | --- | --- | --- |
| 100 | revoked_early | 3 | 0 | 70.629 | 110 | 110 |
| 100 | revoked_middle | 3 | 50 | 70.425 | 60 | 60 |
| 100 | revoked_late | 3 | 99 | 63.566 | 11 | 11 |
| 365 | revoked_early | 3 | 0 | 84.401 | 375 | 375 |
| 365 | revoked_middle | 3 | 182 | 72.762 | 193 | 193 |
| 365 | revoked_late | 3 | 364 | 60.225 | 11 | 11 |
| 1000 | revoked_early | 3 | 0 | 121.205 | 1010 | 1010 |
| 1000 | revoked_middle | 3 | 500 | 91.565 | 510 | 510 |
| 1000 | revoked_late | 3 | 999 | 64.369 | 11 | 11 |
| 5000 | revoked_early | 3 | 0 | 380.249 | 5010 | 5010 |
| 5000 | revoked_middle | 3 | 2500 | 214.622 | 2510 | 2510 |
| 5000 | revoked_late | 3 | 4999 | 79.944 | 11 | 11 |
| 10000 | revoked_early | 3 | 0 | 670.101 | 10010 | 10010 |
| 10000 | revoked_middle | 3 | 5000 | 370.153 | 5010 | 5010 |
| 10000 | revoked_late | 3 | 9999 | 73.164 | 11 | 11 |


## Tabela 7. Tamanho do Pacote de Apresentação com Entrega Parcial de Janelas

| Janelas válidas | Experimentos | Janelas extras FP | Janelas entregues ao Verificador | Total (ms) | Prova revogável (ms) | Serialização payload (ms) | Authcrypt envelope (ms) | Payload apresentação (bytes) | Envelope criptografado (bytes) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 | 10 | 1 | 14.177 | 12.723 | 0.053 | 1.219 | 10148 | 14645 |
| 10 | 3 | 10 | 1 | 13.979 | 12.637 | 0.045 | 1.218 | 10227 | 14753 |
| 100 | 3 | 10 | 1 | 14.26 | 12.957 | 0.058 | 1.103 | 10352 | 14919 |
| 365 | 3 | 10 | 3 | 14.742 | 13.605 | 0.052 | 1.063 | 14066 | 19871 |
| 1000 | 3 | 10 | 10 | 17.526 | 15.751 | 0.085 | 1.11 | 27280 | 37492 |
| 5000 | 3 | 10 | 50 | 27.388 | 24.39 | 0.284 | 2.21 | 108937 | 146368 |
| 10000 | 3 | 10 | 100 | 39.142 | 35.582 | 0.498 | 2.475 | 214379 | 286957 |
| 25000 | 3 | 10 | 250 | 74.76 | 67.143 | 1.165 | 4.423 | 535125 | 714620 |


