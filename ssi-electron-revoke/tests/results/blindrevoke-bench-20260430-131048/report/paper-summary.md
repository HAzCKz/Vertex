# BlindRevoke Experimental Summary

- Generated at: 2026-04-30T13:15:46.622Z
- Config: /home/yugi/programacao/ssi-electron-revoke/tests/blindrevoke.config.json
- Output: /home/yugi/programacao/ssi-electron-revoke/tests/results/blindrevoke-bench-20260430-131048
- Default filter profile: m16777216-cap345238
- Tempo total de processamento: 04:57.356

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
| 100 | 3 | 100 | 10 | 74.439 | 78834 | 33604 | 614 | 11 |
| 365 | 3 | 365 | 10 | 155.494 | 198759 | 111077 | 614 | 11 |
| 1000 | 3 | 1000 | 10 | 372.665 | 485975 | 296644 | 614 | 11 |
| 5000 | 3 | 5000 | 10 | 1719.91 | 2295650 | 1465887 | 614 | 11 |
| 10000 | 3 | 10000 | 10 | 3413.117 | 4557743 | 2927443 | 614 | 11 |


## Tabela 2. Latência de Verificação

| Janelas | Cenário | Experimentos | Warmups | Janela revogação | Mediana (ms) | P95 (ms) | Janelas consultadas | Modo dominante |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 100 | not_revoked | 10 | 1 | - | 88.439 | 110.916 | 18 | binary_window_search |
| 100 | revoked_early | 10 | 1 | 0 | 57.618 | 76.719 | 12 | binary_window_search |
| 100 | revoked_middle | 10 | 1 | 50 | 51.181 | 68.689 | 11 | binary_window_search |
| 100 | revoked_late | 10 | 1 | 99 | 24.185 | 30.748 | 8 | binary_window_search |
| 365 | not_revoked | 10 | 1 | - | 125.516 | 176.274 | 20 | binary_window_search |
| 365 | revoked_early | 10 | 1 | 0 | 94.839 | 132.132 | 16 | binary_window_search |
| 365 | revoked_middle | 10 | 1 | 182 | 51.406 | 57.226 | 10 | binary_window_search |
| 365 | revoked_late | 10 | 1 | 364 | 33.193 | 47.187 | 10 | binary_window_search |
| 1000 | not_revoked | 10 | 1 | - | 160.319 | 199.417 | 21 | binary_window_search |
| 1000 | revoked_early | 10 | 1 | 0 | 145.731 | 174.91 | 18 | binary_window_search |
| 1000 | revoked_middle | 10 | 1 | 500 | 123.634 | 161.323 | 17 | binary_window_search |
| 1000 | revoked_late | 10 | 1 | 999 | 51.373 | 74.534 | 11 | binary_window_search |
| 5000 | not_revoked | 10 | 1 | - | 389.745 | 424.682 | 24 | binary_window_search |
| 5000 | revoked_early | 10 | 1 | 0 | 400.054 | 411.509 | 24 | binary_window_search |
| 5000 | revoked_middle | 10 | 1 | 2500 | 382.755 | 392.366 | 23 | binary_window_search |
| 5000 | revoked_late | 10 | 1 | 4999 | 190.95 | 196.31 | 14 | binary_window_search |
| 10000 | not_revoked | 10 | 1 | - | 668.873 | 683.993 | 25 | binary_window_search |
| 10000 | revoked_early | 10 | 1 | 0 | 708.646 | 725.524 | 26 | binary_window_search |
| 10000 | revoked_middle | 10 | 1 | 5000 | 667.734 | 689.233 | 25 | binary_window_search |
| 10000 | revoked_late | 10 | 1 | 9999 | 364.79 | 376.108 | 15 | binary_window_search |


## Tabela 3. Falso Positivo

| Status | Manifesto | Motivo | Fillers | Testes | FP observados | Taxa FP | FP escaparam | Taxa escaparam | Latência mediana (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ok | http://127.0.0.1:8081/manifest | - | 8 | 20 | 0 | 0 | 0 | 0 | 185.486 |


## Tabela 4. Tamanho do Pacote Completo de Apresentação

| Janelas válidas | Experimentos | Janelas extras FP | Janelas totais no pacote | Total (ms) | Prova revogável (ms) | Serialização payload (ms) | Authcrypt envelope (ms) | Payload apresentação (bytes) | Envelope criptografado (bytes) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 | 10 | 11 | 13.998 | 12.825 | 0.112 | 0.93 | 25831 | 35560 |
| 10 | 3 | 10 | 20 | 14.676 | 13.076 | 0.125 | 1.188 | 40961 | 55733 |
| 100 | 3 | 10 | 110 | 20.451 | 16.456 | 0.471 | 3.086 | 197635 | 264633 |
| 365 | 3 | 10 | 375 | 28.764 | 18.612 | 2.857 | 5.077 | 688866 | 919609 |
| 1000 | 3 | 10 | 1010 | 48.279 | 26.582 | 5.459 | 12.393 | 1892563 | 2524538 |
| 5000 | 3 | 10 | 5010 | 201.126 | 89.774 | 35.635 | 62.347 | 10069151 | 13426655 |
| 10000 | 3 | 10 | 10010 | 403.531 | 169.389 | 61.576 | 131.069 | 20611573 | 27483219 |
| 25000 | 3 | 10 | 25010 | 1096.974 | 436.41 | 177.455 | 377.547 | 52727150 | 70303988 |


## Tabela 4B. Decomposição Diagnóstica da Prova Revogável

| Janelas válidas | Experimentos | Janelas totais no pacote | Apresentação anoncreds (ms) | Primary proof (ms) | Sequência revogável total (ms) | Confirmações estimadas (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 | 11 | 13.153 | 0.598 | 0.771 | 0.176 |
| 10 | 3 | 20 | 14.061 | 0.838 | 0.889 | 0.051 |
| 100 | 3 | 110 | 13.641 | 0.986 | 1.752 | 0.766 |
| 365 | 3 | 375 | 14.604 | 1.791 | 4.787 | 2.999 |
| 1000 | 3 | 1010 | 13.044 | 3.359 | 13.706 | 10.285 |
| 5000 | 3 | 5010 | 12.057 | 11.366 | 78.467 | 64.985 |
| 10000 | 3 | 10010 | 12.561 | 24.607 | 161.905 | 138.438 |
| 25000 | 3 | 25010 | 12.568 | 51.788 | 435.785 | 385.102 |


## Tabela 5. Throughput do Bloom

| Amostras | Janelas/credencial | Janela revogação | Escritas/credencial | Escrita (ops/s) | Leitura (ops/s) | Escrita mediana (ms/op) | Leitura mediana (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 20 | 100 | 0 | 110 | 1510.119412 | 457.285656 | 0.626 | 1.048 |


## Tabela 5B. Tempo de Registro do Vetor K no Ledger

| Chunk solicitado | Experimentos | Registro K (ms) | Setup K (ms) | ATTRIBs estimados | Chunks K | Chunk efetivo (bytes) | Total K (bytes) | Valores K |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| default | 1 | 39108.655 | 1.044 | 13 | 11 | 3045 | 32768 | 1024 |


## Tabela 6. Tempo de Revogação da Credencial pelo Issuer

| Janelas | Cenário | Experimentos | Janela revogação | Revogação (ms) | Chaves esperadas | Chaves escritas |
| --- | --- | --- | --- | --- | --- | --- |
| 100 | revoked_early | 3 | 0 | 68.339 | 110 | 110 |
| 100 | revoked_middle | 3 | 50 | 64.609 | 60 | 60 |
| 100 | revoked_late | 3 | 99 | 62.677 | 11 | 11 |
| 365 | revoked_early | 3 | 0 | 86.862 | 375 | 375 |
| 365 | revoked_middle | 3 | 182 | 73.035 | 193 | 193 |
| 365 | revoked_late | 3 | 364 | 62.233 | 11 | 11 |
| 1000 | revoked_early | 3 | 0 | 123.831 | 1010 | 1010 |
| 1000 | revoked_middle | 3 | 500 | 93.76 | 510 | 510 |
| 1000 | revoked_late | 3 | 999 | 65.022 | 11 | 11 |
| 5000 | revoked_early | 3 | 0 | 388.161 | 5010 | 5010 |
| 5000 | revoked_middle | 3 | 2500 | 215.853 | 2510 | 2510 |
| 5000 | revoked_late | 3 | 4999 | 70.056 | 11 | 11 |
| 10000 | revoked_early | 3 | 0 | 663.686 | 10010 | 10010 |
| 10000 | revoked_middle | 3 | 5000 | 371.443 | 5010 | 5010 |
| 10000 | revoked_late | 3 | 9999 | 73.297 | 11 | 11 |


## Tabela 7. Tamanho do Pacote de Apresentação com Entrega Parcial de Janelas

| Janelas válidas | Experimentos | Janelas extras FP | Janelas entregues ao Verificador | Total (ms) | Prova revogável (ms) | Serialização payload (ms) | Authcrypt envelope (ms) | Payload apresentação (bytes) | Envelope criptografado (bytes) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 | 10 | 1 | 13.881 | 12.811 | 0.054 | 0.917 | 10153 | 14656 |
| 10 | 3 | 10 | 1 | 13.398 | 12.67 | 0.045 | 0.606 | 10209 | 14733 |
| 100 | 3 | 10 | 1 | 14.379 | 13.153 | 0.043 | 1.078 | 10335 | 14900 |
| 365 | 3 | 10 | 3 | 16.537 | 14.877 | 0.06 | 1.371 | 14053 | 19858 |
| 1000 | 3 | 10 | 10 | 17.508 | 15.885 | 0.08 | 1.384 | 27266 | 37475 |
| 5000 | 3 | 10 | 50 | 27.687 | 25.068 | 0.277 | 1.849 | 108953 | 146391 |
| 10000 | 3 | 10 | 100 | 37.735 | 34.221 | 0.486 | 2.587 | 214241 | 286775 |
| 25000 | 3 | 10 | 250 | 74.58 | 67.341 | 1.184 | 4.756 | 535092 | 714580 |


