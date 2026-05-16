# BlindRevoke Experimental Summary

- Generated at: 2026-05-13T13:29:02.584Z
- Config: /home/yugi/programacao/ssi-electron-revoke/tests/blindrevoke-indicio.config.json
- Output: /home/yugi/programacao/ssi-electron-revoke/tests/results/indicio/blindrevoke-bench-20260513-132054
- Default filter profile: m16777216-cap345238
- Tempo total de processamento: 08:08.211

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
| 100 | 3 | 100 | 10 | 66.722 | 78927 | 33607 | 614 | 11 |
| 365 | 3 | 365 | 10 | 158.322 | 198815 | 111074 | 614 | 11 |
| 1000 | 3 | 1000 | 10 | 372.357 | 486035 | 296619 | 614 | 11 |
| 5000 | 3 | 5000 | 10 | 1706.66 | 2295899 | 1466003 | 614 | 11 |
| 10000 | 3 | 10000 | 10 | 3387.788 | 4558127 | 2927667 | 614 | 11 |


## Tabela 2. Latência de Verificação

| Janelas | Cenário | Experimentos | Warmups | Janela revogação | Mediana (ms) | P95 (ms) | Janelas consultadas | Modo dominante |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 100 | not_revoked | 10 | 1 | - | 104.947 | 124.703 | 18 | binary_window_search |
| 100 | revoked_early | 10 | 1 | 0 | 68.185 | 99.204 | 12 | binary_window_search |
| 100 | revoked_middle | 10 | 1 | 50 | 46.955 | 68.855 | 11 | binary_window_search |
| 100 | revoked_late | 10 | 1 | 99 | 22.03 | 30.559 | 8 | binary_window_search |
| 365 | not_revoked | 10 | 1 | - | 161.799 | 189.842 | 20 | binary_window_search |
| 365 | revoked_early | 10 | 1 | 0 | 107.072 | 147.164 | 16 | binary_window_search |
| 365 | revoked_middle | 10 | 1 | 182 | 42.802 | 49.753 | 10 | binary_window_search |
| 365 | revoked_late | 10 | 1 | 364 | 52.11 | 56.298 | 10 | binary_window_search |
| 1000 | not_revoked | 10 | 1 | - | 213.797 | 248.515 | 21 | binary_window_search |
| 1000 | revoked_early | 10 | 1 | 0 | 148.398 | 223.995 | 18 | binary_window_search |
| 1000 | revoked_middle | 10 | 1 | 500 | 149.931 | 176.496 | 17 | binary_window_search |
| 1000 | revoked_late | 10 | 1 | 999 | 62.915 | 77.311 | 11 | binary_window_search |
| 5000 | not_revoked | 10 | 1 | - | 390.649 | 402.263 | 24 | binary_window_search |
| 5000 | revoked_early | 10 | 1 | 0 | 392.923 | 410.005 | 24 | binary_window_search |
| 5000 | revoked_middle | 10 | 1 | 2500 | 374.468 | 392.738 | 23 | binary_window_search |
| 5000 | revoked_late | 10 | 1 | 4999 | 186.38 | 199.511 | 14 | binary_window_search |
| 10000 | not_revoked | 10 | 1 | - | 665.988 | 684.484 | 25 | binary_window_search |
| 10000 | revoked_early | 10 | 1 | 0 | 704.546 | 722.529 | 26 | binary_window_search |
| 10000 | revoked_middle | 10 | 1 | 5000 | 670.378 | 681.45 | 25 | binary_window_search |
| 10000 | revoked_late | 10 | 1 | 9999 | 358.478 | 376.448 | 15 | binary_window_search |


## Tabela 3. Falso Positivo

| Status | Manifesto | Motivo | Fillers | Testes | FP observados | Taxa FP | FP escaparam | Taxa escaparam | Latência mediana (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ok | http://127.0.0.1:8081/manifest | - | 8 | 20 | 0 | 0 | 0 | 0 | 210.329 |


## Tabela 4. Tamanho do Pacote Completo de Apresentação

| Janelas válidas | Experimentos | Janelas extras FP | Janelas totais no pacote | Total (ms) | Prova revogável (ms) | Serialização payload (ms) | Authcrypt envelope (ms) | Payload apresentação (bytes) | Envelope criptografado (bytes) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 | 10 | 11 | 16.286 | 14.758 | 0.095 | 1.203 | 25868 | 35607 |
| 10 | 3 | 10 | 20 | 14.52 | 12.93 | 0.12 | 1.314 | 41040 | 55841 |
| 100 | 3 | 10 | 110 | 17.754 | 13.937 | 0.603 | 2.278 | 197641 | 264642 |
| 365 | 3 | 10 | 375 | 26.557 | 18.35 | 1.921 | 5.02 | 688939 | 919705 |
| 1000 | 3 | 10 | 1010 | 50.777 | 26.968 | 4.886 | 12.84 | 1892539 | 2524507 |
| 5000 | 3 | 10 | 5010 | 228.581 | 95.044 | 40.779 | 69.746 | 10069348 | 13426918 |
| 10000 | 3 | 10 | 10010 | 435.223 | 179.614 | 69.673 | 142.027 | 20621174 | 27496020 |
| 25000 | 3 | 10 | 25010 | 1122.708 | 447.26 | 200.436 | 376.236 | 52726685 | 70303368 |


## Tabela 4B. Decomposição Diagnóstica da Prova Revogável

| Janelas válidas | Experimentos | Janelas totais no pacote | Apresentação anoncreds (ms) | Primary proof (ms) | Sequência revogável total (ms) | Confirmações estimadas (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 | 11 | 18.54 | 0.819 | 0.783 | 0 |
| 10 | 3 | 20 | 17.653 | 0.824 | 0.871 | 0 |
| 100 | 3 | 110 | 17.577 | 1.109 | 1.931 | 0.691 |
| 365 | 3 | 375 | 17.899 | 1.356 | 6.205 | 4.523 |
| 1000 | 3 | 1010 | 19.061 | 3.07 | 16.682 | 11.341 |
| 5000 | 3 | 5010 | 17.871 | 12.131 | 80.329 | 68.737 |
| 10000 | 3 | 10010 | 18.598 | 22.009 | 173.15 | 151.141 |
| 25000 | 3 | 25010 | 19.685 | 52.772 | 425.946 | 374.247 |


## Tabela 5. Throughput do Bloom

| Amostras | Janelas/credencial | Janela revogação | Escritas/credencial | Escrita (ops/s) | Leitura (ops/s) | Escrita mediana (ms/op) | Leitura mediana (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 20 | 100 | 0 | 110 | 1447.528818 | 415.377284 | 0.656 | 0.925 |


## Tabela 5B. Tempo de Registro do Vetor K no Ledger

| Chunk solicitado | Experimentos | Escritas K | K reutilizados | Status | Registro K (ms) | Setup K (ms) | ATTRIBs estimados | Chunks K | Chunk efetivo (bytes) | Total K (bytes) | Valores K |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| default | 1 | 0 | 1 | reused_existing | 0 | 0 | 13 | 11 | 3045 | 32768 | 1024 |


## Tabela 6. Tempo de Revogação da Credencial pelo Issuer

| Janelas | Cenário | Experimentos | Janela revogação | Revogação (ms) | Chaves esperadas | Chaves escritas |
| --- | --- | --- | --- | --- | --- | --- |
| 100 | revoked_early | 3 | 0 | 69.532 | 110 | 110 |
| 100 | revoked_middle | 3 | 50 | 66.195 | 60 | 60 |
| 100 | revoked_late | 3 | 99 | 60.626 | 11 | 11 |
| 365 | revoked_early | 3 | 0 | 85.73 | 375 | 375 |
| 365 | revoked_middle | 3 | 182 | 73.647 | 193 | 193 |
| 365 | revoked_late | 3 | 364 | 61.016 | 11 | 11 |
| 1000 | revoked_early | 3 | 0 | 121.486 | 1010 | 1010 |
| 1000 | revoked_middle | 3 | 500 | 92.623 | 510 | 510 |
| 1000 | revoked_late | 3 | 999 | 65.517 | 11 | 11 |
| 5000 | revoked_early | 3 | 0 | 378.647 | 5010 | 5010 |
| 5000 | revoked_middle | 3 | 2500 | 216.227 | 2510 | 2510 |
| 5000 | revoked_late | 3 | 4999 | 78.015 | 11 | 11 |
| 10000 | revoked_early | 3 | 0 | 672.02 | 10010 | 10010 |
| 10000 | revoked_middle | 3 | 5000 | 375.685 | 5010 | 5010 |
| 10000 | revoked_late | 3 | 9999 | 72.628 | 11 | 11 |


## Tabela 7. Tamanho do Pacote de Apresentação com Entrega Parcial de Janelas

| Janelas válidas | Experimentos | Janelas extras FP | Janelas entregues ao Verificador | Total (ms) | Prova revogável (ms) | Serialização payload (ms) | Authcrypt envelope (ms) | Payload apresentação (bytes) | Envelope criptografado (bytes) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3 | 10 | 1 | 13.852 | 12.69 | 0.044 | 1.238 | 10190 | 14701 |
| 10 | 3 | 10 | 1 | 14.106 | 13.246 | 0.048 | 1 | 10263 | 14805 |
| 100 | 3 | 10 | 1 | 14.357 | 13.076 | 0.046 | 1.225 | 10382 | 14961 |
| 365 | 3 | 10 | 3 | 14.752 | 13.698 | 0.059 | 0.868 | 14092 | 19910 |
| 1000 | 3 | 10 | 10 | 17.358 | 15.688 | 0.088 | 1.531 | 27318 | 37546 |
| 5000 | 3 | 10 | 50 | 27.222 | 24.39 | 0.266 | 1.817 | 108986 | 146435 |
| 10000 | 3 | 10 | 100 | 40.228 | 34.308 | 0.486 | 3.628 | 214444 | 287048 |
| 25000 | 3 | 10 | 250 | 72.878 | 66.888 | 1.18 | 3.926 | 535193 | 714712 |


