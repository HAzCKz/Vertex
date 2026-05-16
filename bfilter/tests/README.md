# Testes Manuais

Esta pasta mistura testes automatizados em Rust e scripts manuais em JavaScript para validar o comportamento do `bfilter` em cenarios reais e controlados.

Existe tambem uma nota tecnica comparando a formula classica com a formula corrigida do paper:

- `NOTE_CAPACITY_FORMULA_DECISION.md`

## Quando usar cada script

### Matriz de capacidade teorica

Arquivo: `src/lib.rs`

Use quando voce quiser ver, no proprio codigo do projeto, quantas entradas cada tamanho de Bloom Filter suporta antes de ultrapassar a meta teorica de falso positivo da API.

Esse teste:
- calcula a capacidade aproximada pela formula base
- calcula a `capacity_limit` exata usada pela API
- mostra o `k` escolhido para cada tamanho
- mostra o limiar operacional equivalente a `95%` de ocupacao
- valida que `n` ainda respeita a meta e que `n + 1` ja ultrapassa o alvo

Comando:

```bash
cargo test test_matriz_capacidade_exaustao_para_tamanhos_comuns -- --nocapture
```

### Matriz de capacidade pelo paper

Arquivo: `manual_capacity_matrix_formula_paper.py`

Use quando voce quiser repetir a mesma matriz de 2MB a 32MB, mas avaliando a taxa de falso positivo pela formula corrigida do paper de Christensen, Roginsky e Jimeno.

Esse teste:
- calcula a taxa com a formula ocupacional do paper em alta precisao
- busca a maior capacidade que ainda respeita `2^-32`
- busca o melhor `k` perto do otimo classico apenas para reduzir custo computacional
- valida que `n + 1` ultrapassa a meta
- imprime a tabela de `capacity_limit` e `rotacao_95%`

Comando:

```bash
python3 tests/manual_capacity_matrix_formula_paper.py
```

### Reset rapido em modo TESTS

Arquivo: `manual_reset_test_mode.js`

Use quando voce quiser apenas limpar a instancia de testes e recriar um unico filtro ativo via `POST /test/reset`.

Esse script:
- consulta o manifesto antes
- executa o reset em modo TESTS
- valida que sobra exatamente um filtro ativo vazio
- aceita `filter_id`, `m_bits` e `k` opcionais por variavel de ambiente

Ele exige `BFILTER_ENABLE_TEST_API=1`.

### Rotacao em servico real

Arquivo: `manual_rotate_real_service.js`

Use quando voce quiser forcar a rotacao automatica de uma instancia real do servico e confirmar que:
- o filtro ativo fecha ao atingir o limiar configurado
- um novo filtro ativo e aberto
- o manifesto e os arquivos `.bloom` foram atualizados

Esse script altera a instancia real e grava revogacoes reais.

### Fronteira 94% -> 95% em servico real

Arquivo: `manual_rotate_real_service_boundary_94_to_95.js`

Use quando voce quiser validar a fronteira de seguranca da rotacao:
- em 94% ainda nao deve rotacionar
- ao atingir 95% deve rotacionar

Esse script tambem altera a instancia real e grava revogacoes reais.

### Roteamento por window_start

Arquivo: `manual_window_start_routing.js`

Use quando voce quiser validar a semantica de janelas temporais da API:
- reseta a instancia de testes
- preenche um filtro fechado com uma faixa temporal antiga
- abre um novo filtro com outra faixa temporal
- valida `GET /filters/for-window/:window_start`
- valida `POST /check` com `window_start`
- confirma o fallback para o filtro ativo quando nenhuma janela candidata e encontrada

Esse teste e especialmente util para regressao funcional da API, porque cruza `/admin/revocations/v2`, descoberta por janela e consulta por janela no mesmo fluxo.

### Sobreposicao de window_start

Arquivo: `manual_window_start_overlap_routing.js`

Use quando voce quiser validar o caso em que mais de um filtro cobre a mesma janela:
- reseta a instancia de testes
- fecha um filtro com uma faixa temporal
- escreve no novo filtro ativo com uma faixa sobreposta
- valida `GET /filters/for-window/:window_start` com dois candidatos
- valida `POST /check` na janela sobreposta
- confirma o `filter_id` concatenado na ordem atual da API

Esse teste e util para regressao do comportamento multi-filtro em consultas por janela.

### Confiabilidade em configuracao producao-like

Arquivo: `manual_false_positive_reliability_95.js`

Use quando voce quiser validar o comportamento do bloom filter perto da configuracao padrao do servico:
- reseta o ambiente de teste
- preenche ate 95% da capacidade teorica
- confirma rotacao
- verifica ausencia de falso negativo em uma amostra de inseridos
- verifica que nao aparecem falsos positivos em uma amostra pratica de chaves ausentes

Esse teste e bom para validacao operacional e de integracao. Ele mostra que o filtro continua confiavel no ponto de seguranca de 95%, mas nao mede empiricamente a taxa `2^-32`, porque essa taxa e baixa demais para uma amostra pequena.

### Validacao estatistica em laboratorio

Arquivo: `manual_false_positive_statistical_validation.js`

Use quando voce quiser comparar taxa observada vs taxa teorica de falso positivo de forma mensuravel:
- reseta o ambiente de teste com um filtro menor
- usa `TEST_K` explicito para tornar falsos positivos observaveis
- preenche ate 95% da capacidade do filtro criado
- mede falsos positivos em uma amostra grande de ausentes
- compara o resultado com o valor teorico por `z-score`

Esse teste e adequado para laboratorio, tuning e demonstracao matematica do comportamento do filtro.

### Curva empirica de capacidade

Arquivo: `manual_empirical_capacity_curve.js`

Use quando voce quiser medir varios pontos de carga no mesmo tamanho de filtro e comparar:
- taxa observada de falso positivo
- taxa teorica no ponto testado
- compatibilidade com a meta alvo

Esse teste:
- reseta o ambiente antes de cada percentual
- calcula a capacidade teorica para o `k` real do filtro
- preenche o filtro em varios percentuais dessa capacidade
- mede falsos positivos numa amostra grande de ausentes
- informa um limite empirico inferior e o primeiro ponto de falha observado

Esse e o teste mais indicado quando o objetivo e estimar capacidade empirica e compara-la com a teoria.

### Varredura de rotacao por falso positivo

Arquivo: `manual_false_positive_rotation_sweep.js`

Use quando voce quiser comparar varios percentuais candidatos de rotacao no tamanho padrao:
- reseta o ambiente de teste antes de cada percentual
- preenche o filtro com chaves identificaveis ate o percentual desejado
- testa chaves ausentes aleatorias ate encontrar o primeiro falso positivo ou ate o limite configurado
- reinicia do zero e repete o processo no proximo percentual

Por padrao ele comeca em `50%`, sobe de `5 em 5` e termina em `95%`. Esse teste e util para descobrir, na pratica, quantas consultas ausentes seriam necessarias ate aparecer o primeiro falso positivo em cada nivel de ocupacao.

### Falso positivo em um percentual unico

Arquivo: `manual_false_positive_single_percent.js`

Use quando voce quiser medir um unico ponto de ocupacao, por exemplo `90%`, com uma amostra grande de chaves ausentes aleatorias:
- reseta o ambiente de teste
- preenche o filtro ate `FILL_PERCENT`
- testa exatamente `ABSENT_KEYS_TO_TEST` chaves ausentes aleatorias
- pode paralelizar a fase de consulta com `CHECK_WORKERS`
- informa o primeiro falso positivo encontrado, se houver
- informa o total de falsos positivos observados e a taxa observada na amostra

Esse teste e util quando voce ja escolheu um percentual candidato e quer medir um volume especifico, como `100000000` consultas ausentes.

## Fluxo recomendado

1. Use `manual_window_start_routing.js` para validar a semantica de roteamento da API por janela temporal.
2. Use `manual_window_start_overlap_routing.js` para validar o caso de sobreposicao entre filtros.
3. Use `manual_false_positive_reliability_95.js` para validar o cenario mais proximo da configuracao padrao.
4. Use `manual_false_positive_statistical_validation.js` para verificar aderencia entre teoria e pratica em um cenario mensuravel.
5. Use `manual_false_positive_rotation_sweep.js` para comparar percentuais candidatos de rotacao no tamanho padrao.
6. Use `manual_false_positive_single_percent.js` para medir um unico percentual com uma amostra grande configuravel.
7. Use os scripts de rotacao real quando precisar validar o comportamento da instancia persistente e dos artefatos em disco.

## Observacoes

- Os scripts que usam `POST /test/reset` exigem `BFILTER_ENABLE_TEST_API=1`.
- Os scripts de servico real nao usam `reset` e mexem diretamente nos dados persistidos.
- Se o servico for reiniciado com novo `BFILTER_FALSE_POSITIVE_POWER`, o manifesto agora passa a refletir a configuracao ativa na inicializacao e no reset.
