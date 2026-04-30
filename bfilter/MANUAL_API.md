# Manual de Operações da API `bfilter`

## Visão geral

O `bfilter` é um serviço HTTP que expõe operações para consulta e administração de Bloom Filters usados para revogação.

O serviço:

- expõe uma API HTTP local via `axum`
- mantém estado em memória durante a execução
- persiste manifesto e filtros em disco no diretório de dados
- não realiza chamadas para APIs externas
- pode expor endpoints adicionais de teste somente quando habilitado por ambiente

Por padrão, o servidor sobe em `127.0.0.1:8080`.

## Objetivo operacional

Esta API permite:

- consultar se uma chave possivelmente está revogada
- baixar o manifesto atual de filtros
- obter um filtro específico serializado em Base64
- inserir novas chaves de revogação
- fechar, criar e rotacionar filtros
- rotacionar automaticamente o filtro ativo ao atingir o limiar operacional configurado
- resetar todos os filtros apenas em modo de teste

## Nota sobre os exemplos de resposta

Os exemplos de resposta abaixo foram capturados em uma instância temporária isolada do `bfilter`, usando uma copia dos dados do projeto em `/tmp`.

Isso significa que:

- os formatos e campos refletem o comportamento real da API
- timestamps, hashes, contadores e `filter_id` podem variar no seu ambiente
- alguns exemplos administrativos alteram o estado da instancia temporaria usada para documentacao
- o exemplo de `GET /filters/:filter_id` usa um filtro pequeno criado apenas para deixar o `bloom_base64` legivel

## Conceitos importantes

### Bloom Filter

O Bloom Filter responde apenas se uma chave:

- provavelmente existe no filtro (`maybe_present: true`)
- definitivamente não existe no filtro (`maybe_present: false`)

`true` pode ser falso positivo. `false` não deve gerar falso negativo.

### Filtro ativo

O manifesto mantém um `active_filter_id`. Esse é o filtro usado por padrão para escrita e, na maioria dos casos, também para leitura.

### Janela temporal

Algumas operações usam `window_start` para selecionar filtros candidatos com base nos campos:

- `window_start_min`
- `window_start_max`

## Variáveis de ambiente

## Como subir a API com token administrativo na linha de comando

O controle administrativo da API usa um token Bearer configurado pela variável `BFILTER_ADMIN_TOKEN`.

Para subir o serviço informando esse token diretamente na linha de comando:

```bash
BFILTER_ADMIN_TOKEN='minha-senha-admin' cargo run
```

Exemplo definindo também endereço de bind:

```bash
BFILTER_ADMIN_TOKEN='minha-senha-admin' BFILTER_BIND_ADDR='0.0.0.0:8080' cargo run
```

Exemplo definindo token e diretório de dados:

```bash
BFILTER_ADMIN_TOKEN='minha-senha-admin' BFILTER_DATA_DIR='./data' cargo run
```

Exemplo de ambiente de produção, sem endpoints de teste:

```bash
BFILTER_ADMIN_TOKEN='minha-senha-admin' \
BFILTER_DATA_DIR='./data' \
cargo run
```

Exemplo de ambiente de testes, com endpoint de reset habilitado:

```bash
BFILTER_ADMIN_TOKEN='minha-senha-admin' \
BFILTER_DATA_DIR='./data' \
BFILTER_ENABLE_TEST_API=1 \
cargo run
```

Depois disso, os endpoints administrativos devem receber:

```http
Authorization: Bearer minha-senha-admin
```

Exemplo:

```bash
curl -X POST http://127.0.0.1:8080/admin/revocations \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer minha-senha-admin' \
  -d '{
    "revocation_keys": ["credencial_A"],
    "encoding": "utf8"
  }'
```

### `BFILTER_BIND_ADDR`

Endereço de bind do servidor.

Valor padrão:

```bash
127.0.0.1:8080
```

### `BFILTER_ADMIN_TOKEN`

Token Bearer exigido para endpoints administrativos.

Valor padrão:

```bash
dev-admin-token
```

### `BFILTER_DATA_DIR`

Diretório de persistência do manifesto e dos arquivos `.bloom`.

Valor padrão:

```bash
./data
```

### `BFILTER_FILTER_BYTES`

Tamanho padrão do Bloom Filter em bytes ao criar novos filtros.

Valor padrão:

```bash
2097152
```

### `BFILTER_ROTATE_AT_PERCENT`

Percentual da `capacity_limit` que dispara a rotação automática do filtro ativo.

Valor padrão:

```bash
95
```

### `BFILTER_FALSE_POSITIVE_POWER`

Controla a meta de falso positivo no formato `2^-N`.

Valor padrão:

```bash
32
```

### `BFILTER_PUBLIC_BASE_URL`

Base pública usada para compor o campo `download_url` no manifesto.

Exemplo:

```bash
https://api.exemplo.com
```

Quando ausente, o `download_url` é montado como caminho relativo, por exemplo:

```bash
/filters/filter-123
```

### `BFILTER_ENABLE_TEST_API`

Habilita endpoints exclusivos de teste.

Valor padrão:

```bash
desabilitado
```

Quando definido como `1`, `true` ou `yes`, a API também expõe:

```bash
POST /test/reset
```

Esse endpoint não é exposto por padrão e não deve ser habilitado em produção.

## Autenticação

Os endpoints administrativos exigem o header:

```http
Authorization: Bearer <token>
```

Se o header estiver ausente ou o token for inválido, a API responde `401 Unauthorized`.

## Formato de erro

Erros gerados pelos handlers da API retornam JSON no formato:

```json
{
  "ok": false,
  "error": "mensagem de erro"
}
```

Mapeamento principal:

- `400 Bad Request`: encoding inválido, parâmetros de negócio inválidos ou filtro em estado incompatível
- `401 Unauthorized`: token administrativo ausente ou inválido
- `404 Not Found`: filtro inexistente
- `404 Not Found`: endpoint de teste não exposto porque `BFILTER_ENABLE_TEST_API` está desabilitado
- `409 Conflict`: tentativa de criar filtro com `filter_id` já existente
- `500 Internal Server Error`: erro de I/O ou falha inesperada

Observações importantes:

- erros de roteamento ou de extração automática do `axum` não passam por esse envelope; por exemplo, `POST /test/reset` com a test API desabilitada retorna `404` porque a rota nem existe e o corpo pode vir vazio
- requests com `Content-Type` incompatível ou JSON estruturalmente inválido podem retornar respostas padrão do `axum`, incluindo `415 Unsupported Media Type`, `400 Bad Request` ou `422 Unprocessable Entity`

## Referência de endpoints

### 1. `GET /health`

Retorna um resumo simples do estado do serviço.

Uso típico:

- monitoramento
- readiness/liveness
- conferência rápida do filtro ativo

Exemplo:

```bash
curl http://127.0.0.1:8080/health
```

Resposta esperada:

```json
{
  "ok": true,
  "active_filter_id": "filter-1773770314",
  "total_filters": 1
}
```

Resposta real capturada:

```json
{
  "ok": true,
  "active_filter_id": "filter-1773770314",
  "total_filters": 1
}
```

### 2. `GET /manifest`

Retorna o manifesto completo do serviço.

O manifesto inclui:

- filtro ativo
- lista de filtros
- status de cada filtro
- capacidade
- hash SHA-256 do conteúdo serializado
- `download_url`
- faixa temporal coberta por cada filtro

Exemplo:

```bash
curl http://127.0.0.1:8080/manifest
```

Resposta real capturada:

```json
{
  "manifest": {
    "active_filter_id": "filter-1773770314",
    "false_positive_power": 32,
    "filters": [
      {
        "capacity_limit": 363408,
        "closed_at": null,
        "created_at": 1773770315,
        "download_url": "/filters/filter-1773770314",
        "encoding": "base64",
        "file_name": "filter-1773770314.bloom",
        "filter_id": "filter-1773770314",
        "inserted_count": 1284,
        "k": 32,
        "m_bits": 16777216,
        "sha256_base64": "/kCBvdOHLZEfMjxx3kuT1Vc5VfkpP5vnCqFcMJ8pzmk=",
        "status": "active",
        "updated_at": 1773922641,
        "window_start_max": 1776601001,
        "window_start_min": 1773838700
      }
    ],
    "public_base_url": null,
    "service": "bfilter",
    "updated_at": 1773924474,
    "version": 1
  },
  "ok": true
}
```

Uso típico:

- sincronização de clientes
- auditoria operacional
- descoberta dos filtros disponíveis

### 3. `GET /filters/:filter_id`

Retorna os metadados do filtro e o Bloom Filter serializado em Base64.

Exemplo:

```bash
curl http://127.0.0.1:8080/filters/filter-1773770314
```

Resposta:

- `filter_id`: identificador do filtro
- `bloom_base64`: conteúdo completo do filtro em Base64
- `meta`: metadados do manifesto para esse filtro

Resposta real capturada:

```json
{
  "ok": true,
  "filter_id": "filter-manual-small",
  "bloom_base64": "QAAAAAAAAAACAAAAAAAAAAAAAAAAAAAA",
  "meta": {
    "capacity_limit": 1,
    "closed_at": null,
    "created_at": 1773924594,
    "download_url": "/filters/filter-manual-small",
    "encoding": "base64",
    "file_name": "filter-manual-small.bloom",
    "filter_id": "filter-manual-small",
    "inserted_count": 0,
    "k": 2,
    "m_bits": 64,
    "sha256_base64": "A0D92RfMTm2Xv5TYsV5tVEQO3Tev4WAsCfiT3oofjp0=",
    "status": "active",
    "updated_at": 1773924594,
    "window_start_max": null,
    "window_start_min": null
  }
}
```

Uso típico:

- distribuição do filtro para consumidores externos
- download pontual de um filtro

### 4. `GET /filters/for-window/:window_start`

Retorna os filtros candidatos para um `window_start`.

Exemplo:

```bash
curl http://127.0.0.1:8080/filters/for-window/1774000000
```

Seleção dos filtros:

- se o filtro tiver `window_start_min` e `window_start_max`, o valor deve cair dentro da faixa
- se só houver mínimo, o valor deve ser maior ou igual ao mínimo
- se só houver máximo, o valor deve ser menor ou igual ao máximo
- se não houver faixa, o filtro entra como candidato apenas se tiver itens inseridos
- quando mais de um filtro combina com a janela, a API retorna todos os candidatos ordenados com o filtro `active` primeiro; os demais vêm depois em ordem de criação

Uso típico:

- descoberta de filtros relevantes para uma janela temporal
- pré-seleção de filtros antes de uma consulta

Resposta real capturada:

```json
{
  "ok": true,
  "window_start": 1775000000,
  "filters": [
    {
      "capacity_limit": 363408,
      "closed_at": null,
      "created_at": 1773770315,
      "download_url": "/filters/filter-1773770314",
      "encoding": "base64",
      "file_name": "filter-1773770314.bloom",
      "filter_id": "filter-1773770314",
      "inserted_count": 1286,
      "k": 32,
      "m_bits": 16777216,
      "sha256_base64": "QlCtR9zKsQN+pv7vfTect56r16bQ7Fx3oTatEznjAwI=",
      "status": "active",
      "updated_at": 1773924573,
      "window_start_max": 1776601001,
      "window_start_min": 1773838700
    }
  ]
}
```

Comportamento validado em testes manuais recentes:

- cenário simples: uma janela antiga retorna somente o filtro fechado antigo, uma janela nova retorna somente o filtro ativo novo e uma janela fora de todas as faixas retorna `filters: []`
- cenário sobreposto: uma janela coberta por dois filtros retorna os dois candidatos; na implementação atual a ordem é `active` primeiro e depois o filtro fechado mais antigo

### 5. `POST /check`

Consulta se uma ou mais chaves podem estar presentes no filtro.

Payload:

```json
{
  "filter_id": "opcional",
  "keys": ["opcional"],
  "revocation_keys": ["opcional"],
  "encoding": "utf8|base64",
  "window_start": 1774000000
}
```

Regras importantes:

- deve ser enviado `keys` ou `revocation_keys`
- se ambos forem enviados, `revocation_keys` tem precedência
- quando `encoding` é omitido, o valor padrão é `utf8`
- se `filter_id` for informado, a consulta usa somente esse filtro
- se `window_start` for informado e `filter_id` não for informado, a API procura nos filtros candidatos daquela janela
- se nenhum filtro candidato for encontrado, a API usa o filtro ativo
- se nada for informado além das chaves, a API usa o filtro ativo
- quando `window_start` encontra mais de um filtro, a API consulta todos eles e retorna `maybe_present: true` se qualquer candidato indicar presença

Exemplo com `utf8`:

```bash
curl -X POST http://127.0.0.1:8080/check \
  -H 'Content-Type: application/json' \
  -d '{
    "keys": ["credencial_A", "credencial_B"],
    "encoding": "utf8"
  }'
```

Exemplo com `base64`:

```bash
curl -X POST http://127.0.0.1:8080/check \
  -H 'Content-Type: application/json' \
  -d '{
    "keys": ["Y3JlZGVuY2lhbF9B"],
    "encoding": "base64"
  }'
```

Exemplo usando `window_start`:

```bash
curl -X POST http://127.0.0.1:8080/check \
  -H 'Content-Type: application/json' \
  -d '{
    "revocation_keys": ["credencial_A"],
    "encoding": "utf8",
    "window_start": 1774000000
  }'
```

Resposta:

```json
{
  "ok": true,
  "filter_id": "filter-1773770314",
  "results": [
    {
      "key": "credencial_A",
      "maybe_present": true
    }
  ]
}
```

Resposta real capturada:

```json
{
  "ok": true,
  "filter_id": "filter-1773770314",
  "results": [
    {
      "key": "manual-key-utf8-001",
      "maybe_present": true
    }
  ]
}
```

Observação operacional:

Quando mais de um filtro é consultado por causa de `window_start`, o campo `filter_id` da resposta vem concatenado com vírgulas na mesma ordem em que os candidatos foram selecionados.

Exemplos validados manualmente:

- caso simples: `filter_id` vem com um único valor, como `filter-1774631258396978655`
- caso sobreposto: `filter_id` vem com dois ids, por exemplo `filter-ativo,filter-antigo-fechado`
- caso sem candidatos para a janela: a API faz fallback para o filtro ativo e `filter_id` volta a ter um único valor

### 6. `POST /admin/revocations`

Insere chaves de revogação em um filtro.

Requer autenticação administrativa.

Payload:

```json
{
  "issuer_did": "opcional",
  "credential_record_id": "opcional",
  "filter_id": "opcional",
  "keys": ["opcional"],
  "revocation_keys": ["opcional"],
  "encoding": "utf8|base64",
  "reason": "opcional",
  "requested_by": "opcional"
}
```

Comportamento:

- usa `revocation_keys` se presente; caso contrário usa `keys`
- quando `encoding` é omitido, o valor padrão é `utf8`
- decodifica cada item conforme `encoding`
- grava no filtro informado ou no filtro ativo
- atualiza `inserted_count`
- persiste o arquivo `.bloom`
- recalcula hashes e regrava o manifesto
- se o filtro ativo atingir o limiar configurado por `BFILTER_ROTATE_AT_PERCENT`, ele é fechado automaticamente e um novo filtro ativo é criado

Exemplo:

```bash
curl -X POST http://127.0.0.1:8080/admin/revocations \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer dev-admin-token' \
  -d '{
    "revocation_keys": ["credencial_A", "credencial_B"],
    "encoding": "utf8",
    "reason": "fraude",
    "requested_by": "admin"
  }'
```

Resposta:

```json
{
  "ok": true,
  "filter_id": "filter-1773770314",
  "inserted": 2,
  "issuer_did": null,
  "credential_record_id": null,
  "reason": "fraude",
  "requested_by": "admin"
}
```

Resposta real capturada:

```json
{
  "ok": true,
  "filter_id": "filter-1773770314",
  "inserted": 1,
  "issuer_did": null,
  "credential_record_id": null,
  "reason": "manual-doc",
  "requested_by": "codex"
}
```

### 7. `POST /admin/revocations/v2`

Versão administrativa com suporte a `window_starts`.

Requer autenticação administrativa.

Payload:

```json
{
  "issuer_did": "opcional",
  "credential_record_id": "opcional",
  "filter_id": "opcional",
  "revocation_keys": ["obrigatório"],
  "window_starts": [1773838700, 1776601001],
  "reason": "opcional",
  "requested_by": "opcional"
}
```

Comportamento:

- `revocation_keys` é obrigatório
- cada item de `revocation_keys` é gravado como bytes UTF-8 da própria string; este endpoint não aceita campo `encoding`
- se `window_starts` for enviado, deve ter o mesmo tamanho de `revocation_keys`
- se `window_starts` for omitido, a faixa temporal do filtro não é alterada
- atualiza `window_start_min` e `window_start_max` do filtro com base nos valores recebidos
- persiste o filtro e o manifesto
- se o filtro ativo atingir o limiar configurado por `BFILTER_ROTATE_AT_PERCENT`, ele é fechado automaticamente e um novo filtro ativo é criado

Exemplo:

```bash
curl -X POST http://127.0.0.1:8080/admin/revocations/v2 \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer dev-admin-token' \
  -d '{
    "filter_id": "filter-1773770314",
    "revocation_keys": ["credencial_A", "credencial_B"],
    "window_starts": [1773838700, 1776601001],
    "reason": "expiracao",
    "requested_by": "admin"
  }'
```

Observação importante:

O comportamento de payload difere de `/admin/revocations`: aqui não existe `encoding`, então uma string `"abc"` é inserida literalmente como bytes UTF-8 de `abc`.

Resposta real capturada:

```json
{
  "ok": true,
  "filter_id": "filter-1773770314",
  "inserted": 1,
  "issuer_did": null,
  "credential_record_id": null,
  "reason": "manual-doc-window",
  "requested_by": "codex"
}
```

### 8. `POST /admin/filters/close`

Fecha um filtro ativo.

Requer autenticação administrativa.

Payload:

```json
{
  "filter_id": "opcional"
}
```

Comportamento:

- se `filter_id` for informado, tenta fechar aquele filtro
- se não for informado, fecha o filtro ativo
- marca o filtro como `closed`
- preenche `closed_at`
- limpa `active_filter_id` se o filtro fechado for o ativo

Exemplo:

```bash
curl -X POST http://127.0.0.1:8080/admin/filters/close \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer dev-admin-token' \
  -d '{}'
```

Uso típico:

- encerramento controlado de um filtro antes de criar outro
- manutenção operacional

Resposta real capturada:

```json
{
  "closed_filter": {
    "capacity_limit": 363408,
    "closed_at": 1773924587,
    "created_at": 1773770315,
    "download_url": "/filters/filter-1773770314",
    "encoding": "base64",
    "file_name": "filter-1773770314.bloom",
    "filter_id": "filter-1773770314",
    "inserted_count": 1286,
    "k": 32,
    "m_bits": 16777216,
    "sha256_base64": "QlCtR9zKsQN+pv7vfTect56r16bQ7Fx3oTatEznjAwI=",
    "status": "closed",
    "updated_at": 1773924587,
    "window_start_max": 1776601001,
    "window_start_min": 1773838700
  },
  "manifest": {
    "active_filter_id": "",
    "false_positive_power": 32,
    "filters": [
      {
        "capacity_limit": 363408,
        "closed_at": 1773924587,
        "created_at": 1773770315,
        "download_url": "/filters/filter-1773770314",
        "encoding": "base64",
        "file_name": "filter-1773770314.bloom",
        "filter_id": "filter-1773770314",
        "inserted_count": 1286,
        "k": 32,
        "m_bits": 16777216,
        "sha256_base64": "QlCtR9zKsQN+pv7vfTect56r16bQ7Fx3oTatEznjAwI=",
        "status": "closed",
        "updated_at": 1773924587,
        "window_start_max": 1776601001,
        "window_start_min": 1773838700
      }
    ],
    "public_base_url": null,
    "service": "bfilter",
    "updated_at": 1773924587,
    "version": 1
  },
  "ok": true
}
```

### 9. `POST /admin/filters/create`

Cria um novo filtro ativo.

Requer autenticação administrativa.

Payload:

```json
{
  "filter_id": "opcional",
  "m_bits": 16777216,
  "k": 32
}
```

Comportamento:

- falha se já existir um filtro com status `active`
- se `filter_id` for informado, caracteres fora de `[A-Za-z0-9._-]` são removidos; se o resultado ficar vazio, a API retorna `400`
- cria novo arquivo `.bloom`
- registra metadados no manifesto
- calcula `capacity_limit`
- define o novo filtro como ativo

Exemplo:

```bash
curl -X POST http://127.0.0.1:8080/admin/filters/create \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer dev-admin-token' \
  -d '{
    "filter_id": "filter-manual-001",
    "m_bits": 16777216,
    "k": 32
  }'
```

Uso típico:

- criação manual de novo filtro
- inicialização após fechamento do ativo anterior

Resposta real capturada:

```json
{
  "active_filter": {
    "capacity_limit": 1,
    "closed_at": null,
    "created_at": 1773924594,
    "download_url": "/filters/filter-manual-small",
    "encoding": "base64",
    "file_name": "filter-manual-small.bloom",
    "filter_id": "filter-manual-small",
    "inserted_count": 0,
    "k": 2,
    "m_bits": 64,
    "sha256_base64": "",
    "status": "active",
    "updated_at": 1773924594,
    "window_start_max": null,
    "window_start_min": null
  },
  "manifest": {
    "active_filter_id": "filter-manual-small",
    "false_positive_power": 32,
    "filters": [
      {
        "capacity_limit": 363408,
        "closed_at": 1773924587,
        "created_at": 1773770315,
        "download_url": "/filters/filter-1773770314",
        "encoding": "base64",
        "file_name": "filter-1773770314.bloom",
        "filter_id": "filter-1773770314",
        "inserted_count": 1286,
        "k": 32,
        "m_bits": 16777216,
        "sha256_base64": "QlCtR9zKsQN+pv7vfTect56r16bQ7Fx3oTatEznjAwI=",
        "status": "closed",
        "updated_at": 1773924587,
        "window_start_max": 1776601001,
        "window_start_min": 1773838700
      },
      {
        "capacity_limit": 1,
        "closed_at": null,
        "created_at": 1773924594,
        "download_url": "/filters/filter-manual-small",
        "encoding": "base64",
        "file_name": "filter-manual-small.bloom",
        "filter_id": "filter-manual-small",
        "inserted_count": 0,
        "k": 2,
        "m_bits": 64,
        "sha256_base64": "A0D92RfMTm2Xv5TYsV5tVEQO3Tev4WAsCfiT3oofjp0=",
        "status": "active",
        "updated_at": 1773924594,
        "window_start_max": null,
        "window_start_min": null
      }
    ],
    "public_base_url": null,
    "service": "bfilter",
    "updated_at": 1773924594,
    "version": 1
  },
  "ok": true
}
```

### 10. `POST /admin/filters/rotate`

Fecha o filtro ativo atual e cria um novo filtro em seguida.

Requer autenticação administrativa.

Payload:

```json
{
  "filter_id": "opcional",
  "m_bits": 16777216,
  "k": 32
}
```

Comportamento:

- se houver filtro ativo, ele é fechado primeiro
- se `filter_id` for informado para o novo filtro, ele passa pela mesma sanitização de `POST /admin/filters/create`
- depois um novo filtro é criado
- o novo filtro passa a ser o ativo

Exemplo:

```bash
curl -X POST http://127.0.0.1:8080/admin/filters/rotate \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer dev-admin-token' \
  -d '{
    "filter_id": "filter-rotated-001",
    "m_bits": 16777216,
    "k": 32
  }'
```

Uso típico:

- rotação operacional periódica
- troca controlada do filtro ativo

Resposta real capturada:

```json
{
  "active_filter": {
    "capacity_limit": 1,
    "closed_at": null,
    "created_at": 1773924607,
    "download_url": "/filters/filter-rotated-small",
    "encoding": "base64",
    "file_name": "filter-rotated-small.bloom",
    "filter_id": "filter-rotated-small",
    "inserted_count": 0,
    "k": 2,
    "m_bits": 64,
    "sha256_base64": "",
    "status": "active",
    "updated_at": 1773924607,
    "window_start_max": null,
    "window_start_min": null
  },
  "manifest": {
    "active_filter_id": "filter-rotated-small",
    "false_positive_power": 32,
    "filters": [
      {
        "capacity_limit": 363408,
        "closed_at": 1773924587,
        "created_at": 1773770315,
        "download_url": "/filters/filter-1773770314",
        "encoding": "base64",
        "file_name": "filter-1773770314.bloom",
        "filter_id": "filter-1773770314",
        "inserted_count": 1286,
        "k": 32,
        "m_bits": 16777216,
        "sha256_base64": "QlCtR9zKsQN+pv7vfTect56r16bQ7Fx3oTatEznjAwI=",
        "status": "closed",
        "updated_at": 1773924587,
        "window_start_max": 1776601001,
        "window_start_min": 1773838700
      },
      {
        "capacity_limit": 1,
        "closed_at": 1773924607,
        "created_at": 1773924594,
        "download_url": "/filters/filter-manual-small",
        "encoding": "base64",
        "file_name": "filter-manual-small.bloom",
        "filter_id": "filter-manual-small",
        "inserted_count": 0,
        "k": 2,
        "m_bits": 64,
        "sha256_base64": "A0D92RfMTm2Xv5TYsV5tVEQO3Tev4WAsCfiT3oofjp0=",
        "status": "closed",
        "updated_at": 1773924607,
        "window_start_max": null,
        "window_start_min": null
      },
      {
        "capacity_limit": 1,
        "closed_at": null,
        "created_at": 1773924607,
        "download_url": "/filters/filter-rotated-small",
        "encoding": "base64",
        "file_name": "filter-rotated-small.bloom",
        "filter_id": "filter-rotated-small",
        "inserted_count": 0,
        "k": 2,
        "m_bits": 64,
        "sha256_base64": "A0D92RfMTm2Xv5TYsV5tVEQO3Tev4WAsCfiT3oofjp0=",
        "status": "active",
        "updated_at": 1773924607,
        "window_start_max": null,
        "window_start_min": null
      }
    ],
    "public_base_url": null,
    "service": "bfilter",
    "updated_at": 1773924607,
    "version": 1
  },
  "ok": true
}
```

### 11. `POST /test/reset`

Endpoint disponível somente quando `BFILTER_ENABLE_TEST_API=1`.

Objetivo:

- apagar todos os filtros `.bloom`
- zerar o manifesto
- criar um novo filtro ativo vazio

Requer autenticação administrativa.

Payload:

```json
{
  "filter_id": "opcional",
  "m_bits": 16777216,
  "k": 32
}
```

Comportamento:

- remove os filtros históricos do diretório `BFILTER_DATA_DIR/filters`
- remove também qualquer arquivo `.bloom` remanescente encontrado nesse diretório
- limpa o `manifest.json`
- restaura `false_positive_power` e `public_base_url` conforme a configuração atual do processo
- cria imediatamente um novo filtro ativo
- se `filter_id` for informado, ele passa pela mesma sanitização de `POST /admin/filters/create`
- deve ser usado apenas em cenários de teste/manual reset

Exemplo em modo de teste:

```bash
curl -X POST http://127.0.0.1:8080/test/reset \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer dev-admin-token' \
  -d '{}'
```

Com `BFILTER_ENABLE_TEST_API` desabilitado, essa rota não é registrada no roteador e um `POST /test/reset` retorna `404`, tipicamente com corpo vazio.

Resposta esperada:

```json
{
  "ok": true,
  "active_filter": {
    "filter_id": "filter-1774277000000000000",
    "status": "active",
    "inserted_count": 0
  },
  "manifest": {
    "active_filter_id": "filter-1774277000000000000",
    "filters": [
      {
        "filter_id": "filter-1774277000000000000",
        "status": "active",
        "inserted_count": 0
      }
    ]
  }
}
```

## Fluxos operacionais recomendados

### Consultar revogação

1. Identificar se a consulta será feita no filtro ativo, em um filtro específico ou por `window_start`.
2. Chamar `POST /check`.
3. Interpretar `maybe_present: true` como possível presença e `false` como ausência.

### Incluir novas revogações

1. Confirmar qual filtro deve receber a escrita.
2. Enviar `POST /admin/revocations` ou `POST /admin/revocations/v2`.
3. Validar no `GET /manifest` se `inserted_count` e a faixa temporal foram atualizados.

### Rotacionar o filtro ativo

Opção direta:

1. Chamar `POST /admin/filters/rotate`.

Opção controlada:

1. Chamar `POST /admin/filters/close`.
2. Chamar `POST /admin/filters/create`.

Opção automática:

1. Continuar gravando via `POST /admin/revocations` ou `POST /admin/revocations/v2`.
2. Ao atingir `BFILTER_ROTATE_AT_PERCENT` da `capacity_limit`, o filtro ativo será fechado automaticamente.
3. Um novo filtro ativo será criado e o manifesto será persistido.

### Resetar todo o estado em ambiente de testes

1. Subir o serviço com `BFILTER_ENABLE_TEST_API=1`.
2. Chamar `POST /test/reset`.
3. Confirmar em `GET /manifest` que existe apenas um novo filtro ativo vazio.

Exemplo:

```bash
BFILTER_ADMIN_TOKEN='dev-admin-token' \
BFILTER_ENABLE_TEST_API=1 \
cargo run
```

Depois:

```bash
curl -X POST http://127.0.0.1:8080/test/reset \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer dev-admin-token' \
  -d '{}'
```

### Distribuir filtros para consumidores

1. Consultar `GET /manifest`.
2. Ler `download_url` ou o `filter_id` desejado.
3. Baixar o conteúdo em `GET /filters/:filter_id`.

### Scripts manuais de validação prática

Validar roteamento simples por `window_start` em ambiente de testes:

```bash
cd /home/yugi/programacao/bfilter
BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
BFILTER_ROTATE_AT_PERCENT="95" \
TEST_FILTER_M_BITS="100000" \
TEST_K="4" \
INSERT_BATCH_SIZE="1000" \
OLD_WINDOW_BASE="1700000000" \
OLD_WINDOW_SPREAD="17" \
NEW_WINDOW_BASE="1700100000" \
NEW_WINDOW_SPREAD="11" \
OUTSIDE_WINDOW_START="1700200000" \
node tests/manual_window_start_routing.js
```

Validar sobreposição de `window_start` com múltiplos candidatos:

```bash
cd /home/yugi/programacao/bfilter
BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
BFILTER_ROTATE_AT_PERCENT="95" \
TEST_FILTER_M_BITS="100000" \
TEST_K="4" \
INSERT_BATCH_SIZE="1000" \
OLD_WINDOW_BASE="1700000000" \
OLD_WINDOW_SPREAD="30" \
NEW_WINDOW_BASE="1700000010" \
NEW_WINDOW_SPREAD="25" \
OUTSIDE_WINDOW_START="1700200000" \
node tests/manual_window_start_overlap_routing.js
```

Forçar a rotação até o ponto de 95% na instância real:

```bash
cd /home/yugi/programacao/bfilter
BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
BFILTER_DATA_DIR="./data" \
BFILTER_ROTATE_AT_PERCENT="95" \
BATCH_SIZE="5000" \
node tests/manual_rotate_real_service.js
```

Validar a fronteira de 94% para 95% na instância real:

```bash
cd /home/yugi/programacao/bfilter
BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
BFILTER_DATA_DIR="./data" \
BFILTER_ROTATE_AT_PERCENT="95" \
BATCH_SIZE="5000" \
node tests/manual_rotate_real_service_boundary_94_to_95.js
```

Rodar o teste isolado do endpoint de reset test-only:

```bash
cd /home/yugi/programacao/bfilter
cargo test --test api test_only_reset_endpoint_is_gated_and_resets_filters -- --nocapture
```

## Regras operacionais importantes

- Somente filtros com status `active` aceitam escrita.
- Ao atingir `BFILTER_ROTATE_AT_PERCENT` da `capacity_limit`, o filtro ativo é fechado automaticamente e um novo filtro ativo é criado.
- Filtros fechados continuam preservados em `data/filters` e referenciados no manifesto.
- `POST /admin/filters/create` falha se já houver um filtro ativo.
- `POST /admin/filters/rotate` é o caminho mais seguro para trocar o filtro ativo em uma única operação lógica.
- O manifesto é recalculado e persistido após alterações administrativas.
- `POST /test/reset` só existe em modo de teste e não deve ser exposto em produção.

## Como inspecionar o estado atual

Como o manifesto muda a cada inserção, rotação ou reset, o estado operacional atual deve ser lido da API ou do arquivo persistido no momento da análise.

Exemplos:

```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/manifest
sed -n '1,160p' data/manifest.json
```

## Observações finais

- A API não possui versionamento de rota global; apenas o endpoint `/admin/revocations/v2` traz uma segunda versão específica.
- Não há paginação, rate limiting, TLS, nem autenticação além do token Bearer administrativo.
- Como o armazenamento é local em disco, a operação depende da integridade do diretório de dados.
- O `manifest.json` persistido em `BFILTER_DATA_DIR` é o artefato que pode ser reancorado no ledger pelo emissor após rotações operacionais.
