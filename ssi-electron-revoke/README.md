# SSI Electron Revoke

Aplicação desktop em Electron para operar fluxos SSI/AnonCreds com suporte a revogação de credenciais pelo algoritmo BlindRevoke. O projeto usa uma biblioteca nativa Rust/N-API para wallet, DIDs, ledger Indy/VON, schemas, creddefs, credenciais, apresentações e provas de revogação.

Este README é um guia de instalação e preparação do ambiente. O manual de uso das telas fica em:

```text
docs/MANUAL DE OPERAÇÕES - SSI - com recurso de revogação.pdf
```

## Componentes

- `src/main`: processo principal Electron, carregamento da N-API e handlers IPC.
- `src/renderer`: interface HTML/CSS/JS.
- `native/index.node`: biblioteca SSI nativa compilada, obrigatória para o app iniciar.
- `genesis.txn`: arquivo genesis usado para conectar ao ledger Indy/VON local.
- `tests`: benchmarks BlindRevoke e configurações de campanha.
- `../bfilter`: serviço HTTP do Bloom Filter usado pela revogação.
- `../ssi_napi_lib`: projeto fonte da biblioteca SSI nativa usada por `native/index.node`.
- `../von-network`: rede Indy local para desenvolvimento e testes.

Os caminhos acima assumem que os projetos foram instalados lado a lado:

```text
<pasta-de-instalacao>/
  ssi-electron-revoke/
  bfilter/
  ssi_napi_lib/
  von-network/
```

Se a sua estrutura for diferente, ajuste os caminhos relativos nos comandos.

## Pré-requisitos

Instale ou confirme no ambiente:

- Node.js e npm.
- Rust/Cargo. O `bfilter` usa edition 2024, então use uma toolchain Rust recente.
- Docker e Docker Compose para subir a VON Network.
- Linux x86_64, se você pretende usar o `native/index.node` já compilado neste projeto.

O app principal não compila a biblioteca SSI automaticamente. Ele apenas carrega:

```text
native/index.node
```

Se esse arquivo estiver ausente ou incompatível, o app falha com erro semelhante a `N-API não encontrada`.

## Instalação do app

A partir da pasta onde os projetos foram instalados:

```bash
cd ssi-electron-revoke
npm install
```

Para executar em modo desenvolvimento:

```bash
npm run dev
```

Para empacotar:

```bash
npm run pack
npm run dist
```

## Atualizar a biblioteca SSI nativa

Use estes passos quando alterar ou recompilar `../ssi_napi_lib`:

```bash
cd ../ssi_napi_lib
cargo build --release
cp target/release/libssi_native_lib.so ../ssi-electron-revoke/native/index.node
```

O arquivo resultante é um módulo Node N-API carregado pelo Electron. O projeto `ssi_napi_lib` também costuma manter uma cópia local chamada `index.node`, útil para os testes daquele repositório.

## Subir a VON Network

A VON Network fornece o ledger Indy local. Ela expõe:

- ledger browser em `http://localhost:9000`
- genesis em `http://localhost:9000/genesis`
- nós Indy nas portas `9701` a `9708`

Suba a rede:

```bash
cd ../von-network
./manage build
./manage start --wait --logs
```

Quando os logs indicarem que a rede está pronta, `Ctrl+C` apenas para a visualização dos logs; os containers continuam rodando. Para voltar aos logs:

```bash
./manage logs
```

Para parar sem apagar o ledger:

```bash
./manage stop
```

Para apagar containers e volumes do ledger, reiniciando o ambiente do zero:

```bash
./manage down
```

Depois de subir ou recriar a rede, atualize o genesis do projeto. Isso evita usar um `genesis.txn` antigo com IPs de nós que mudaram:

```bash
cd ../ssi-electron-revoke
curl -fsSL http://localhost:9000/genesis -o genesis.txn
```

Na VON Network local, o Trustee padrão é:

```text
seed: 000000000000000000000000Trustee1
DID:  V4SGRU86Z58d6TV7PBUe6f
```

Use esse Trustee apenas em ambiente local de desenvolvimento.

## Subir a API do Bloom Filter

O serviço `bfilter` é obrigatório para emissão, manifesto e revogação de credenciais revogáveis. Por padrão ele sobe em `127.0.0.1:8080`, usa token administrativo `dev-admin-token` e persiste dados em `./data`.

Para desenvolvimento e benchmarks, habilite a API de teste, pois os scripts usam `POST /test/reset`:

```bash
cd ../bfilter
BFILTER_ADMIN_TOKEN='dev-admin-token' \
BFILTER_ENABLE_TEST_API=1 \
BFILTER_DATA_DIR='./data' \
cargo run
```

Valide:

```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/manifest
```

Reset manual do filtro em modo de teste:

```bash
curl -X POST http://127.0.0.1:8080/test/reset \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer dev-admin-token' \
  -d '{}'
```

Para rodar o perfil de falso positivo dos benchmarks, suba uma segunda instância em `8081`:

```bash
cd ../bfilter
BFILTER_BIND_ADDR='127.0.0.1:8081' \
BFILTER_ADMIN_TOKEN='dev-admin-token' \
BFILTER_ENABLE_TEST_API=1 \
BFILTER_DATA_DIR='./data-fp' \
cargo run
```

Endpoints relevantes do `bfilter`:

- `GET /health`
- `GET /manifest`
- `GET /filters/:filter_id`
- `GET /filters/for-window/:window_start`
- `POST /check`
- `POST /admin/revocations`
- `POST /admin/revocations/v2`
- `POST /admin/filters/create`
- `POST /admin/filters/rotate`
- `POST /admin/filters/close`
- `POST /test/reset`, somente com `BFILTER_ENABLE_TEST_API=1`

O app usa como manifesto padrão:

```text
http://127.0.0.1:8080/manifest
```

## Executar o fluxo inicial no app

Antes de abrir o app, tenha a VON Network e o `bfilter` rodando.

1. Execute `npm run dev`.
2. Em `Wallet`, crie ou abra uma wallet. Ao criar, o app também gera o arquivo lateral `*.kdf.json` com os parâmetros KDF.
3. Em `Ledger`, informe o caminho absoluto ou relativo do `genesis.txn` e clique em `Connect`; depois rode `Healthcheck`.
4. Em `DIDs`, crie um DID próprio. Para publicar no ledger local, importe o Trustee padrão e registre o DID selecionado com role `ENDORSER`.
5. Em `Schemas`, crie e publique um schema. Se ele for revogável, os atributos técnicos `seed`, `start_time`, `unit_of_time`, `time_window` e `root_merkle_L` são adicionados pelo fluxo de revogação.
6. Em `CredDefs`, crie e publique a creddef do schema.
7. Em `Criar Credencial Revogável`, prepare o vetor `K`, escreva o `K` no ledger, ancore o manifesto do Bloom e emita o envelope revogável.
8. Em `Revogar Credencial`, use o token administrativo do Bloom (`dev-admin-token` no ambiente local) para executar a revogação.
9. Em `Verificar Revogação` ou `Verificar Apresentações`, confira a situação da credencial contra o manifesto e as provas entregues.

Se você executar `./manage down` na VON Network, o ledger é apagado. Nesse caso, recrie ou limpe também wallets/catálogos locais usados no app, porque schemas, creddefs e ATTRIBs antigos deixam de existir no novo ledger.

## Benchmarks BlindRevoke

Crie a configuração a partir do exemplo:

```bash
cd ssi-electron-revoke
cp tests/blindrevoke.config.example.json tests/blindrevoke.config.json
```

Confira no JSON:

- `genesisPath`: normalmente `./genesis.txn`
- `walletPath` e `walletPass`
- `manifestUrl`: normalmente `http://127.0.0.1:8080/manifest`
- `bloomAdminToken`: deve bater com `BFILTER_ADMIN_TOKEN`
- `bloomBootstrap.resetBeforeRun`: `true` exige `BFILTER_ENABLE_TEST_API=1`
- `filterProfiles.falsePositive.manifestUrl`: use `http://127.0.0.1:8081/manifest` se rodar o perfil de falso positivo

Rodar a campanha completa:

```bash
npm run bench:campaign
```

Rodar blocos específicos:

```bash
npm run bench:issue
npm run bench:verify
npm run bench:false-positive
npm run bench:proof-size
npm run bench:throughput
npm run bench:k-ledger
npm run bench:compare-networks
npm run bench:ledger-ops
```

O `bench:ledger-ops` mede separadamente escritas de `SCHEMA`, `CRED_DEF`, DID comum e `ATTRIB` nas redes von-network e Indicio. Use `--iterations` para escolher a quantidade de repetições por operação.
As execuções iniciais descartadas como aquecimento são controladas por `SKIP_ITERATIONS_PER_OPERATION` em `tests/blindrevoke-ledger-ops-bench.js`.

Resultados são gravados em:

```text
tests/results/<timestamp>/
```

## Dados locais e arquivos gerados

O Electron usa `app.getPath("userData")` para armazenar dados auxiliares. No Linux, normalmente fica em:

```text
~/.config/ssi-electron/
```

Subpastas criadas pelo app:

- `wallets`
- `exchange/inbox`
- `exchange/outbox`
- `logs`

As wallets são arquivos SQLite e devem ser mantidas junto do seu sidecar `*.kdf.json`. Sem o sidecar, a biblioteca nativa não consegue derivar a chave correta para abrir a wallet.

## Diagnóstico rápido

- `N-API não encontrada`: confirme `native/index.node` ou recompile a SSI nativa e copie o `.so` para esse caminho.
- `WalletNotOpen` ao conectar no ledger: abra uma wallet antes de `Ledger > Connect`.
- Falha ao conectar no ledger: atualize `genesis.txn` a partir de `http://localhost:9000/genesis` e confirme a VON em `http://localhost:9000`.
- `PoolNotConnected`: rode `Ledger > Connect` antes de operações que leem/escrevem no ledger.
- `POST /test/reset` retorna `404`: suba o `bfilter` com `BFILTER_ENABLE_TEST_API=1`.
- Bloom retorna `401`: o token informado no app/config não bate com `BFILTER_ADMIN_TOKEN`.
- Manifesto desatualizado: use `Gerenciar Manifesto` ou `Criar Credencial Revogável > Ancorar manifesto no ledger`.
- Schemas/CredDefs duplicados ou ausentes após reset do ledger: crie uma nova wallet de teste ou publique novamente os objetos no ledger novo.

## Referências locais

- Manual da aplicação: `docs/MANUAL DE OPERAÇÕES - SSI - com recurso de revogação.pdf`
- API Bloom Filter: `../bfilter/MANUAL_API.md`
- Biblioteca SSI nativa: `../ssi_napi_lib`
- VON Network: `../von-network`
- Benchmarks: `tests/README.md`
