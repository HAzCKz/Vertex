#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# run_parallel_von_bench.sh
#
# Roda múltiplas instâncias do benchmark von-network em paralelo
# para estressar o ledger e observar comportamento/latência.
#
# Uso:
#   ./teste-node/time/run_parallel_von_bench.sh 5 10
#     -> 5 instâncias em paralelo, cada uma com ITER=10
#
# Ou via env:
#   PARALLEL=8 ITER=20 ./teste-node/time/run_parallel_von_bench.sh
#
# Variáveis opcionais:
#   GENESIS_FILE (default: ./genesis.txn)
#   TRUSTEE_SEED / TRUSTEE_DID / WALLET_PASS (defaults do seu padrão)
#   OUTDIR (default: ./teste-node/time/parallel_logs)
# ============================================================

PARALLEL="${1:-${PARALLEL:-5}}"
ITER="${2:-${ITER:-10}}"

GENESIS_FILE="${GENESIS_FILE:-./genesis.txn}"
TRUSTEE_SEED="${TRUSTEE_SEED:-000000000000000000000000Trustee1}"
TRUSTEE_DID="${TRUSTEE_DID:-V4SGRU86Z58d6TV7PBUe6f}"
WALLET_PASS="${WALLET_PASS:-minha_senha_teste}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

TEST_JS="${PROJECT_ROOT}/teste-node/time/test_time_01_von_network_ops.js"
OUTDIR="${OUTDIR:-${PROJECT_ROOT}/teste-node/time/parallel_logs}"

mkdir -p "${OUTDIR}"

if ! command -v node >/dev/null 2>&1; then
  echo "❌ node não encontrado no PATH."
  exit 1
fi

if [ ! -f "${TEST_JS}" ]; then
  echo "❌ Teste não encontrado: ${TEST_JS}"
  exit 1
fi

echo "============================================================"
echo "🚀 PARALLEL VON BENCH"
echo "Projeto:     ${PROJECT_ROOT}"
echo "Teste:       ${TEST_JS}"
echo "PARALLEL:    ${PARALLEL}"
echo "ITER:        ${ITER}"
echo "GENESIS:     ${GENESIS_FILE}"
echo "Logs em:     ${OUTDIR}"
echo "============================================================"

run_id="$(date +%Y%m%d_%H%M%S)"
pids=()
names=()

# Função para iniciar uma instância
start_one() {
  local idx="$1"
  local tag="run_${run_id}_p${idx}"
  local log="${OUTDIR}/${tag}.log"

  echo "▶️  Iniciando instância ${idx}/${PARALLEL} -> ${tag}"
  (
    export TRUSTEE_SEED="${TRUSTEE_SEED}"
    export TRUSTEE_DID="${TRUSTEE_DID}"
    export WALLET_PASS="${WALLET_PASS}"
    export GENESIS_FILE="${GENESIS_FILE}"
    export ITER="${ITER}"
    export RUN_TAG="${tag}"      # opcional: se quiser usar no JS depois
    export PARALLEL_RUN_ID="${run_id}"

    # Importante: rodar do root do projeto para paths relativos baterem
    cd "${PROJECT_ROOT}"

    # stdout+stderr no log
    node "${TEST_JS}"
  ) >"${log}" 2>&1 &

  local pid="$!"
  pids+=("${pid}")
  names+=("${tag}")
  echo "   PID=${pid} log=${log}"
}

# Inicia todas as instâncias
for i in $(seq 1 "${PARALLEL}"); do
  start_one "${i}"
done

echo ""
echo "⏳ Aguardando ${PARALLEL} instâncias finalizarem..."
echo ""

# Espera e coleta status
fail_count=0
declare -a exit_codes=()

for i in "${!pids[@]}"; do
  pid="${pids[$i]}"
  tag="${names[$i]}"
  if wait "${pid}"; then
    code=0
    echo "✅ ${tag} (PID=${pid}) finalizou OK"
  else
    code=$?
    echo "❌ ${tag} (PID=${pid}) falhou (exit=${code})"
    fail_count=$((fail_count + 1))
  fi
  exit_codes+=("${code}")
done

echo ""
echo "============================================================"
echo "🏁 RESUMO"
echo "Run ID:     ${run_id}"
echo "Instâncias: ${PARALLEL}"
echo "Falhas:     ${fail_count}"
echo "Logs:       ${OUTDIR}"
echo "============================================================"

# Lista logs das falhas (se houver)
if [ "${fail_count}" -gt 0 ]; then
  echo ""
  echo "🔎 Logs com falha (sugestão: tail -n 80 <log>):"
  for i in "${!exit_codes[@]}"; do
    if [ "${exit_codes[$i]}" -ne 0 ]; then
      echo " - ${OUTDIR}/${names[$i]}.log"
    fi
  done
  exit 1
fi

exit 0