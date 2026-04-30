"""
TESTE MANUAL: MATRIZ DE CAPACIDADE PELA FORMULA DO PAPER

Paper:
Ken Christensen, Allen Roginsky, Miguel Jimeno
"A new analysis of the false positive rate of a Bloom filter"
Information Processing Letters 110 (2010) 944-949

PARA RODAR:

cd /home/yugi/programacao/bfilter
python3 tests/manual_capacity_matrix_formula_paper.py

O que este script faz:
- calcula a taxa de falso positivo pela formula corrigida do paper
- procura a maior capacidade n que ainda respeita a meta 2^-32
- busca o melhor k em torno do k otimo classico, apenas para reduzir o custo computacional
- mostra a matriz para 2MB, 4MB, 8MB, 16MB e 32MB
- valida que n respeita a meta e que n + 1 a ultrapassa

Observacao:
- para estes tamanhos, a avaliacao da formula do paper em f64 perde precisao
- por isso este teste usa Decimal em alta precisao
"""

from decimal import Decimal, getcontext
from math import comb

FALSE_POSITIVE_POWER = 32
TARGET_SIZES_MB = [2, 4, 8, 16, 32]
EXPECTED_CAPACITY_LIMITS = {
    2: 363408,
    4: 726817,
    8: 1453634,
    16: 2907269,
    32: 5814539,
}
EXPECTED_ROTATE_THRESHOLDS = {
    2: 345238,
    4: 690477,
    8: 1380953,
    16: 2761906,
    32: 5523813,
}

getcontext().prec = 80

_STIRLING_CACHE = {}


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)


def decimal_two_pow_minus(power):
    return Decimal(2) ** Decimal(-power)


def calculate_n_max_classic_approx(m_bits, false_positive_power):
    p_target = decimal_two_pow_minus(false_positive_power)
    return (Decimal(m_bits) * Decimal("0.6185").ln()) / p_target.ln()


def calculate_k_opt_classic(m_bits, n_estimate):
    return (Decimal(m_bits) / n_estimate) * Decimal(2).ln()


def stirling_second_kind_row(n):
    if n in _STIRLING_CACHE:
        return _STIRLING_CACHE[n]

    previous = [0] * (n + 1)
    previous[0] = 1

    for current_n in range(1, n + 1):
        current = [0] * (n + 1)
        for current_k in range(1, current_n + 1):
            current[current_k] = current_k * previous[current_k] + previous[current_k - 1]
        previous = current

    _STIRLING_CACHE[n] = previous
    return previous


def false_positive_probability_paper(m_bits, k, n):
    if n == 0 or k == 0:
        return Decimal(0)

    m = Decimal(m_bits)
    hashes_written = Decimal(k * n)
    ln_m = m.ln()
    stirling = stirling_second_kind_row(k)
    total = Decimal(0)

    for selected_bins in range(1, k + 1):
        occupied_probability = Decimal(0)

        for empty_bins in range(0, selected_bins + 1):
            ratio = Decimal(1) - (Decimal(empty_bins) / m)
            probability = Decimal(0) if ratio <= 0 else (hashes_written * ratio.ln()).exp()
            signal = Decimal(-1) if empty_bins % 2 else Decimal(1)
            occupied_probability += signal * Decimal(comb(selected_bins, empty_bins)) * probability

        ln_falling_ratio = -Decimal(k) * ln_m
        for offset in range(selected_bins):
            ln_falling_ratio += Decimal(m_bits - offset).ln()

        total += Decimal(stirling[selected_bins]) * ln_falling_ratio.exp() * occupied_probability

    return total


def rotation_threshold(capacity_limit, rotate_at_percent=95):
    return (capacity_limit * rotate_at_percent + 99) // 100


def max_n_for_k_paper(m_bits, k, false_positive_power):
    p_target = decimal_two_pow_minus(false_positive_power)
    n_guess = int(calculate_n_max_classic_approx(m_bits, false_positive_power).to_integral_value())
    search_radius = max(65536, n_guess // 1000)
    low = max(0, n_guess - search_radius)
    high = n_guess + search_radius
    best_n = 0
    best_p = Decimal(0)

    while low <= high:
        mid = (low + high) // 2
        p_mid = false_positive_probability_paper(m_bits, k, mid)

        if p_mid <= p_target:
            best_n = mid
            best_p = p_mid
            low = mid + 1
        else:
            high = mid - 1

    return best_n, best_p


def calculate_n_max_exact_paper(m_bits, false_positive_power):
    n_approx = calculate_n_max_classic_approx(m_bits, false_positive_power)
    k_guess = max(1, int(calculate_k_opt_classic(m_bits, n_approx).to_integral_value()))

    best_n = 0
    best_k = 1
    best_p = Decimal(0)

    for k in range(max(1, k_guess - 4), k_guess + 5):
        n_k, p_k = max_n_for_k_paper(m_bits, k, false_positive_power)
        if n_k > best_n:
            best_n = n_k
            best_k = k
            best_p = p_k

    return best_n, best_k, best_p


def main():
    p_target = decimal_two_pow_minus(FALSE_POSITIVE_POWER)
    previous_capacity_limit = 0

    print("Matriz de capacidade teorica do Bloom Filter (paper 2010)")
    print(f"Meta de falso positivo: 2^-{FALSE_POSITIVE_POWER}")
    print(
        f"{'MB':<6} {'m_bits':>12} {'k':>8} {'capacity_limit':>14} "
        f"{'rotacao_95%':>14} {'p(n_limit)':>14}"
    )

    for size_mb in TARGET_SIZES_MB:
        m_bits = size_mb * 1024 * 1024 * 8
        capacity_limit, best_k, p_at_limit = calculate_n_max_exact_paper(
            m_bits, FALSE_POSITIVE_POWER
        )
        rotate_95 = rotation_threshold(capacity_limit)
        p_after_limit = false_positive_probability_paper(m_bits, best_k, capacity_limit + 1)

        print(
            f"{size_mb:<6} {m_bits:>12} {best_k:>8} {capacity_limit:>14} "
            f"{rotate_95:>14} {float(p_at_limit):>14.6e}"
        )

        assert_true(
            capacity_limit > previous_capacity_limit,
            "capacity_limit deveria crescer com o tamanho do filtro",
        )
        assert_true(best_k == 32, f"k esperado era 32, veio {best_k} para {size_mb} MB")
        assert_true(
            capacity_limit == EXPECTED_CAPACITY_LIMITS[size_mb],
            f"capacity_limit inesperado para {size_mb} MB: {capacity_limit}",
        )
        assert_true(
            rotate_95 == EXPECTED_ROTATE_THRESHOLDS[size_mb],
            f"rotacao_95% inesperada para {size_mb} MB: {rotate_95}",
        )
        assert_true(
            p_at_limit <= p_target,
            f"p(n_limit) deveria respeitar 2^-{FALSE_POSITIVE_POWER} para {size_mb} MB",
        )
        assert_true(
            p_after_limit > p_target,
            f"p(n_limit + 1) deveria ultrapassar 2^-{FALSE_POSITIVE_POWER} para {size_mb} MB",
        )

        previous_capacity_limit = capacity_limit

    print("\nValidacao concluida com sucesso.")


if __name__ == "__main__":
    main()
