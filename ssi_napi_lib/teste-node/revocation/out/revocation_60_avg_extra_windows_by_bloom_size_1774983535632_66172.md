# Teste 60 - Media de janelas extras por tamanho de Bloom

Gerado em: 2026-03-31T18:58:55.633Z

Tamanhos testados: 256, 512

k do Bloom: 3

Rodadas por tamanho: 1

<table style="border-collapse:collapse;margin:16px 0 20px 0;min-width:980px;">
<thead><tr><th style="border:1px solid #999;padding:8px 10px;background:#f3f4f6;text-align:left;">m_bits</th><th style="border:1px solid #999;padding:8px 10px;background:#f3f4f6;text-align:left;">FP</th><th style="border:1px solid #999;padding:8px 10px;background:#f3f4f6;text-align:left;">Confirm.</th><th style="border:1px solid #999;padding:8px 10px;background:#f3f4f6;text-align:left;">Media extras</th><th style="border:1px solid #999;padding:8px 10px;background:#f3f4f6;text-align:left;">Mediana</th><th style="border:1px solid #999;padding:8px 10px;background:#f3f4f6;text-align:left;">Min-Max</th><th style="border:1px solid #999;padding:8px 10px;background:#f3f4f6;text-align:left;">Distribuicao</th><th style="border:1px solid #999;padding:8px 10px;background:#f3f4f6;text-align:left;">Carga hit</th><th style="border:1px solid #999;padding:8px 10px;background:#f3f4f6;text-align:left;">Nao ref. em 10</th></tr></thead>
<tbody><tr><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">256</td><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">1/1</td><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">1</td><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">1.00</td><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">1.0</td><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">1-1</td><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">1:1</td><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">23680.0%</td><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">0</td></tr>
<tr><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">512</td><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">0/1</td><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">0</td><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">-</td><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">-</td><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">-</td><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">-</td><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">-</td><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">0</td></tr></tbody>
</table>

## Leitura rapida

- `FP`: quantas rodadas daquele tamanho chegaram a gerar falso positivo na janela principal.
- `Confirm.`: quantas dessas rodadas conseguiram confirmar o falso positivo dentro das 10 extras disponiveis.
- `Media extras`: numero medio de janelas extras necessarias para chegar a false_positive_confirmed.
- `Distribuicao`: contagem compacta no formato `extras:rodadas`. Ex.: `1:3 2:1`.
- `Nao ref. em 10`: rodadas com falso positivo encontrado, mas que nao foram confirmadas como false_positive_confirmed nas 10 extras medidas.
