# Teste 57 - Percentuais de refutacao com 1 ou 2 janelas extras

Gerado em: 2026-03-31T12:39:39.489Z

Bloom m_bits: 200

Bloom k: 3

Rodadas planejadas: 1

Rodadas executadas: 1

<table style="border-collapse:collapse;margin:16px 0 20px 0;min-width:980px;">
<thead><tr><th style="border:1px solid #999;padding:8px 10px;background:#f3f4f6;text-align:left;">Metrica</th><th style="border:1px solid #999;padding:8px 10px;background:#f3f4f6;text-align:left;">Valor</th><th style="border:1px solid #999;padding:8px 10px;background:#f3f4f6;text-align:left;">Percentual</th><th style="border:1px solid #999;padding:8px 10px;background:#f3f4f6;text-align:left;">Observacao</th></tr></thead>
<tbody><tr><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">Rodadas com falso positivo encontrado</td><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">1/1</td><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">100.0%</td><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">falso positivo na janela principal encontrado dentro do budget</td></tr>
<tr><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">1 janela extra suficiente</td><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">1</td><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">100.0%</td><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">sequencia esperada: T,F</td></tr>
<tr><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">2 janelas extras necessarias</td><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">0</td><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">0.0%</td><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">sequencia esperada: T,T,F</td></tr>
<tr><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">Nem 2 janelas extras bastaram</td><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">0</td><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">0.0%</td><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">sequencia esperada: T,T,T</td></tr>
<tr><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">Sem falso positivo no budget</td><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">0</td><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">0.0%</td><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">rodadas em que a janela principal nao colidiu</td></tr>
<tr><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">Carga media no hit</td><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">3200.0%</td><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">-</td><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">media de ocupacao do filtro quando o FP apareceu</td></tr>
<tr><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">FP teorica media no hit</td><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">62.2%</td><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">-</td><td style="border:1px solid #bbb;padding:8px 10px;background:#ffffff;vertical-align:top;">estimativa teorica no ponto em que o FP apareceu</td></tr>
<tr><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">Tempo medio por rodada</td><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">697 ms</td><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">-</td><td style="border:1px solid #bbb;padding:8px 10px;background:#fafafa;vertical-align:top;">inclui reset do filtro, busca do hit e verificacoes</td></tr></tbody>
</table>

## Leitura rapida

- `1 janela extra suficiente`: a janela principal deu hit, mas a janela seguinte veio limpa.
- `2 janelas extras necessarias`: a janela principal e a primeira extra deram hit, mas a segunda extra veio limpa.
- `Nem 2 janelas extras bastaram`: as 3 janelas verificadas vieram com hit no Bloom.
- Os percentuais dessas tres categorias sao calculados apenas sobre as rodadas com falso positivo encontrado na janela principal.
