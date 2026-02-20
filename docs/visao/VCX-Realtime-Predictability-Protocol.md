# VCX Realtime Predictability Protocol (RPP-1)

## Objetivo

Definir um protocolo **determinístico e em tempo real** para calcular a predictabilidade durante streaming VCX (sem prever o futuro), usando apenas histórico recente já observado.

A ideia é simples:

- O player renderiza otimista quando o fluxo está estável.
- O player reduz otimização quando o fluxo fica volátil.
- A decisão é baseada em um **indicador de predictabilidade em janela deslizante + EWMA**.

---

## Chip canônico

Tipo recomendado:

- `@type: "vcx/sidecar.predictability.realtime"`

Campos mínimos:

```json
{
  "@type": "vcx/sidecar.predictability.realtime",
  "@id": "b3:...",
  "@ver": "1.0",
  "@world": "a/episode1/t/live",
  "target_manifest": "b3:manifest...",
  "group_seq": 128,
  "window": {
    "groups": 16,
    "duration_ms": 8000
  },
  "observed": {
    "guessed_tiles": 620,
    "correct_tiles": 579,
    "corrected_tiles": 41
  },
  "metrics": {
    "instant_hit_rate": "0.933871",
    "ewma_hit_rate": "0.918402",
    "ewma_volatility": "0.072114",
    "predictability_score": "0.852188"
  },
  "policy_hint": {
    "mode": "balanced",
    "max_speculative_tiles_per_group": 220,
    "prefetch_depth_groups": 3
  }
}
```

---

## Cálculo normativo

Para cada grupo temporal `g` (ex.: 500 ms):

1. Medir `hit_rate_g = correct_tiles_g / guessed_tiles_g`.
2. Medir volatilidade local: `vol_g = |hit_rate_g - hit_rate_(g-1)|`.
3. Atualizar EWMA:
   - `ewma_hit = alpha * hit_rate_g + (1-alpha) * ewma_hit_prev`
   - `ewma_vol = alpha * vol_g + (1-alpha) * ewma_vol_prev`
4. Calcular score final:
   - `score = clamp( ewma_hit * (1 - ewma_vol), 0, 1 )`

Parâmetros padrão RPP-1:

- `alpha = 0.25`
- `min_samples = 4 grupos`
- `high_threshold = 0.85`
- `low_threshold = 0.60`

---

## Política adaptativa

Com base em `predictability_score`:

- `score >= high_threshold`: `mode = aggressive_ghost`
  - Mais renderização otimista local.
- `low_threshold <= score < high_threshold`: `mode = balanced`
  - Mistura de speculative render + prefetch.
- `score < low_threshold`: `mode = download_first`
  - Reduz especulação; prioriza download real.

Essa política permite aproveitar a tendência do fluxo em tempo real, sem assumir conhecimento futuro.

---

## Semântica operacional

- O sidecar é emitido por grupo (ou a cada N grupos) pelo nó de transmissão.
- O player aplica a política imediatamente no próximo ciclo de fetch/render.
- Todos os valores devem ser serializados de forma canônica (NRF/UNC quando aplicável no pipeline UBL).

---

## Segurança e auditabilidade

- O sidecar é um chip normal: versionado, assinado e auditável.
- O score não substitui verificação por CID; apenas decide estratégia de fetch/render.
- Correções sempre prevalecem sobre especulação quando hash diverge.

---

## Compatibilidade

RPP-1 é compatível com:

- `VCX-Core` (manifest/chunks por CID)
- `VCX-PACK v1` (payload sidecar com `application/vcx-sidecar`)
- Pipeline UBL (ingestão e receipts por chip)
