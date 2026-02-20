# VCX Streaming & Edição Protocol v1 (VSEP-1)

## 1. Escopo

Este documento consolida um protocolo profissional para:

1. **Streaming ao vivo** com controle adaptativo determinístico.
2. **Streaming “já gravado” (VOD)** com mapa de previsibilidade pré-computado.
3. **Edição de vídeo verificável** orientada por manifesto (sem reencode quando possível).

O objetivo é manter a regra do UBL: **Everything through the pipeline. No side channels.**

---

## 2. Princípios normativos

- **Estado canônico em chips** (`@type`, `@id`, `@ver`, `@world`).
- **Blocos por CID** como fonte de verdade para mídia e sidecars.
- **Edição por referência** (manifest rewrite) antes de qualquer recompressão.
- **Separação de responsabilidades**:
  - **Big**: ingest/render/transcode determinístico, cálculo de sidecars de mídia.
  - **Small**: governança, advisories, decisão editorial, publicação.
- **Verificação sempre manda**: rendering otimista nunca substitui confirmação por hash/CID.

---

## 3. Tipos de chips do protocolo

### 3.1 Live predictability

`vcx/sidecar.predictability.realtime`

Usado por stream ao vivo para reportar qualidade recente da especulação.

Campos essenciais:

- `target_manifest`
- `group_seq`
- `window` (grupos + duração)
- `observed` (`guessed_tiles`, `correct_tiles`, `corrected_tiles`)
- `metrics` (`instant_hit_rate`, `ewma_hit_rate`, `ewma_volatility`, `predictability_score`)
- `policy_hint` (`aggressive_ghost | balanced | download_first`)

### 3.2 VOD predictability map

`vcx/sidecar.predictability.vod`

Mapa de previsibilidade pré-computado no ingest VOD.

Campos essenciais:

- `target_manifest`
- `global_stats` (`volatility_score`, `average_shot_length_ms`)
- `regions[]` por zona/tiles com estratégia:
  - `hold_and_noise`
  - `copy_previous`
  - `download_aggressive`

### 3.3 Edição verificável

`vcx/edit.decision`

Representa decisão editorial auditável com operações explícitas:

- `trim`
- `splice_insert`
- `swap_track_ref`
- `overlay_ref`

Toda decisão gera:

- `input_manifest`
- `output_manifest`
- `operations[]`
- `reencode_required: bool`
- `editorial_receipt_cid`

---

## 4. Algoritmo normativo de live predictability (RPP profile)

Para grupo temporal `g`:

1. `hit_rate_g = correct_tiles_g / max(guessed_tiles_g, 1)`
2. `vol_g = |hit_rate_g - hit_rate_(g-1)|`
3. EWMA:
   - `ewma_hit = alpha * hit_rate_g + (1-alpha) * ewma_hit_prev`
   - `ewma_vol = alpha * vol_g + (1-alpha) * ewma_vol_prev`
4. `predictability_score = clamp(ewma_hit * (1 - ewma_vol), 0, 1)`

Parâmetros padrão VSEP-1:

- `alpha = 0.25`
- `min_samples = 4`
- `high_threshold = 0.85`
- `low_threshold = 0.60`

Política de execução:

- `score >= 0.85` → `aggressive_ghost`
- `0.60 <= score < 0.85` → `balanced`
- `score < 0.60` → `download_first`

---

## 5. Fluxo operacional ao vivo (end-to-end)

1. Big produz grupos VCX e publica manifesto incremental.
2. Player tenta render otimista conforme `policy_hint`.
3. Player valida CIDs dos tiles recebidos.
4. Divergência gera correção e entra na telemetria do próximo sidecar.
5. Small acompanha sidecars + advisories e pode ajustar política global de transmissão.

Resultado: adaptação contínua sem “prever” dados não observados.

---

## 6. Fluxo operacional VOD

1. Ingest determinístico calcula estatísticas globais e por região.
2. Big emite `vcx/sidecar.predictability.vod` assinado.
3. Player carrega manifesto + mapa antes do playback principal.
4. Para regiões de alta confiança, usa estratégia local (copy/noise).
5. Para regiões voláteis, baixa agressivamente da CDN.

No VOD, o mapa é estático por versão de manifesto (ou por capítulo/segmento).

---

## 7. Modelo editorial (edição sem reencode)

### 7.1 Operações “cheap” (O(1) em CPU)

- `trim`: recorta timeline ajustando referências.
- `splice_insert`: injeta sequência de outro manifesto.
- `swap_track_ref`: troca referência de trilha (ex.: áudio ou legenda).
- `overlay_ref`: adiciona trilha overlay por intervalo.

### 7.2 Quando reencode é obrigatório

`reencode_required = true` se:

- alteração exige regeneração de pixels base (ex.: blur destrutivo sem camada de overlay);
- mudança viola perfil/codec declarado no manifesto de saída;
- ausência de chunks necessários para montagem por referência.

### 7.3 Prova editorial

Cada decisão editorial deve produzir receipt encadeando:

- CID do manifesto de entrada;
- CID do script de edição;
- CID do manifesto de saída;
- política aplicada (`policy_ref`);
- assinaturas e timestamp lógico do runtime.

---

## 8. Segurança, conformidade e governança

- Sidecars/advisories são informativos; nunca sobrepõem verificação por hash.
- Chaves de assinatura e permissões editoriais devem estar em policy/passport.
- Publicação de versão final deve ser imutável (`output_manifest` por CID).
- Auditoria precisa reproduzir score e decisão editorial a partir dos chips.

---

## 9. Interoperabilidade

VSEP-1 integra com:

- `VCX-Core` (manifesto/grafo/chunks)
- `VCX-PACK v1` (armazenamento on-disk/on-wire)
- Runtime UBL (receipts e pipeline de governança)

---

## 10. Perfil mínimo de implementação

Para considerar uma implementação “VSEP-1 compliant”:

1. Emitir e consumir `vcx/sidecar.predictability.realtime`.
2. Suportar pelo menos 2 modos de política (`balanced` e `download_first`).
3. Suportar `vcx/sidecar.predictability.vod` no player VOD.
4. Aplicar pelo menos `trim` e `splice_insert` sem reencode.
5. Emitir `vcx/edit.decision` com `input_manifest` e `output_manifest`.

