# Rollout P0 -> P1 (Bootstrap Seguro)

**Status**: active
**Owner**: Ops + Security
**Last reviewed**: 2026-02-17
**Automation**: `scripts/rollout_p0_p1_check.sh` (`make rollout-check`)

## Objetivo
Ancorar o sistema em **P0 (Genesis hardcoded)** e, após verificação, ativar **P1** que libera Onboarding e tipos centrais — mantendo o princípio **Auth IS the pipeline** (sem endpoints exclusivos).

## Ordem dos passos

1) **Gate/Runtime com P0 embutido**
   - Compilar binários com `policy/genesis@v1` embarcado (hash público).
   - Validar `runtime_hash` contra allowlist de P0.

2) **Ativar apenas POST /v1/chips e GETs de leitura**
   - Remover `/v1/users`, `/v1/tokens`, `/v1/passports` (POST).
   - Manter: `GET /v1/chips/:cid`, `GET /v1/receipts/:cid/trace`, `GET /v1/passports/:cid/advisories`, `GET /v1/advisories/:cid/verify`.

3) **Submeter o Chip Originário (skill/primer)**
   - Passa por P0 (KATs de canonicidade/recibo).

4) **Submeter P1 (policy/update)**
   - Assinado por 2‑de‑3 (Dan, Sec, Ops).
   - `activation_time` com janela (ex.: T+1h).
   - Se `CHECK` aprovar, **programa a vigência**.

5) **Entrar em vigor P1**
   - Habilita `ubl/app`, `ubl/user`, `ubl/tenant`, `ubl/membership`, `ubl/token`, `ubl/revoke`.
   - Habilita `advisory/*`, `vcx/manifest`, `ubl/script`, `ubl/document`.
   - Enforce das **regras de dependência** no CHECK.

6) **Rollback (se necessário)**
   - Acionar **break-glass** para reiniciar apenas com P0.
   - Recibo especial de recovery para auditoria.

## Reason Codes (canônicos)
- `bootstrap.only_policy_and_primer`
- `onboard.app_missing`
- `onboard.user_missing_or_invalid`
- `onboard.tenant_missing_or_invalid`
- `onboard.membership_missing_or_not_admin`
- `onboard.token_denied_user_or_membership`
- `advisory.opinion_required`
- `policy.quorum_not_met`

## KATs mínimos do rollout
- Verificar `CID(P0)` do binário == publicado.
- `skill/primer` aceita sob P0.
- `policy/update (P1)` aceita com 2‑de‑N.
- Após P1: fluxo **app→user→tenant→membership→token** passa; inversões falham.
- Advisor consegue emitir `advisory/opinion` (registrado), mas **publish/pay** exigem 2‑de‑N.

## Automação (H4)

Pré-flight automatizado:

```bash
RUNTIME_HASH="<sha256:...>" make rollout-check
```

Script base:
- `scripts/rollout_p0_p1_check.sh`

Referência operacional:
- `docs/ops/ROLLOUT_AUTOMATION.md`
