# Certified Runtime — Motor de Estado

**Status**: active (normative complement)
**Owner**: Core Runtime
**Last reviewed**: 2026-02-20
**Primary trust model**: `SECURITY.md`

> Este documento define papéis e garantias arquiteturais. Não define milestones, janelas de tempo ou prazos fixos.

> **Tese:** O Certified Runtime não é só um carimbador de recibos. Ele é **motor de alterações**, **executor de política**,
> **árbitro determinístico** e **cartório criptográfico** do sistema. O LLM aconselha; o Runtime **decide e assina**.

## 1) Papéis formais do Certified Runtime
1. **Executor (State Engine):** aplica UBL/ops no grafo/contas, resolve referências, calcula deltas, impõe limites de combustível.
2. **Árbitro (Policy Enforcer):** avalia políticas fractais (genesis/app/tenant/objeto) no CHECK; primeiro DENY encerra.
3. **Escrivão (Receipt Authority):** em WF, sela o **recibo unificado** (linhagem, política aplicada, runtime hash, fuel, assinaturas).
4. **Cartório (Seal & Registry Bridge):** quando configurado, publica/ancora no Registry; gerencia revogações e versões sob DIDs e kids.
5. **Guardião de Determinismo:** bloqueia fontes de não-determinismo (I/O implícita, relógios flutuantes, floats ambíguos).
6. **Observabilidade determinística:** emite métricas sem dados sensíveis e com IDs estáveis (para auditoria/QA).

## 2) Relação com LLM (Accountable Advisor)
- **LLM → Advisory assinado** (leitura de sidecars/manifestos NRF‑1; sugestão de UBL).
- **Runtime → Julgamento determinístico** (aplica ou rejeita conforme política; nunca “segue” prompt).
- **Trilha:** `advisory` → `script UBL` → `CHECK`/`TR` → `recibo` (com a referência ao advisory que motivou).

## 3) Pipeline com Runtime central
**WA:** nonce, policy_ref, issuer DID, hash do runtime.  
**CHECK:** Runtime roda Policy Engine e coleta traço (quais RBs dispararam).  
**TR:** Runtime reescreve grafo/estado (manifest-first), cria/consome notas, gera tiles quando necessário via adaptadores declarados.  
**WF:** Runtime sela recibo, assina e expõe _rich URL_; opcionalmente ancora em Registry.

## 4) Garantias
- **Mesmo input → mesmo output → mesmo `@id`/CID.**
- **Sem side-channels:** toda mutação passa pelo Runtime e deixa recibo.
- **Política imutável por recibo:** `policy_ref` sela o contexto normativo daquele resultado.
- **Reprodução local do conteúdo:** qualquer verificador reproduz a decisão e o CID de conteúdo (KATs + canon estável). Reprodutibilidade bit-a-bit de binário é hardening separado.

## 5) Mapeamento de responsabilidades (RACI)
- **LLM/Advisor:** R (propõe) / A (—) / C (sim) / I (sempre)
- **Certified Runtime:** R (executa/julga) / A (assinatura) / C (política / auditor) / I (registry)
- **Policy Owners:** R (escrevem políticas) / A (governança) / C (segurança/compliance) / I (usuários)
- **Registry Operator:** R (ancoras/CRLs) / A (disponibilidade) / C (auditores) / I (público)

## 6) Glossário rápido
- **Julgamento:** decisão determinística do Runtime segundo política; **não** é “opinião” do LLM.
- **Advisory:** recomendação assinada por IA/humano; **não vinculante**.
- **Recibo Unificado:** prova completa WA/CHECK/TR/WF, com referências a advisory/política/artefatos.
