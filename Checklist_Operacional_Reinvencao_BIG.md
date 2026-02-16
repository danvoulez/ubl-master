# Checklist Operacional de Reinvenção (Versão Estendida)

> Use esta lista como _gate_ de decisão, guia de execução e instrumento de auditoria.

---

## A) Decisão (Sim/Não + Pontuação)
Marque **Sim (1)** ou **Não (0)**. Some os pontos.
1. Falta **prova offline** do que aconteceu? [ ]  
2. Falha de **determinismo** (mesma entrada ≠ mesmo hash/ID)? [ ]  
3. Falta **composição** em unidades pequenas (grafo, não arquivo)? [ ]  
4. **Custo** alto por retrabalho (reencode/reingest/reindex)? [ ]  
5. **Políticas** fora do fluxo (não versionadas/auditáveis)? [ ]  
6. Precisa de **privacidade proporcional** (selective disclosure/ZK)? [ ]  
7. Exigências regulatórias exigem **trilha forte**? [ ]

**Decisão:**  
- 0–2 → Integre/adapte legado.  
- 3–4 → Reinvenção focal (domínio específico).  
- 5–7 → Reinvenção estrutural (adote o stack completo).

---

## B) Fundamentos técnicos
- [ ] Esquema **NRF‑1** definido (unicidade de chaves, normalização Unicode, floats eliminados).  
- [ ] IDs: **CID (BLAKE3)** para conteúdo, **DID** para atores; rotação/escopo de chaves com `kid`.  
- [ ] **Receipt‑is‑State**: formato de recibo unificado (WA/CHECK/TR/WF) e domínio de assinatura.  
- [ ] **UBL**: operações determinísticas e tipadas (sem E/S implícita).  
- [ ] **Runtime Certificado**: fuel‑metered, _no side‑channels_, build reprodutível.

---

## C) Grafo & Manifesto
- [ ] Modelo de dados **grafo‑first** (tiles/notes/steps).  
- [ ] **Manifesto** como timeline de referências (edição sem tocar payload).  
- [ ] Regras de **t0/duração** e ordenação estáveis.  
- [ ] **Dedup global** por CID (cache/CDN-aware).

---

## D) Provas portáteis
- [ ] **Merkle tree** e **assinatura** em _packs_.  
- [ ] **Rich URLs** com `cid`, `did`, `rt_hash`, `sig`.  
- [ ] Verificador **offline** (CLI/SDK) com saída clara (OK/FAIL + motivo).

---

## E) Políticas & Compliance
- [ ] Políticas como **chips versionados**; `policy_ref` em todas as operações.  
- [ ] **Nonces** e anti‑replay em WA; monotonicidade por DID/tenant.  
- [ ] **Sanções/KYC/limites** embutidos no CHECK (listas por CID).  
- [ ] **Selective disclosure/ZK** para compartilhamento mínimo.  
- [ ] **Retenção** e “direito ao esquecimento” modelados.

---

## F) IA como conselheira (Accountable Advisor)
- [ ] AI Passport (DID) + assinaturas em **advisories**.  
- [ ] Rastreabilidade: advisory → edit → receipt.  
- [ ] Políticas de autonomia (o que pode aplicar sozinho vs. requer aceite).

---

## G) Testes & Conformidade
- [ ] **KATs** cobrindo _happy path_ e bordas (cross‑plataforma).  
- [ ] **Conformance suite** pública e marca de conformidade.  
- [ ] Telemetria determinística (sem dados sensíveis).

---

## H) Interop & Legado
- [ ] **Adaptadores declarados** (WASM/host) com _trace_ assinado.  
- [ ] Mapeamentos para rails/formatos (Pix/SEPA/MP4/CSV…).  
- [ ] Estratégia de **migração** (bootstrap de manifests/saldos) e _backfill_ de recibos.

---

## I) Segurança & Chaves
- [ ] Gestão de chaves: rotação, _kids_, escopos, MFA/HSM opcional.  
- [ ] **Revogação** e listas assinadas (CRLs) com cache.  
- [ ] **Recuperação** (M‑de‑N, carência, _break‑glass_).

---

## J) Métricas de sucesso (KPIs)
- [ ] Cobertura de **prova offline** (≥ 95% dos objetos).  
- [ ] Redução de **storage/banda** por dedup (alvo 5–20×).  
- [ ] **p95/p99** de edição manifest‑only (ms).  
- [ ] % de disputas resolvidas via recibo (≥ 90%).  
- [ ] **CPU/GB** por hora de operação ↓ contínua.

---

## K) Roteiro operacional (fases)
1. **Fase 0 — Descoberta:** gaps vs. checklist; escopo mínimo viável.  
2. **Fase 1 — Fundamentos:** NRF‑1 + IDs + recibos; verificador offline.  
3. **Fase 2 — Runtime & Manifests:** edições/transformações determinísticas.  
4. **Fase 3 — Provas & Advisors:** Merkle + assinatura + _advisories_.  
5. **Fase 4 — Federação & Pilotos:** registries interoperáveis; 2–3 pilotos.  
6. **Fase 5 — Conformidade:** KATs públicos, marca e auditoria externa.

---

## L) RACI de governança (exemplo)
- **Specs/KATs:** Tech Steering (R), Foundation (A), Vendors (C), Comunidade (I)  
- **Runtimes:** Vendors (R), Foundation (A), Auditores (C), Comunidade (I)  
- **Registries:** Operadores (R), Foundation (A), Participantes (C), Público (I)

---

## M) Saídas mínimas por fase (Definition of Done)
- **Fase 1:** esquema NRF‑1, `cid()` estável, `verify-cli` funcional.  
- **Fase 2:** runtime executa UBL (manifest-only) + recibo unificado.  
- **Fase 3:** _pack_ com Merkle+assinatura + advisor emitindo chip.  
- **Fase 4:** federação básica; 2 pilotos com KPIs batidos.  
- **Fase 5:** conformance pública; selo emitido.

---

## N) Apêndice — Exemplos de políticas
- **Autonomia de advisor:** `reorder/trim` permitidos; `overlay` requer aceite; `publish` requer 2‑de‑N.  
- **Privacidade de distribuição:** público vê _proof‑lite_; auditor vê prova completa; usuário controla _selective disclosure_.  
- **Retenção:** 180 dias para sidecars QoE; 5 anos para recibos; apagar via chaves de retenção.

