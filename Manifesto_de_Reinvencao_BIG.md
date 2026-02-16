# Manifesto de Reinvenção — Da Entrega à Prova (Versão Estendida)

> **Tese:** A próxima década migra de sistemas que _entregam_ para sistemas que _provam_.  
> Reinventar não é reescrever por vaidade; é **dar garantias** que o legado não consegue: determinismo, proveniência,
> auditabilidade, privacidade proporcional e custo estrutural menor.

---

## 1) Por que agora (contexto e motivadores)
- **IA onipresente:** modelos geram e transformam conteúdo em escala; sem trilha, a confiança colapsa em logos e promessas.
- **Regulação crescente:** setores pedem _explainability_, _audit trail_, _data lineage_ e retenção; PDF e logs soltos não bastam.
- **Custo estrutural:** reencode/reeprocesso/reingest consomem CAPEX/OPEX. Dedup global e edições _manifest-only_ derrubam ordens de grandeza.
- **Interoperabilidade real:** ecossistemas precisam ser **federados**; provas devem viajar com o artefato e funcionar **offline**.

**Conclusão**: sem **bytes canônicos**, **IDs estáveis** e **recibos portáteis**, não há base para confiança composta.

---

## 2) Axiomas (não negociáveis)
1. **Canônico primeiro (NRF‑1):** bytes canônicos (sem floats ambíguos/duplicidade), hashável, estável entre máquinas.
2. **CID/DID como alfabetos:** **CID** identifica _o quê_ (conteúdo); **DID** identifica _quem_ (atores/dispositivos).
3. **Receipt‑is‑State:** somente recibos determinísticos alteram estado; nada fora da trilha.
4. **Programas > prompts:** operações **tipadas e verificáveis** (UBL) executadas por **Runtime Certificado** sob política.
5. **Grafo > arquivo:** mídia, dinheiro, dados e processos tornam-se **grafos imutáveis deduplicados**.
6. **IA responsável:** conselhos **assinados** (AI Passport); runtime decide; política governa; trilha completa.
7. **Privacidade proporcional:** prova do necessário, nada além; _selective disclosure_ e ZK quando agrega valor.

---

## 3) Padrões nucleares
- **NRF‑1 (Canonical JSON-like):** ordenação determinística, unicidade de chaves, normalização Unicode, sem floats soltos.
- **VCX (Verifiable Media):** vídeo/imagem/áudio como **grafo de tiles**; edição é **reescrever manifestos**, não pixels.
- **UBL (Universal Binary Logic):** conjunto estrito de operações determinísticas; _programs over prompts_.
- **Certified Runtime:** executor fuel‑metered, sem E/S fora de adaptadores declarados; emite **recibo unificado**.
- **Universal Registry:** catálogo federado de **identidades, políticas, recibos, revogações e linhagens**.

---

## 4) Arquitetura de referência (macro → micro)
### 4.1 Pipeline determinístico (WA→CHECK→TR→WF)
- **WA:** sela intenção (nonce, horário, policy_ref, issuer DID).  
- **CHECK:** aplica políticas (governança, licenças, limites, sanções, KYC).  
- **TR:** executa transformação/edição determinística (manifest-first; geração de payload só quando necessário).  
- **WF:** emite **recibo unificado** com rastro completo e **runtime hash**; o recibo é o **estado**.

### 4.2 Distribuição com prova portátil
- **Merkle + assinatura** nos _packs_;  
- **Rich URLs** contendo `cid`, `did`, `rt_hash` e `sig` → **verificação offline** em segundos.

### 4.3 Advisors responsáveis (LLMs)
- Consomem **manifests/sidecars NRF‑1**; produzem **advisories assinados**; o runtime valida/aplica sob política.

---

## 5) Modelos de ameaça (e contramedidas)
| Ameaça | Efeito | Contramedida |
|---|---|---|
| Tampering em artefato | Corrupção silenciosa | **CID** por chunk, **Merkle root**, assinatura de _pack_ |
| Replay/duplicata | Duplicar efeitos | **Nonces** em WA + monotonicidade por DID/tenant |
| Execução fora da política | Shadow changes | **Receipt‑is‑State**, CHECK estrito, **policy immutability** |
| Adapter malicioso | Vaza/forja | Sandboxing + declaração de E/S + _trace_ assinado do adapter |
| Chave comprometida | Abusos | Revogação/rotação, escopos/kids, _witness logs_ opcionais |
| Alucinação de LLM | Sugestões inválidas | Advisor assina, Runtime decide; políticas limitam autonomia |

---

## 6) Privacidade e prova (sem nevoeiro)
- **Camadas de visibilidade:** _owner_, _pair_, _auditor_, _público_. Cada uma enxerga o **mínimo necessário**.  
- **Selective disclosure:** provar “≤ X”, “com KYC L2”, “sem sanções” com **ZK assertions**.  
- **Retenção e esquecimento:** políticas versionadas definem janelas e chaves de apagamento criptográfico.

---

## 7) Compliance e governança
- **Políticas como chips**: diffs auditáveis, escopos claros, _policy lockfiles_.  
- **Conformance/KATs:** suites abertas; marcas de conformidade são **ganhas por testes**, não compradas.  
- **Federation‑first:** múltiplos registries; **mesma prova, muitos verificadores**.

---

## 8) Economia (por que compensa)
- **Dedup global:** reuso de tiles/notas → 5–20× menos storage/banda.  
- **Edição sem render:** _manifest-only_ → ms em vez de minutos/horas.  
- **Suporte e jurídico:** disputas fecham pela trilha, não por opinião.  
- **Capex/Opex:** verificação local, GPU/CPU só onde agrega valor.

---

## 9) Métricas de verdade
- % de objetos com **recibos validáveis offline**.  
- **Hash‑stability** cross‑plataforma (KATs).  
- Redução de **storage/banda** por dedup (alvo 5–20×).  
- **Latência** de edição manifest-only (p95/p99).  
- **Incidentes** resolvidos com prova (sem suporte manual).  
- **Custo** por hora de operação (CPU/GB).

---

## 10) Roteiro de adoção (12 meses)
1. **Q1** — Canonical & IDs: NRF‑1 final, DIDs/passports, primeiros KATs.  
2. **Q2** — Runtime & Packs: executores certificados, Merkle+assinatura, verificador CLI.  
3. **Q3** — Advisors & Sidecars: _advisories_ assinados, sidecars determinísticos, _policy locks_.  
4. **Q4** — Federação & Pilotos: registries interoperáveis, 3–5 pilotos (mídia, pagamentos, cívico, ciência).

---

## 11) Casos farol (lighthouse)
- **Mídia verificável:** câmera→ingest VCX→edição determinística→publish selado; checagem em tribunais e redações.  
- **Money‑as‑Chips:** pagamentos/escrow/streams com política legível, prova offline e _selective disclosure_.  
- **Cívico:** reuniões, votações e orçamentos como fatos NRF‑1 com registro público.  
- **Ciência:** _pipelines_ determinísticos com recibo‑é‑estado, reprodutibilidade real.

---

## 12) Glossário rápido
- **NRF‑1:** encoding canônico (hash‑estável).  
- **CID/DID:** ID de conteúdo/ator.  
- **Recibo:** prova unificada (WA/CHECK/TR/WF).  
- **Manifesto:** “timeline”/grafo de referências.  
- **Pack:** content‑bundle com Merkle e assinatura.  
- **KAT:** _Known‑Answer Test_ para travar comportamento.

---

## 13) FAQ (curto)
**Isso censura?** Não. É infraestrutura de **prova**, não de decisão.  
**Funciona offline?** Sim. Provas via CID/Merkle/assinatura e _rich URLs_.  
**Privacidade?** Provas minimamente suficientes; escopos e ZK sob política.  
**Preciso regravar tudo?** Não. Legacy entra por **adaptadores declarados** com recibos.

---

## 14) Chamado à ação
Adote **bytes canônicos**, **IDs estáveis** e **recibos portáteis**.  
Projete como **grafo**, não como arquivo. **Provas vencem promessas.**
