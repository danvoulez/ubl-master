# UBL Book Engine — Manual do Desenvolvedor

> **Versão:** 0.1.0
> **Crates:** `ubl_book_types` · `ubl_book_engine` · `ubl_book_approve`
> **Binário CLI:** `book-approve`

---

## Índice

1. [Visão Geral](#1-visão-geral)
2. [Arquitetura](#2-arquitetura)
3. [Ciclo de vida de uma seção](#3-ciclo-de-vida-de-uma-seção)
4. [Formato do projeto — `project.yaml`](#4-formato-do-projeto--projectyaml)
5. [Crate `ubl_book_types`](#5-crate-ubl_book_types)
6. [Crate `ubl_book_engine`](#6-crate-ubl_book_engine)
7. [Crate `ubl_book_approve`](#7-crate-ubl_book_approve)
8. [CLI `book-approve`](#8-cli-book-approve)
9. [Armazenamento em disco](#9-armazenamento-em-disco)
10. [Escrevendo sua própria integração](#10-escrevendo-sua-própria-integração)
11. [Referência de tipos de chip](#11-referência-de-tipos-de-chip)

---

## 1. Visão Geral

O **UBL Book Engine** é uma máquina de escrita genérica: você declara um livro em YAML e ela cuida da geração, revisão e aprovação de cada seção — usando LLMs como autores e críticos, e o humano apenas para aprovar o resultado final.

```
project.yaml
     │
     ▼
┌─────────────┐   SectionGenerateJob   ┌───────────┐   draft
│  Scheduler  │ ─────────────────────► │ Generator │ ──────► CAS
└─────────────┘                        └───────────┘
                                             │ SectionReceipt
                                             ▼
                                       ┌───────────┐   review
                                       │  Critic   │ ──────► CAS
                                       └───────────┘
                                             │ SectionReview
                              passes?        ▼
                           ┌─────────────────────────────┐
                           │  auto_passes() == true?      │
                           └──────┬──────────────────┬───┘
                                  │ sim               │ não
                                  ▼                   ▼
                        ReadyForApproval          Revising
                                  │             (volta ao Generator
                                  ▼              com revision_of)
                          [ Humano revisa ]
                          book-approve approve
                                  │
                                  ▼
                              Approved ✅
```

O engine **não é específico para o livro do UBL**. Qualquer conteúdo longo e estruturado (manuais técnicos, documentação, relatórios) pode ser gerado através dele.

---

## 2. Arquitetura

### Crates no workspace

| crate | tipo | responsabilidade |
|-------|------|-----------------|
| `ubl_book_types` | lib | Tipos de dados canônicos (chips, specs, estados) |
| `ubl_book_engine` | lib | Workers: Generator, Critic, Scheduler, Revisor |
| `ubl_book_approve` | bin | CLI de aprovação humana |

### Dependências

```
ubl_book_approve
    └── ubl_book_engine
            └── ubl_book_types
```

### Princípios de design

- **Sem estado global.** Todo estado é passado explicitamente via traits `CasStore` / `StateStore`.
- **Testável sem rede.** `StubAiClient` e `MemCasStore` / `MemStateStore` permitem testes 100% determinísticos.
- **Chips UBL.** Cada artefato (job, receipt, review, state) é um chip JSON com `@type`, `@ver`, `@world` — compatível com o runtime UBL existente.
- **CAS BLAKE3.** Todos os blobs (prompts, rascunhos, revisões) são endereçados por conteúdo (`b3:<hex64>`).

---

## 3. Ciclo de vida de uma seção

```
Pending
  │
  │ SectionGenerateJob emitido pelo Scheduler
  ▼
Generating
  │
  │ Generator chama LLM, armazena rascunho em CAS
  ▼
DraftReadyForReview
  │
  │ Critic carrega rascunho do CAS, chama LLM para avaliação
  ▼
UnderReview
  │
  ├─── auto_passes() == true ──────────────────────────────────► ReadyForApproval
  │                                                                      │
  ├─── grade falhou, attempts < max_attempts ────► Revising              │ humano aprova
  │         │                                         │                  ▼
  │         │ Revisor constrói novo job                │             Approved ✅
  │         │ com revision_of + revision_notes_cid     │
  │         └─────────────────────────────────────────►┘
  │
  └─── grade falhou, attempts >= max_attempts ──────────────────► NeedsHumanEdit ⚠
```

### Estados terminais

| estado | significado |
|--------|-------------|
| `Approved` | Seção aceita — conteúdo final |
| `NeedsHumanEdit` | Máxima de tentativas atingida ou rejeitada pelo humano |

### Transições automáticas vs. manuais

| quem decide | transição |
|-------------|-----------|
| `run_critic` | `DraftReadyForReview → ReadyForApproval` (se `auto_passes`) |
| `run_critic` | `DraftReadyForReview → Revising` (se falhou, tentativas restantes) |
| `run_critic` | `DraftReadyForReview → NeedsHumanEdit` (se `attempt >= max_attempts`) |
| `book-approve approve` | `ReadyForApproval → Approved` |
| `book-approve reject` | `ReadyForApproval → NeedsHumanEdit` |

---

## 4. Formato do projeto — `project.yaml`

```yaml
# Identificador estável do projeto (sem espaços)
id: "meu-livro"
title: "Meu Livro Técnico"

# BCP-47: "en", "pt", "es", ...
language: "pt"

# Chave de estilo — passada ao prompt do Generator
style: "technical"

# Modelo LLM para geração
author_model: "claude-opus-4"

# Modelo LLM para revisão
critic_model: "claude-opus-4"

volumes:
  - id: "vol01"
    title: "Fundamentos"
    chapters:
      - id: "ch01"
        title: "Introdução"
        sections:
          - id: "1.1"
            title: "O que é X"
            mission: "Explicar o conceito de X de forma clara e concisa."
            outline:
              - "Definição formal de X"
              - "Por que X importa"
              - "Exemplo concreto de X em uso"
            # Opcionais — os defaults estão abaixo:
            word_min: 800          # mínimo de palavras (default: 800)
            word_soft_max: 3000    # máximo suave (default: 3000)
            max_attempts: 3        # tentativas antes de NeedsHumanEdit (default: 3)
            priority: 5            # gerado primeiro se maior (default: 5)
            code_files: []         # arquivos de código para incluir como contexto
```

### Campos obrigatórios por seção

| campo | tipo | descrição |
|-------|------|-----------|
| `id` | string | Identificador dentro do capítulo (ex: `"1.1"`) |
| `title` | string | Título da seção |
| `mission` | string | Uma frase: o que essa seção deve alcançar |

### Campos opcionais por seção

| campo | default | descrição |
|-------|---------|-----------|
| `outline` | `[]` | Pontos que o Critic verificará |
| `word_min` | `800` | Mínimo de palavras |
| `word_soft_max` | `3000` | Máximo suave (o LLM é orientado, não forçado) |
| `max_attempts` | `3` | Após este número de falhas → `NeedsHumanEdit` |
| `priority` | `5` | Seções com maior prioridade são geradas primeiro |
| `code_files` | `[]` | Arquivos de código para contexto (caminhos relativos ao repo) |

---

## 5. Crate `ubl_book_types`

### `ProjectSpec` / `VolumeSpec` / `ChapterSpec` / `SectionSpec`

Estruturas de dados deserializadas do `project.yaml`.

```rust
use ubl_book_types::ProjectSpec;

let spec = ProjectSpec::from_yaml_file("project.yaml")?;

// Iterar sobre todas as seções em ordem de declaração
for sec_ref in spec.all_sections() {
    println!("{}", sec_ref.full_id());  // "vol01/ch01/1.1"
    println!("{}", sec_ref.section.title);
}
```

`SectionRef<'a>` é um borrow que expõe `volume`, `chapter`, `section`, e o método `full_id() -> String`.

---

### `SectionGenerateJob` — chip `ubl/book.section.generate.v1`

Dispara a geração de uma seção.

| campo | tipo | descrição |
|-------|------|-----------|
| `@type` | string | `"ubl/book.section.generate.v1"` |
| `author_model` | string | Modelo a usar (ex: `"claude-opus-4"`) |
| `language` | string | BCP-47 |
| `max_attempts` | u32 | Limite de auto-revisões |
| `mission` | string | O que a seção deve cobrir |
| `outline` | Vec\<String\> | Pontos do rubric do Critic |
| `project_id` | string | ID do projeto |
| `section_id` | string | ID composto `"vol01/ch01/1.1"` |
| `revision_of` | Option\<String\> | CID do receipt anterior (só em revisões) |
| `revision_notes_cid` | Option\<String\> | CID das notas de revisão em CAS |
| `style` | string | Estilo de escrita |
| `title` | string | Título da seção |
| `word_min` | u32 | Mínimo de palavras |
| `word_soft_max` | u32 | Máximo suave |

```rust
let job = SectionGenerateJob::new("meu-livro", "vol01/ch01/1.1", "a/meu-livro/t/dev");
println!("{}", job.is_revision()); // false
```

---

### `SectionReceipt` — chip `ubl/book.section.receipt.v1`

Produzido após geração bem-sucedida.

| campo | tipo | descrição |
|-------|------|-----------|
| `attempt` | u32 | Número da tentativa (começa em 1) |
| `author_model` | string | Modelo usado |
| `draft_cid` | string | CID do rascunho em CAS |
| `generate_job_cid` | string | CID do job que disparou isso |
| `prompt_cid` | string | CID do prompt usado (reprodutibilidade) |
| `review_cid` | Option\<String\> | CID da review (preenchido após o Critic) |
| `tokens_used` | u32 | Tokens consumidos |
| `version` | u32 | Versão do receipt dentro do ciclo da seção |
| `word_count` | u32 | Palavras no rascunho gerado |

---

### `SectionReview` — chip `ubl/book.section.review.v1`

Produzido pelo Critic.

| campo | tipo | descrição |
|-------|------|-----------|
| `advisory_cid` | string | CID do texto de comentário editorial em CAS |
| `blocking_issues` | Vec\<String\> | Problemas que bloqueiam aprovação automática |
| `coverage` | Vec\<ReviewCoverage\> | Cobertura de cada ponto do outline |
| `grade` | ReviewGrade | Nota geral |
| `missing_points` | u32 | Pontos do outline não cobertos |
| `suggested_edits` | Vec\<String\> | Sugestões de melhoria (não bloqueantes) |

```rust
assert!(review.auto_passes()); // grade >= B+ && missing_points == 0 && blocking_issues.is_empty()
```

#### `ReviewGrade` — ordem do pior para o melhor

```
F < D < C < B- < B < B+ < A- < A < A+
```

`ReviewGrade::passing()` retorna `B+`. Qualquer nota `>= B+` passa automaticamente (desde que sem blocking_issues e missing_points == 0).

---

### `SectionState` — chip `ubl/book.section.state.v1`

Estado autoritativo de uma seção.

| campo | tipo | descrição |
|-------|------|-----------|
| `attempts` | u32 | Tentativas de geração realizadas |
| `last_grade` | Option\<String\> | Última nota do Critic |
| `latest_receipt_cid` | Option\<String\> | CID do receipt mais recente |
| `section_id` | string | ID composto da seção |
| `status` | SectionStatus | Estado atual |

```rust
let state = SectionState::new_pending("meu-livro", "vol01/ch01/1.1", "a/meu-livro/t/dev");
assert!(!state.is_terminal());
assert!(!state.is_in_progress());
```

---

## 6. Crate `ubl_book_engine`

### `AiClient` — trait

```rust
#[async_trait]
pub trait AiClient: Send + Sync {
    async fn complete(&self, model: &str, prompt: &str) -> Result<String>;
}
```

Implemente este trait para conectar ao Anthropic, OpenAI ou qualquer outro LLM.

#### `StubAiClient` — para testes

```rust
let ai = StubAiClient::new("resposta fixa aqui");
let result = ai.complete("qualquer-modelo", "qualquer prompt").await?;
// result == "resposta fixa aqui"
```

---

### `CasStore` — trait

```rust
pub trait CasStore: Send + Sync {
    fn put(&mut self, data: &[u8]) -> Result<String>;  // retorna CID b3:...
    fn get(&self, cid: &str) -> Result<Vec<u8>>;
    fn has(&self, cid: &str) -> bool;
}
```

Implementações disponíveis:
- `MemCasStore` — in-memory (testes / dry-run)
- `FsCasStore` *(em `ubl_book_approve`)* — filesystem (`<data_dir>/cas/`)

Função utilitária: `blake3_cid(data: &[u8]) -> String`

---

### `StateStore` — trait

```rust
pub trait StateStore: Send + Sync {
    fn load(&self, section_id: &str) -> Option<SectionState>;
    fn save(&mut self, state: &SectionState) -> Result<()>;
    fn all(&self, project_id: &str) -> Vec<SectionState>;
}
```

Implementações disponíveis:
- `MemStateStore` — in-memory (testes)
- `FsStateStore` *(em `ubl_book_approve`)* — filesystem (`<data_dir>/state/`)

---

### `run_generator` — Worker de Geração

```rust
pub async fn run_generator<C, S, A>(
    job: &SectionGenerateJob,
    cas: &mut C,
    states: &mut S,
    ai: &A,
) -> Result<SectionReceipt>
```

**O que faz:**
1. Carrega notas de revisão do CAS (se `job.revision_notes_cid` presente)
2. Constrói prompt a partir dos campos do job
3. Armazena o prompt em CAS → `prompt_cid`
4. Chama `ai.complete(job.author_model, &prompt)`
5. Armazena o rascunho em CAS → `draft_cid`
6. Incrementa `state.attempts`
7. Atualiza estado para `DraftReadyForReview`
8. Retorna `SectionReceipt`

---

### `run_critic` — Worker de Revisão

```rust
pub async fn run_critic<C, S, A>(
    receipt: &SectionReceipt,
    outline: &[String],
    critic_model: &str,
    cas: &mut C,
    states: &mut S,
    ai: &A,
) -> Result<SectionReview>
```

**O que faz:**
1. Carrega o rascunho do CAS via `receipt.draft_cid`
2. Constrói prompt de review com o outline como rubric
3. Chama `ai.complete(critic_model, &prompt)`
4. Parseia o JSON de resposta do LLM
5. Avança o estado:
   - `auto_passes()` → `ReadyForApproval`
   - falhou, `attempt < max_attempts` → `Revising`
   - falhou, `attempt >= max_attempts` → `NeedsHumanEdit`
6. Retorna `SectionReview`

#### Formato de resposta esperado do LLM (Critic)

O LLM deve retornar JSON puro (sem markdown fence):

```json
{
  "advisory_notes": "Comentário geral sobre a seção.",
  "blocking_issues": ["Falta exemplo de código para X"],
  "coverage": [
    { "covered": true,  "point": "Definição de X", "score": 95 },
    { "covered": false, "point": "Exemplo de uso",  "score": 20 }
  ],
  "grade": "B",
  "missing_points": 1,
  "suggested_edits": ["Adicionar um exemplo prático no final"]
}
```

---

### `schedule` — Scheduler

```rust
pub fn schedule<S: StateStore>(
    spec: &ProjectSpec,
    states: &S,
) -> Vec<SectionGenerateJob>
```

Retorna jobs para todas as seções em estado `Pending` (ou sem estado) ordenadas por `priority` decrescente.

```rust
pub fn schedule_revisions<S: StateStore>(
    spec: &ProjectSpec,
    states: &S,
) -> Vec<SectionGenerateJob>
```

Retorna jobs para seções em estado `Revising`, com `revision_of` preenchido a partir do `latest_receipt_cid` do estado.

---

### `build_revision_job` — Revisor

```rust
pub fn build_revision_job<C: CasStore>(
    base_job: &SectionGenerateJob,
    review: &SectionReview,
    cas: &mut C,
    previous_receipt_cid: &str,
) -> Result<SectionGenerateJob>
```

Dado um job base e uma review com falha, compila as notas de revisão em texto legível, armazena no CAS e retorna um novo job com `revision_of` e `revision_notes_cid` preenchidos.

As notas incluem:
- Nota geral do Critic
- Blocking issues (se houver)
- Pontos do outline não cobertos
- Sugestões de edição

---

## 7. Crate `ubl_book_approve`

### `FsCasStore`

Implementa `CasStore` com armazenamento em disco.

```
<data_dir>/cas/b3_<hex64>.bin
```

- `put`: Computa CID BLAKE3, escreve arquivo se não existir (idempotente)
- `get`: Lê arquivo pelo CID
- Formato CID no nome de arquivo: `b3:abc123` → `b3_abc123.bin` (`:` substituído por `_`)

### `FsStateStore`

Implementa `StateStore` com armazenamento em disco.

```
<data_dir>/state/<section_id_safe>.json
```

- `section_id` é sanitizado: `/` → `__` (ex: `vol01/ch01/1.1` → `vol01__ch01__1.1.json`)
- Cada arquivo é um `SectionState` serializado com `serde_json::to_string_pretty`

---

## 8. CLI `book-approve`

### Instalação

```bash
cargo install --path crates/ubl_book_approve
# ou
cargo build -p ubl_book_approve
# binário em: target/debug/book-approve
```

### Opções globais

```
-p, --project <FILE>     Path para project.yaml [default: project.yaml]
-d, --data-dir <DIR>     Diretório de dados (CAS + estados) [default: .book]
```

### Subcomandos

---

#### `status` — ver estado de todas as seções

```bash
book-approve status
book-approve --project meu-livro.yaml status
```

Saída:
```
SECTION                        STATUS                   ATTEMPTS  GRADE
------------------------------------------------------------------------
vol01/ch01/1.1                 approved ✅                     1  A
vol01/ch01/1.2                 ready_for_approval ✓            1  B+
vol01/ch02/2.1                 revising                        2  C
vol02/ch03/3.1                 pending                         0  -
```

---

#### `show <section_id>` — ver rascunho de uma seção

```bash
book-approve show vol01/ch01/1.2
```

Carrega o rascunho do CAS via `latest_receipt_cid` → `draft_cid` e exibe com bordas:

```
════════════════════════════════════════════════════════════════════════
  DRAFT: vol01/ch01/1.2
════════════════════════════════════════════════════════════════════════
# O que é X

...texto do rascunho em Markdown...
════════════════════════════════════════════════════════════════════════
```

---

#### `review <section_id>` — ver review do Critic

```bash
book-approve review vol01/ch01/1.2
```

Exibe a review mais recente:

```
  Review summary for vol01/ch01/1.2
  Grade        : BPlus
  Missing pts  : 0
  Coverage:
    ✓ [95] Definição de X
    ✓ [88] Por que X importa
  Suggestions:
    → Adicionar referência bibliográfica
```

---

#### `approve <section_id>` — aprovar uma seção

```bash
book-approve approve vol01/ch01/1.2
```

Transição: `ReadyForApproval` ou `Revising` → `Approved`

```
✅  Section 'vol01/ch01/1.2' approved.

SECTION                        STATUS                   ATTEMPTS  GRADE
------------------------------------------------------------------------
vol01/ch01/1.1                 approved ✅                     1  A
vol01/ch01/1.2                 approved ✅                     1  B+
```

---

#### `reject <section_id>` — rejeitar uma seção

```bash
book-approve reject vol01/ch01/1.2
book-approve reject vol01/ch01/1.2 --reason "Conteúdo muito superficial, refazer do zero"
```

Transição: `ReadyForApproval` / `Revising` / `Approved` → `NeedsHumanEdit`

```
⚠  Section 'vol01/ch01/1.2' sent to NeedsHumanEdit. Reason: Conteúdo muito superficial
```

---

## 9. Armazenamento em disco

### Estrutura de diretórios

```
.book/                         ← data_dir (configurável via --data-dir)
├── cas/
│   ├── b3_4f3a...1c2d.bin    ← rascunho de seção (Markdown)
│   ├── b3_7b2e...0a1f.bin    ← prompt de geração
│   ├── b3_9c1d...3e4b.bin    ← receipt JSON
│   ├── b3_a2f1...8c9e.bin    ← notas de revisão
│   └── ...
└── state/
    ├── vol01__ch01__1.1.json  ← SectionState de vol01/ch01/1.1
    ├── vol01__ch01__1.2.json
    └── ...
```

### Formato de um arquivo de estado (`state/*.json`)

```json
{
  "@type": "ubl/book.section.state.v1",
  "@ver": "1.0",
  "@world": "a/meu-livro/t/dev",
  "attempts": 2,
  "last_grade": "BPlus",
  "latest_receipt_cid": "b3:4f3a...1c2d",
  "project_id": "meu-livro",
  "section_id": "vol01/ch01/1.1",
  "status": "ready_for_approval"
}
```

---

## 10. Escrevendo sua própria integração

### Pipeline mínimo com `MemCasStore` + `MemStateStore`

```rust
use ubl_book_engine::{
    run_generator, run_critic, schedule, build_revision_job,
    MemCasStore, MemStateStore, StubAiClient,
};
use ubl_book_types::ProjectSpec;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let spec = ProjectSpec::from_yaml_file("project.yaml")?;
    let mut cas = MemCasStore::default();
    let mut states = MemStateStore::default();

    // Implementar AiClient real aqui
    let ai = StubAiClient::new("...seu conteúdo...");

    // 1. Agendar seções pendentes
    let jobs = schedule(&spec, &states);

    for job in &jobs {
        // 2. Gerar rascunho
        let receipt = run_generator(job, &mut cas, &mut states, &ai).await?;

        // 3. Revisar
        let review = run_critic(
            &receipt,
            &job.outline,
            &spec.critic_model,
            &mut cas,
            &mut states,
            &ai,
        ).await?;

        if !review.auto_passes() {
            // 4. Se falhou, construir job de revisão
            let receipt_cid = states.load(&job.section_id)
                .and_then(|s| s.latest_receipt_cid)
                .unwrap();
            let revision_job = build_revision_job(job, &review, &mut cas, &receipt_cid)?;
            // dispatch revision_job...
        }
    }

    Ok(())
}
```

### Implementando `AiClient` para o Anthropic

```rust
use ubl_book_engine::AiClient;
use anyhow::Result;

pub struct AnthropicClient {
    api_key: String,
    // reqwest::Client, etc.
}

#[async_trait::async_trait]
impl AiClient for AnthropicClient {
    async fn complete(&self, model: &str, prompt: &str) -> Result<String> {
        // Chamar a API do Anthropic Messages aqui
        // POST https://api.anthropic.com/v1/messages
        todo!()
    }
}
```

---

## 11. Referência de tipos de chip

| `@type` | crate | produzido por | consumido por |
|---------|-------|---------------|---------------|
| `ubl/book.section.generate.v1` | `ubl_book_types` | Scheduler / Revisor | Generator |
| `ubl/book.section.receipt.v1` | `ubl_book_types` | Generator | Critic, `book-approve show` |
| `ubl/book.section.review.v1` | `ubl_book_types` | Critic | Revisor, `book-approve review` |
| `ubl/book.section.state.v1` | `ubl_book_types` | Todos os workers | Scheduler, `book-approve status` |

### Esquema de `@world`

Por convenção, use `a/<project_id>/t/dev` para desenvolvimento:

```
a/meu-livro/t/dev
```

Para produção:
```
a/meu-livro/t/prod
```

---

*Documentação gerada para ubl-master v0.1.0*
