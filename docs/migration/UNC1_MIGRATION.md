# Migração para UNC-1
## Fases
1. Compat: aceitar números JSON; emitir aviso e converter DEC/BND conforme origem.
2. Enforce: `REQUIRE_UNC1_NUMERIC=true` por contrato/tenant.
3. Limpeza: tarefa TR para reescrever payloads antigos (atenção a CIDs).

## Flags de gate
- `REQUIRE_UNC1_NUMERIC` (bool)
- `F64_IMPORT_MODE = bnd|reject`
