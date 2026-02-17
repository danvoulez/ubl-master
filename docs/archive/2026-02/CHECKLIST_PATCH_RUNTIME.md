## (Novo) Bloco — Certified Runtime (exigências)
- [ ] Runtime **executa** UBL e reescreve grafo/estado sem I/O implícita.
- [ ] **Policy Engine** integrado (traço completo; primeiro DENY encerra).
- [ ] **Fuel metering** e limites (tempo/opcodes/bytes) configuráveis.
- [ ] **Assinatura** do recibo com **domínio** e `runtime_hash` de build reproduzível.
- [ ] **Sandbox** para adaptadores (E/S declarada + _trace_ assinado).
- [ ] **Rich URL** do recibo + **ancoragem** opcional no Registry.
- [ ] **CRLs/Revogação** e rotação de chaves com `kid`.
