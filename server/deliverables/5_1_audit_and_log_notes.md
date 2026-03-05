# Entregável 5.1 — registo seguro e rastos de auditoria

## Ficheiros de evidência

- `5_1_security_log_masked_sample.log`: exemplo de registos de segurança com email/password/token mascarados.
- `5_1_audit_logs_sample.json`: exemplo de linhas da tabela `audit_logs` já povoada com Who/What/When/Result.

## Verificação de imutabilidade

```sql
UPDATE audit_logs SET action = 'HACK' WHERE id = 1;
DELETE FROM audit_logs WHERE id = 1;
```

Ambas as operações devem falhar com erro `audit_logs are immutable` por trigger.
