# Entregável 4.2 — CORS e cabeçalhos de segurança

## Como validar cabeçalhos de segurança

```bash
curl -i http://localhost:3000/health
```

Esperado no response headers:
- `Content-Security-Policy`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security`

## Como validar bloqueio de origem não autorizada

```bash
curl -i -H "Origin: https://evil.example" http://localhost:3000/health
```

Esperado:
- `HTTP/1.1 403 Forbidden`
- Body com `{"error":"Forbidden","message":"CORS origin não autorizada"}`
