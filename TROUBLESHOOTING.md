# 🛠️ Troubleshooting

## ✅ Checklist

- [ ] `/api/auth/login` is public
- [ ] Middleware applied to apps
- [ ] Cookie domain correct
- [ ] Redirect URI matches OIDC configuration
- [ ] HTTPS enabled

---

## 🔁 Redirect Loop

- `/api/auth/login` behind middleware
- Cookie not set
- Domain mismatch

## 🍪 Session Cookie Not Set

- Check HTTPS
- Verify domain
- Inspect browser cookies

## 🔐 Redirect URI Mismatch

Ensure exact match:

```
https://auth.example.com/api/auth/login
```

## 🚫 401 Unauthorized

- Check `authz.rules`
- Verify user email

## 🔌 forwardAuth Not Called

- Middleware not attached

## 🧱 502 Errors

- Service name/port mismatch

## 🧠 Sessions Not Persisted

- Use Redis for multiple instances

## ⏱️ Session Expiry

```yaml
session:
  session_ttl: 24h
```
