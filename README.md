# Forward-Auth

[![release](https://img.shields.io/github/v/tag/clambin/forward-auth?color=green&label=release&style=plastic)](https://github.com/clambin/forward-auth/releases)
[![codecov](https://img.shields.io/codecov/c/gh/clambin/forward-auth?style=plastic)](https://app.codecov.io/gh/clambin/forward-auth)
[![Test](https://github.com/clambin/forward-auth/actions/workflows/test.yaml/badge.svg)](https://github.com/clambin/forward-auth/actions)
[![Build](https://github.com/clambin/forward-auth/actions/workflows/build.yaml/badge.svg)](https://github.com/clambin/forward-auth/actions)
[![license](https://img.shields.io/github/license/clambin/forward-auth?style=plastic)](LICENSE.md)

![logo.png](assets/images/logo.png)

`forward-auth` is a minimal, modern authentication and authorization gateway for [Traefik](https://traefik.io/) using its **forwardAuth** middleware. It protects your web applications with Single Sign-On (SSO) via OpenID Connect (OIDC) or GitHub, fine-grained access rules, and centralized session management.

## ✨ Features

- 🔐 **Single Sign-On (SSO)**: Authenticate users via any OIDC provider (Google, Authentik, Keycloak, Codeberg) or GitHub OAuth.
- 🛡️ **Flexible Authorization**: Define access rules by domain, wildcard domains, individual user email, or named user groups.
- 🛑 **Central Session Store & Revocation**: Store sessions in memory or in Redis to allow instant session invalidation across multiple instances.
- 💻 **Self-Service Session UI**: Built-in web dashboard allowing users to view their active sessions, see device info, and revoke sessions.
- 🔄 **Seamless Silent Renewal**: Short-lived browser cookies renewed automatically in the background without interrupting the user.
- 👤 **Identity Headers**: Passes authenticated user email, name, and groups to upstream applications via HTTP headers.
- 📊 **Observability**: Prometheus metrics and ready-to-use Grafana dashboards.

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
  - [Example Configuration](#example-configuration)
  - [Environment Variables](#environment-variables)
- [Identity Provider Setup](#identity-provider-setup)
- [Traefik Integration](#traefik-integration)
  - [1. Define the forwardAuth Middleware](#1-define-the-forwardauth-middleware)
  - [2. Route the Auth Service](#2-route-the-auth-service)
  - [3. Protect Your Applications](#3-protect-your-applications)
- [Authorization Rules](#authorization-rules)
- [Session Management & UI](#session-management--ui)
- [Metrics & Monitoring](#metrics--monitoring)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Overview

`forward-auth` sits alongside Traefik and intercepts incoming web requests before they reach your applications:

```
                  ┌──────────────┐
                  │ OIDC/GitHub  │
                  │   Provider   │
                  └──────▲───────┘
                         │ 3. Authenticate
                         ▼
Browser ──1. Request──► Traefik ──2. Verify──► forward-auth
                          │
                          └──4. Forward (if allowed)──► Upstream App
```

1. **Request**: A user navigates to a protected application.
2. **Verify**: Traefik asks `forward-auth` to verify the user's session cookie.
3. **Authenticate**: If the user is not logged in, `forward-auth` redirects them to your identity provider.
4. **Access**: Once authenticated and authorized according to your rules, Traefik forwards the request downstream with user identity headers.

---

## How It Works

From a user perspective, the experience is simple and seamless:

1. **Login**: When visiting a protected domain for the first time, you are redirected to log in with your identity provider (e.g. Google or GitHub).
2. **Session Cookie**: After successful login, a secure session cookie is stored in your browser, and you are redirected to your original destination.
3. **Automatic Renewal**: Your session remains valid as long as you use it. Sessions renew automatically in the background without prompting you to log in repeatedly.
4. **Session Control**: If you log out or revoke a session from the UI, the session is removed from the central store, immediately revoking access.

---

## Quick Start

### Container Image

Container images are published to GitHub Container Registry:

```bash
docker pull ghcr.io/clambin/traefik-forward-auth:latest
```

Images support both `linux/amd64` and `linux/arm64`.

### Running with Docker

```bash
docker run -d \
  --name forward-auth \
  -p 8080:8080 \
  -p 8081:8081 \
  -v $(pwd)/config.yaml:/etc/forward-auth/config.yaml:ro \
  -e SERVER_KEY="your-random-secret-key-at-least-32-chars-long" \
  -e AUTHN_PROVIDER_OIDC_CLIENT_ID="your-oidc-client-id" \
  -e AUTHN_PROVIDER_OIDC_CLIENT_SECRET="your-oidc-client-secret" \
  ghcr.io/clambin/traefik-forward-auth:latest
```

---

## Configuration

Configuration is loaded from `/etc/forward-auth/config.yaml` by default. You can override the path using the `--config` flag:

```bash
forward-auth --config /path/to/config.yaml
```

### Example Configuration

```yaml
server:
  # Internal address for Traefik forwardAuth verification and health checks
  addrInt: :8080
  # External address for browser login callbacks, session UI, and API
  addrExt: :8081
  # Name of the HTTP session cookie
  cookieName: forward-auth-session
  # Root domain for which the cookie is valid (must cover all protected subdomains)
  domain: .example.com
  # Secret key used to sign session tokens (min 32 characters; can be set via SERVER_KEY)
  key: "your-random-secret-key-at-least-32-chars-long"

logger:
  level: info       # debug, info, warn, error
  format: text      # text or json

prometheus:
  addr: :9120
  path: /metrics

health:
  addr: :8888
  path: /healthz

authn:
  # How long a login attempt remains valid
  state_ttl: 10m
  # Prompt user to choose account at the provider
  select_account: true
  provider:
    type: "oidc"    # oidc or github
    # Where your provider redirects after login (must be publicly reachable)
    redirect_url: https://auth.example.com/api/auth/login
    oidc:
      issuer_url: https://accounts.google.com
      client_id: ""       # or set AUTHN_PROVIDER_OIDC_CLIENT_ID
      client_secret: ""   # or set AUTHN_PROVIDER_OIDC_CLIENT_SECRET
      scopes: [ openid, email, profile ]
    github:
      client_id: ""       # or set AUTHN_PROVIDER_GITHUB_CLIENT_ID
      client_secret: ""   # or set AUTHN_PROVIDER_GITHUB_CLIENT_SECRET
      scopes: [ "user:email", "read:user" ]

authz:
  # Requests are allowed if they match at least one rule.
  rules:
    - domain: "*.example.com"
      users:
        - user@example.com
    - domain: admin.example.com
      groups:
        - admins
  groups:
    - name: admins
      users:
        - admin@example.com

storage:
  type: local       # local (in-memory) or redis
  # redis:
  #   addr: redis:6379
  #   password: ""  # or set STORAGE_REDIS_PASSWORD
  #   db: 0

session:
  # Maximum session duration before requiring a fresh login
  session_ttl: 24h
```

### Environment Variables

Sensitive values can be set or overridden via environment variables:

| Environment Variable                  | Config Equivalent                     | Description                                          |
|---------------------------------------|---------------------------------------|------------------------------------------------------|
| `SERVER_KEY`                          | `server.key`                          | Secret key for signing session tokens (min 32 chars) |
| `AUTHN_PROVIDER_OIDC_CLIENT_ID`       | `authn.provider.oidc.client_id`       | OIDC Client ID                                       |
| `AUTHN_PROVIDER_OIDC_CLIENT_SECRET`   | `authn.provider.oidc.client_secret`   | OIDC Client Secret                                   |
| `AUTHN_PROVIDER_GITHUB_CLIENT_ID`     | `authn.provider.github.client_id`     | GitHub OAuth App Client ID                           |
| `AUTHN_PROVIDER_GITHUB_CLIENT_SECRET` | `authn.provider.github.client_secret` | GitHub OAuth App Client Secret                       |
| `STORAGE_REDIS_USERNAME`              | `storage.redis.username`              | Redis username                                       |
| `STORAGE_REDIS_PASSWORD`              | `storage.redis.password`              | Redis password                                       |

---

## Identity Provider Setup

`forward-auth` supports any standard **OIDC** provider (e.g. Google, Authentik, Keycloak, Codeberg) as well as **GitHub**.

When registering your OAuth application with your provider:
1. Set the **Redirect URI** to your `forward-auth` login URL:
   ```
   https://auth.example.com/api/auth/login
   ```
2. Copy the resulting Client ID and Client Secret into your `config.yaml` or environment variables.

For step-by-step setup guides for Google, GitHub, and Codeberg, see [PROVIDERS.md](PROVIDERS.md).

---

## Traefik Integration

Integrating with Traefik requires three straightforward steps:

### 1. Define the forwardAuth Middleware

Create a Traefik Middleware pointing to `forward-auth`'s internal verification endpoint. Example using a Kubernetes CRD:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: forward-auth
  namespace: default
spec:
  forwardAuth:
    # Internal address where forward-auth is reachable by Traefik
    address: http://forward-auth:8080/api/auth/forwardauth
    trustForwardHeader: true
    # Headers injected into downstream requests for the authenticated user
    authResponseHeaders:
      - X-Forwarded-User-Email
      - X-Forwarded-User-Name
      - X-Forwarded-User-Groups
    # Propagate renewed session cookies back to the browser
    addAuthCookiesToResponse:
      - forward-auth-session
```

### 2. Route the Auth Service

Expose `forward-auth`'s external port (`addrExt`, default `:8081`) under your auth domain (e.g., `auth.example.com`) without the `forwardAuth` middleware so users can reach the login callback and session management UI:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: forward-auth-route
spec:
  parentRefs:
    - name: traefik
  hostnames:
    - auth.example.com
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - name: forward-auth
          port: 8081
```

*(For Traefik `IngressRoute` or standard Kubernetes `Ingress`, create a route pointing `auth.example.com` to service port `8081` without the auth middleware attached).*

### 3. Protect Your Applications

Apply the `forward-auth` middleware to any ingress route or service you wish to protect:

```yaml
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: my-app
spec:
  entryPoints:
    - websecure
  routes:
    - match: Host(`app.example.com`)
      kind: Rule
      middlewares:
        - name: forward-auth
      services:
        - name: my-app-service
          port: 80
```

---

## Authorization Rules

You can restrict access to services using flexible matching rules under `authz`:

- **Domain matching**: Match exact hosts (`app.example.com`) or wildcards (`*.example.com`).
- **User matching**: Allow specific email addresses.
- **Group matching**: Group users together for clean role-based access.

### Examples

```yaml
authz:
  # Define reusable groups
  groups:
    - name: engineering
      users:
        - alice@example.com
        - bob@example.com
    - name: admins
      users:
        - charlie@example.com

  # Define access rules
  rules:
    # Only admins can access the admin portal
    - domain: admin.example.com
      groups:
        - admins

    # Any member of engineering or user@example.com can access internal tools
    - domain: "*.internal.example.com"
      groups:
        - engineering
      users:
        - user@example.com
```

If no rules are specified, all successfully authenticated users are permitted.

---

## Session Management & UI

`forward-auth` includes a lightweight, built-in session management dashboard available at the root of your auth domain (e.g. `https://auth.example.com/`).

### What You Can Do in the UI:

- 📋 **Active Sessions**: View all your currently active login sessions.
- 📱 **Device Details**: See client IP, browser user agent, login time, and last activity time.
- 🚪 **Remote Logout**: Revoke specific sessions (e.g. logging out a lost phone or remote workstation) with a single click.

```
https://auth.example.com/
```

### Storage Backends

- **`local`**: In-memory session store. Fast and requires zero configuration. Ideal for single-instance deployments.
- **`redis`**: Centralized session store. Recommended for multi-replica deployments to share sessions and allow instant revocation across instances.

---

## Metrics & Monitoring

`forward-auth` exposes Prometheus metrics on `/metrics` (`:9120` by default):

| Metric                          | Type    | Description                                       |
|---------------------------------|---------|---------------------------------------------------|
| `forward_auth_session_count`    | Gauge   | Current number of active sessions                 |
| `forward_auth_state_count`      | Gauge   | Current number of in-flight authentication states |
| `http_request_duration_seconds` | Summary | Request latency distribution in seconds           |
| `http_requests_total`           | Counter | Total HTTP requests handled                       |

A sample Grafana dashboard configuration is included in [assets/grafana/dashboards.yaml](assets/grafana/dashboards.yaml).

![screenshot.png](assets/images/screenshot.png)

---

## Troubleshooting

Having trouble setting up `forward-auth`? Check out the [Troubleshooting Guide](TROUBLESHOOTING.md) for solutions to common issues like redirect loops, cookie domain problems, and 401/403 errors.

---

## Author

Christophe Lambin

---

## License

[MIT License](LICENSE.md)
