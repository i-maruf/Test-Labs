# SSO Test 1 — sign-up and sign-in

Dockerized web app with OpenID Connect. By default it uses a **lab identity provider** in Compose (no Azure account required). You can point it at real **Microsoft Entra ID** instead.

## Run

```bash
docker compose up --build
```

Open [http://localhost:8080](http://localhost:8080).

1. **Create account** — register with email and password on the identity provider.
2. **Sign in** — use the same credentials again. The app stores a local profile in Postgres.

Client ID/secret are already set in `.env` for the Docker identity provider.

## Real Microsoft Entra ID (optional)

1. Register an app in [Entra admin center](https://entra.microsoft.com).
2. Redirect URI (Web): `http://localhost:8080/auth/callback`.
3. Create a client secret.
4. In `.env`:

```bash
OIDC_PROVIDER=microsoft
MICROSOFT_CLIENT_ID=<entra-application-id>
MICROSOFT_CLIENT_SECRET=<entra-client-secret>
MICROSOFT_TENANT_ID=common
```

5. `docker compose up -d --build`

## Services

| Service | Role |
| --- | --- |
| `nginx` | HTTP on host port **8080** |
| `app` | Flask relying party |
| `idp` | OpenID Connect identity provider (signup/signin) |
| `db` | Postgres 16 |

Health check: `GET /health`.
