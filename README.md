# CLUB BUSINESS IA - Monorepo Starter

Piattaforma modulare con:

- `services/python-api`: API principale (FastAPI + SQLAlchemy)
- `services/js-frontend`: frontend web (Express + pagine demo)
- `services/php-api`: modulo PHP (endpoint legacy/integrabile)
- `infra/docker-compose.yml`: orchestrazione MySQL e servizi

## Obiettivo MVP

- Registrazione utenti
- Login JWT + ruoli
- Wallet monete virtuali (loyalty points)
- Missioni, community e ordini base

## Avvio rapido

1. Installa Docker Desktop
2. Dal root progetto esegui:

```bash
docker compose -f infra/docker-compose.yml up --build
```

3. Servizi disponibili:

- Frontend: `http://localhost:3000`
- Python API: `http://localhost:8000/docs`
- PHP API: `http://localhost:8080`
- MySQL: `localhost:3306`

Dashboard operativa disponibile su `http://localhost:3000` con:

- registrazione/login/logout
- wallet e missioni
- community post
- prodotti, ordini e checkout Stripe

## Deploy su Render e GitHub

- **GitHub**: vedi [docs/GITHUB.md](docs/GITHUB.md) (init, remote, push).
- **Render**: blueprint [render.yaml](render.yaml) e istruzioni in [docs/DEPLOY_RENDER.md](docs/DEPLOY_RENDER.md) (PostgreSQL, CORS, variabili).

## Note importanti

- Le monete sono punti loyalty, non moneta legale.
- Per produzione: aggiungere JWT, ruoli, validazioni complete, antifrode, audit log.

## Endpoint API principali

- `POST /users` registrazione (bonus iniziale monete)
- `POST /auth/registration/request-otp` OTP per registrazione sicura utenti
- `POST /ai/chat` chatbot IA assistenza utenti
- `POST /auth/login` autenticazione e token
- `POST /auth/request-email-otp` genera OTP email per 3FA
- `POST /auth/refresh` rinnovo token
- `POST /auth/logout` logout e revoca token
- `POST /auth/mfa/setup` setup Google Authenticator
- `POST /auth/mfa/enable` attiva MFA
- `POST /auth/mfa/disable` disattiva MFA
- `GET /wallet/me` saldo + storico movimenti
- `GET /missions` elenco missioni attive
- `POST /missions/{id}/complete` completa missione e accredita reward
- `GET /community/posts` elenco post community
- `POST /community/posts` pubblica post
- `GET /products` catalogo prodotti
- `POST /orders` crea ordine (spendi monete + accumula reward)

## Vero E-commerce (carrello)

- `GET /ecommerce/products` vetrina con titolo/descrizione/showcase/categoria/prezzo/stock
- `POST /ecommerce/cart/items` aggiungi al carrello
- `PATCH /ecommerce/cart/items/{item_id}` aggiorna quantita carrello
- `DELETE /ecommerce/cart/items/{item_id}` rimuovi item carrello
- `GET /ecommerce/cart` visualizza carrello e totale
- `POST /ecommerce/cart/checkout` checkout carrello (Stripe o fallback locale)

## Account completo utenti

- `GET /account/my-products`
- `POST /account/my-products`
- `PATCH /account/my-products/{id}`
- `DELETE /account/my-products/{id}`
- `GET /account/my-courses`
- `POST /account/my-courses`
- `GET /courses/marketplace`
- `POST /courses/{id}/enroll`
- `GET /account/workspaces`
- `POST /account/workspaces`
- `DELETE /account/workspaces/{id}`

## Business Pyramid Program

- `POST /business/join` attiva account business con sponsor opzionale
- `GET /business/me` livello, punti e referral diretti
- `GET /business/pyramid` struttura team (linea diretta e seconda linea)
- `POST /business/ads` crea campagna pubblicitaria business
- `GET /business/ads` elenco campagne business utente

Livelli business applicati:
- `starter_seller` (Starter Seller)
- `smart_vendor` (Smart Vendor)
- `growth_manager` (Growth Manager)
- `business_manager` (Business Manager)
- `area_director` (Area Director)
- `executive_partner` (Executive Partner)

## Capienza massima utenti

- Tabella reale: `site_seats`
- Capienza iniziale automatica: `SITE_CAPACITY=200`
- Assegnazione posto automatica in registrazione
- Se posti esauriti, registrazione bloccata con errore
- Endpoint:
  - `GET /site/capacity`
  - `GET /admin/site/capacity`

## Scambio monete tra target

- `POST /target/offers` pubblica offerta in monete (es. gelataio 1 gelato = 1 moneta)
- `GET /target/offers` elenco offerte attive multi-target
- `POST /target/offers/{id}/redeem` riscatto offerta usando monete
- `GET /target/redemptions/me` storico riscatti utente

## Endpoint admin

- `GET /admin/api-controls`
- `PATCH /admin/api-controls/{feature_key}`
- `POST /admin/products`
- `POST /admin/ecommerce/products`
- `PATCH /admin/ecommerce/products/{id}`
- `DELETE /admin/ecommerce/products/{id}`
- `PATCH /admin/missions/{id}`
- `DELETE /admin/missions/{id}`

Nota permessi:
- ruolo `admin`: gestisce moduli/API on-off, missioni, ordini, prodotti.
- accesso utenti (`/admin/users*`) riservato a ruolo `owner`.

## Pagamenti Stripe

- `POST /payments/checkout-session`
- `POST /payments/webhook/stripe`

Variabili ambiente utili nel servizio `python-api`:

- `JWT_SECRET`
- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`
- `WEBHOOK_AUTH_TOKEN` (fallback webhook locale senza firma Stripe)
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`
- `ADMIN_NAME`
- `ALLOWED_TARGETS` (solo target ammessi al club)
- `REQUIRE_APPROVAL` (se true, serve approvazione admin account)
- `THREE_FACTOR_REQUIRED` (se true: password + Google Auth + OTP email)
- `EMAIL_OTP_DEV_EXPOSE` (solo sviluppo: mostra OTP in risposta API)
- `REQUIRE_REGISTRATION_OTP` (se true, registrazione consentita solo con OTP)
- `OPENAI_API_KEY` (chiave provider IA)
- `OPENAI_MODEL` (modello chat, default `gpt-4o-mini`)

## Utente admin seed automatico

Alla prima partenza viene creato un admin automatico:

- email: `admin@clubbusinessia.local`
- password: `Admin123!`

Modifica questi valori da variabili ambiente in produzione.

## Accesso per target + sicurezza 2FA/3FA

- Registrazione consentita solo ai target in `ALLOWED_TARGETS`.
- Registrazione protetta da OTP (`/auth/registration/request-otp`) se `REQUIRE_REGISTRATION_OTP=true`.
- Se `REQUIRE_APPROVAL=true`, ogni nuovo account deve essere approvato da admin:
  - endpoint: `PATCH /admin/users/{id}/approval`
- 2FA Google:
  1. login normale
  2. `POST /auth/mfa/setup`
  3. scansiona `otpauth_uri` con Google Authenticator
  4. `POST /auth/mfa/enable` con `totp_code`
- 3FA (opzionale): abilita `THREE_FACTOR_REQUIRED=true`
  - prima del login: `POST /auth/request-email-otp`
  - poi login con `totp_code` + `email_otp_code`

## Script test rapido API

Esegui:

```bash
./scripts/test_api.sh
```

Puoi personalizzare:

```bash
BASE_URL=http://localhost:8000 EMAIL=test@mail.local PASSWORD=Pass123! ./scripts/test_api.sh
```
