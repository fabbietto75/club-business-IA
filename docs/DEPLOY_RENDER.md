# Deploy su Render

Questo progetto e compatibile con [Render](https://render.com) usando PostgreSQL (database gestito) e due Web Service Docker: API FastAPI e frontend Node.

**Porta:** Render imposta la variabile d’ambiente `PORT`. Il Dockerfile dell’API avvia Uvicorn su `${PORT:-8000}` (su Render la porta effettiva non e sempre 8000). Se l’API restasse fissata su 8000, i health check fallirebbero e vedresti riavvii o `CancelledError` nei log.

## Prerequisiti

- Account GitHub collegato a Render.
- Repository pushato su GitHub (vedi `docs/GITHUB.md`).

## Opzione A: Blueprint da `render.yaml`

1. Su Render: **New** → **Blueprint**.
2. Collega il repository e seleziona il branch.
3. Render legge `render.yaml` e crea database + servizi.

### Variabili da impostare a mano (primo deploy)

- **club-business-ia-api**
  - `ALLOWED_ORIGINS`: URL del frontend, separati da virgola, es.  
    `https://club-business-ia-web-xxxx.onrender.com`  
    (dopo il deploy del web, aggiorna con l’URL reale).
  - `ADMIN_EMAIL`, `ADMIN_PASSWORD`: credenziali seed admin (cambia in produzione).
  - Opzionale: `STRIPE_*`, `OPENAI_API_KEY`.

- **club-business-ia-web**
  - `PYTHON_API_URL`: URL pubblico dell’API, es.  
    `https://club-business-ia-api-xxxx.onrender.com`  
    (copia dall’URL del servizio API dopo il deploy).

Ordine consigliato: deploy prima l’**API**, poi imposta `PYTHON_API_URL` sul **web** e ridistribuisci il web.

### Database PostgreSQL (persistente)

Il blueprint crea un **PostgreSQL gestito** (`club-business-ia-db`): i dati restano sul disco gestito da Render tra deploy e riavvii del Web Service. Non è un database in-memory né un file locale nel container: è un servizio DB dedicato.

- Render collega l’API con `DATABASE_URL` (formato `postgres://...` o `postgresql://...`).
- L’API converte in `postgresql+psycopg2://` per SQLAlchemy e, se manca nella URL, aggiunge **`sslmode=require`** (compatibile con le connessioni SSL di Render). Per Postgres locale senza SSL puoi impostare `DATABASE_SSLMODE=disable`.
- All’avvio: `create_all` + aggiornamenti schema leggeri + seed (admin, prodotti demo, ecc.).
- **`GET /health`**: risponde `200` solo se l’app **e** il database rispondono (`SELECT 1`), così il health check di Render segnala problemi di connessione al DB.

### Piano free

- I servizi free possono andare in sleep dopo inattivita: il primo accesso puo richiedere ~1 minuto.

## Opzione B: Creazione manuale dei servizi

1. **PostgreSQL**: crea un database, copia **Internal/External Database URL**.
2. **Web Service (API)**: Docker, root context `services/python-api`, Dockerfile come da repo.  
   Variabili come nella sezione sopra, `DATABASE_URL` = URL Postgres fornito da Render.
3. **Web Service (frontend)**: Docker, context `services/js-frontend`.  
   `PYTHON_API_URL` = URL pubblico dell’API.

## CORS

L’API usa `ALLOWED_ORIGINS` (lista separata da virgole). Deve includere esattamente l’origine del frontend (schema + host + porta se presente).

## PHP e Docker locale

Il servizio `php-api` del `docker-compose` locale non e incluso nel blueprint Render; puoi aggiungere un terzo Web Service in seguito se serve.
