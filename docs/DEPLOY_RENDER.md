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
- **`GET /`**: risposta breve (utile se apri l’URL base nel browser; non è una pagina HTML).
- **`GET /health`**: solo **liveness** (processo vivo), senza query al DB — consigliato come **Health Check Path** su Render.
- **`GET /health/ready`**: **readiness** con `SELECT 1` sul DB (per controlli manuali o monitoraggio).

### Piano free

- I servizi free possono andare in sleep dopo inattivita: il primo accesso puo richiedere ~1 minuto.

### Il servizio non risulta Live o il sito “non va”

1. **Web Service → Settings**: **Health Check Path** = `/health` (non lasciare vuoto se prima puntava a `/`, che senza route dedicata poteva dare 404).
2. **Deploy**: ultimo commit da GitHub (Dockerfile API con `${PORT:-8000}`).
3. **Environment** del Web Service: `DATABASE_URL` valorizzata (Internal URL del Postgres).
4. **Logs** del **Web Service** (non solo del database): cerca `Application startup complete` e assenza di traceback.
5. Apri nel browser: `https://<nome-servizio>.onrender.com/` e `.../docs` — se vedi JSON o Swagger, l’API è online.
6. Piano free: dopo lo sleep la prima richiesta può impiegare **fino a ~1 minuto** (schermata “Application loading” / spinner).

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

## Render fa ancora checkout di un commit vecchio (es. `99ba393`)

Nei log di build la riga `Checking out commit ...` deve coincidere con l’ultimo commit su GitHub (`main`). Se vedi sempre lo stesso hash vecchio:

1. **Settings** del Web Service → **Build & Deploy** → verifica **Repository** (`fabbietto75/club-business-IA`) e **Branch** (`main`).
2. **Manual Deploy** → scegli esplicitamente **Deploy latest commit** (non “Redeploy” su un deploy storico dalla lista **Events**).
3. Usa **Clear build cache & deploy** così non resta una cache legata al vecchio tree.
4. Se non cambia: **Disconnect** il repository e **ricollegalo**, poi di nuovo deploy da `main`.

## Build fallita: «uscita con stato 1» (email Render su club-business-IA-2 / API)

Significa che **il comando di build** (di solito `docker build`) non è terminato con successo: **l’ultimo codice non è in produzione** finché la build non va a buon fine.

1. Apri il servizio API su Render → **Logs** (o dal pulsante nell’email) e scorri **Build logs** (non solo Runtime): l’ultima riga utile di solito è l’errore `pip`, `COPY` o `Dockerfile not found`.
2. **Root Directory e Dockerfile** devono essere coerenti:
   - Se **Root Directory** = vuoto (root repo): **Dockerfile Path** = `services/python-api/Dockerfile` e **Docker Build Context** = `services/python-api` (come in `render.yaml`).
   - Se **Root Directory** = `services/python-api`: **Dockerfile Path** = `Dockerfile` (non ripetere `services/python-api/` nel path).
3. Il servizio API deve essere **Environment: Docker**, non una build “Native” con comando `pip` nella cartella sbagliata.
4. Da **Manual Deploy** prova **Clear build cache & deploy** (a volte la cache corrompe la build).

Il `Dockerfile` dell’API include dipendenze di sistema minime (`gcc`, `libpq-dev`) per ridurre i casi in cui `pip` deve compilare pacchetti senza wheel adatto.

## Errore: `Port scan timeout reached, no open ports detected`

L’app deve ascoltare sulla porta indicata dalla variabile d’ambiente **`PORT`** che Render imposta nel container. Il Dockerfile dell’API usa `${PORT:-8000}`. Se nei log di runtime vedi ancora `Uvicorn running on ... 8000` **senza** prima una riga `uvicorn binding port=...` con un numero diverso, stai eseguendo un’immagine costruita da un commit **prima** del fix della porta: aggiorna il deploy come sopra.
