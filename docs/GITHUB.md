# Pubblicare il progetto su GitHub

## 1. Crea il repository su GitHub

Su [github.com](https://github.com) crea un nuovo repository (vuoto, senza README se gia hai i file locali).

Copia l’URL che GitHub ti mostra, ad esempio:

- HTTPS: `https://github.com/TUO_UTENTE/club-business-ia.git`
- SSH: `git@github.com:TUO_UTENTE/club-business-ia.git`

## 2. Inizializza Git nella cartella del progetto (solo la prima volta)

Dal terminale, nella root del progetto (dove c’e `README.md`):

```bash
cd "/Users/fabiocavalieri/Desktop/CLUB BUSINESS IA"
git init
git add .
git commit -m "Initial commit: Club Business IA monorepo"
```

## 3. Collega il remote e fai push

Sostituisci `URL_DEL_TUO_REPO` con l’indirizzo copiato da GitHub:

```bash
git branch -M main
git remote add origin URL_DEL_TUO_REPO
git push -u origin main
```

Se il repository esiste gia e vuoi solo aggiornare:

```bash
git add .
git commit -m "Descrizione delle modifiche"
git push
```

## 4. Collegare Render a GitHub

Su Render: **New** → **Blueprint** (o **Web Service**) → **Connect GitHub** → seleziona il repository e il branch `main`.

---

**Nota:** non committare mai file `.env` con password o chiavi segrete; usa variabili su Render o GitHub Secrets.
