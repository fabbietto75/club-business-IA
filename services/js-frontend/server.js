const express = require("express");

const app = express();
const port = Number(process.env.PORT || 3000);
/** Base URL API Python (senza slash finale): stesso valore per proxy e link Swagger */
const apiPublicBase = String(
  process.env.PYTHON_API_URL || "http://localhost:8000"
).replace(/\/+$/, "");
const pythonApi = apiPublicBase;
/** Commit Render / variabile manuale: per capire se il browser mostra l’ultimo deploy */
const FRONTEND_BUILD = (
  process.env.RENDER_GIT_COMMIT ||
  process.env.BUILD_STAMP ||
  "dev"
).slice(0, 12);

app.use(express.json());

/** Swagger/OpenAPI sono serviti dall'API FastAPI, non da Express: reindirizza al backend */
app.get("/docs", (_req, res) => {
  res.redirect(302, `${pythonApi}/docs`);
});
app.get("/redoc", (_req, res) => {
  res.redirect(302, `${pythonApi}/redoc`);
});
app.get("/openapi.json", (_req, res) => {
  res.redirect(302, `${pythonApi}/openapi.json`);
});

function _proxyDetailFromError(err) {
  const msg = err && err.message ? String(err.message) : String(err);
  if (
    msg.includes("Unexpected token") ||
    msg.includes("<!DOCTYPE") ||
    msg.includes("is not valid JSON")
  ) {
    return (
      "Il backend non ha restituito JSON (di solito una pagina HTML). " +
      "Sul servizio WEB Render imposta PYTHON_API_URL con l'URL dell'API Python (FastAPI), " +
      "es. https://TUO-NOME-api.onrender.com — non l'URL del solo sito vetrina. " +
      "Verifica aprendo /api/health-check su questo sito dopo il deploy."
    );
  }
  return `Errore proxy: ${msg}`;
}

async function proxyApi(req, res, method, endpoint) {
  try {
    const headers = { "Content-Type": "application/json" };
    if (req.headers.authorization) {
      headers.Authorization = req.headers.authorization;
    }
    const url = `${pythonApi}${endpoint}`;
    const response = await fetch(url, {
      method,
      headers,
      body: method === "GET" || method === "DELETE" ? undefined : JSON.stringify(req.body || {}),
    });
    const raw = await response.text();
    let data;
    try {
      data = raw ? JSON.parse(raw) : {};
    } catch {
      const isHtml = raw.trimStart().startsWith("<");
      const detail = isHtml
        ? "Il backend ha restituito HTML invece di JSON. Su Render, sul servizio WEB, imposta PYTHON_API_URL con l'URL dell'API Python (es. https://nome-api.onrender.com), non l'URL della homepage del sito. Poi ridistribuisci il web."
        : `Risposta non valida dal backend: ${raw.slice(0, 200)}`;
      return res.status(502).json({ detail });
    }
    const st = Number(response.status);
    const code = st >= 100 && st <= 599 ? st : 502;
    res.status(code).json(data);
  } catch (error) {
    res.status(500).json({ detail: _proxyDetailFromError(error) });
  }
}

/** Verifica che PYTHON_API_URL punti all'API Python (GET /health deve rispondere JSON) */
app.get("/api/health-check", async (_req, res) => {
  try {
    const r = await fetch(`${pythonApi}/health`);
    const raw = await r.text();
    let backend;
    try {
      backend = raw ? JSON.parse(raw) : null;
    } catch {
      return res.status(200).json({
        ok: false,
        pythonApiBase: pythonApi,
        error: "Risposta non JSON (spesso HTML): PYTHON_API_URL errato o API spenta",
        preview: raw.slice(0, 200),
      });
    }
    return res.status(200).json({
      ok: r.ok,
      pythonApiBase: pythonApi,
      backend,
    });
  } catch (e) {
    return res.status(200).json({
      ok: false,
      pythonApiBase: pythonApi,
      error: String(e.message),
      hint: "Controlla PYTHON_API_URL e che l'API sia online",
    });
  }
});

app.post("/api/registration/request-otp", (req, res) =>
  proxyApi(req, res, "POST", "/auth/registration/request-otp")
);
app.post("/api/register", (req, res) => proxyApi(req, res, "POST", "/users"));
/** GET nel browser: la registrazione e solo POST; reindirizza al form sulla homepage */
app.get("/api/register", (_req, res) => {
  res.redirect(302, "/#registrazione");
});
app.post("/api/verify-registration-email", (req, res) =>
  proxyApi(req, res, "POST", "/auth/verify-registration-email")
);
app.post("/api/resend-registration-verification", (req, res) =>
  proxyApi(req, res, "POST", "/auth/resend-registration-verification")
);
app.post("/api/request-email-otp", (req, res) =>
  proxyApi(req, res, "POST", "/auth/request-email-otp")
);
app.post("/api/login", (req, res) => proxyApi(req, res, "POST", "/auth/login"));
app.post("/api/forgot-password", (req, res) =>
  proxyApi(req, res, "POST", "/auth/forgot-password")
);
app.get("/api/auth/me", (req, res) => proxyApi(req, res, "GET", "/auth/me"));
app.patch("/api/account/profile", (req, res) => proxyApi(req, res, "PATCH", "/account/profile"));
app.get("/api/wallet/me", (req, res) => proxyApi(req, res, "GET", "/wallet/me"));
app.get("/api/missions", (req, res) => proxyApi(req, res, "GET", "/missions"));
app.post("/api/missions/:missionId/complete", (req, res) =>
  proxyApi(req, res, "POST", `/missions/${req.params.missionId}/complete`)
);
app.get("/api/community/posts", (req, res) => proxyApi(req, res, "GET", "/community/posts"));
app.post("/api/community/posts", (req, res) => proxyApi(req, res, "POST", "/community/posts"));
app.get("/api/community/users", (req, res) => proxyApi(req, res, "GET", "/community/users"));
app.get("/api/account/workspaces", (req, res) => proxyApi(req, res, "GET", "/account/workspaces"));
app.post("/api/account/workspaces", (req, res) => proxyApi(req, res, "POST", "/account/workspaces"));
app.delete("/api/account/workspaces/:workspaceId", (req, res) =>
  proxyApi(req, res, "DELETE", `/account/workspaces/${req.params.workspaceId}`)
);
app.get("/api/account/my-products", (req, res) =>
  proxyApi(req, res, "GET", "/account/my-products")
);
app.post("/api/account/my-products", (req, res) =>
  proxyApi(req, res, "POST", "/account/my-products")
);
app.delete("/api/account/my-products/:productId", (req, res) =>
  proxyApi(req, res, "DELETE", `/account/my-products/${req.params.productId}`)
);
app.get("/api/account/my-courses", (req, res) =>
  proxyApi(req, res, "GET", "/account/my-courses")
);
app.post("/api/account/my-courses", (req, res) =>
  proxyApi(req, res, "POST", "/account/my-courses")
);
app.get("/api/account/workspaces/:workspaceId/notes", (req, res) =>
  proxyApi(req, res, "GET", `/account/workspaces/${req.params.workspaceId}/notes`)
);
app.post("/api/account/workspaces/:workspaceId/notes", (req, res) =>
  proxyApi(req, res, "POST", `/account/workspaces/${req.params.workspaceId}/notes`)
);
app.patch("/api/account/workspaces/:workspaceId/notes/:noteId", (req, res) =>
  proxyApi(
    req,
    res,
    "PATCH",
    `/account/workspaces/${req.params.workspaceId}/notes/${req.params.noteId}`
  )
);
app.delete("/api/account/workspaces/:workspaceId/notes/:noteId", (req, res) =>
  proxyApi(
    req,
    res,
    "DELETE",
    `/account/workspaces/${req.params.workspaceId}/notes/${req.params.noteId}`
  )
);
app.get("/api/account/calendar/reminders", (req, res) => {
  const q = new URLSearchParams(req.query).toString();
  const path = "/account/calendar/reminders" + (q ? "?" + q : "");
  proxyApi(req, res, "GET", path);
});
app.get("/api/vitrina/products", (req, res) => {
  const q = new URLSearchParams(req.query).toString();
  proxyApi(req, res, "GET", "/vitrina/products" + (q ? "?" + q : ""));
});
app.get("/api/notifications/me", (req, res) => {
  const q = new URLSearchParams(req.query).toString();
  proxyApi(req, res, "GET", "/notifications/me" + (q ? "?" + q : ""));
});
app.patch("/api/notifications/:notificationId/read", (req, res) =>
  proxyApi(req, res, "PATCH", `/notifications/${req.params.notificationId}/read`)
);
app.post("/api/notifications/read-all", (req, res) =>
  proxyApi(req, res, "POST", "/notifications/read-all")
);
app.get("/api/account/workspaces/:workspaceId/social-posts", (req, res) =>
  proxyApi(req, res, "GET", `/account/workspaces/${req.params.workspaceId}/social-posts`)
);
app.post("/api/account/workspaces/:workspaceId/social-posts", (req, res) =>
  proxyApi(req, res, "POST", `/account/workspaces/${req.params.workspaceId}/social-posts`)
);
app.delete("/api/account/workspaces/:workspaceId/social-posts/:postId", (req, res) =>
  proxyApi(
    req,
    res,
    "DELETE",
    `/account/workspaces/${req.params.workspaceId}/social-posts/${req.params.postId}`
  )
);

app.get("/backend", (_req, res) => {
  res.type("html").send(`
<!doctype html>
<html>
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <title>Dashboard Utente - Club Business IA</title>
  <meta name="theme-color" content="#0f172a" />
  <meta name="apple-mobile-web-app-capable" content="yes" />
  <style>
    :root{
      --bg:#020617;
      --panel:#0f172a;
      --panel2:#111827;
      --border:#334155;
      --text:#e5e7eb;
      --muted:#94a3b8;
      --ok:#22c55e;
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      font-family:Inter,Arial,sans-serif;
      background:
        radial-gradient(circle at 12% 0%, #1d4ed844 0%, transparent 30%),
        radial-gradient(circle at 88% 100%, #db277744 0%, transparent 35%),
        var(--bg);
      color:var(--text);
    }
    .wrap{max-width:1200px;margin:20px auto;padding:16px}
    .top{
      display:flex;justify-content:space-between;align-items:center;gap:12px;
      margin-bottom:14px;
    }
    .title{font-size:28px;font-weight:900}
    .btn{
      border:none;cursor:pointer;color:#fff;padding:10px 12px;border-radius:10px;font-weight:700;
      background:linear-gradient(135deg,#2563eb,#06b6d4);
    }
    .btn.secondary{background:linear-gradient(135deg,#6d28d9,#db2777)}
    .grid{
      display:grid;
      grid-template-columns:repeat(12,1fr);
      gap:12px;
    }
    .card{
      background:linear-gradient(150deg,var(--panel),var(--panel2));
      border:1px solid var(--border);
      border-radius:14px;
      padding:14px;
    }
    .kpi{grid-column:span 3}
    .wide{grid-column:span 6}
    .triple{grid-column:span 4}
    .full{grid-column:1/-1}
    h2{margin:0 0 10px 0;font-size:20px}
    h3{margin:0 0 8px 0;font-size:16px}
    .muted{color:var(--muted);font-size:13px}
    input,textarea,select{
      width:100%;padding:10px;border-radius:10px;border:1px solid #475569;background:#0b1220;color:#fff;
      margin:6px 0;
    }
    textarea{min-height:84px;resize:vertical}
    .list{display:grid;gap:8px;max-height:280px;overflow:auto;padding-right:4px}
    .item{
      border:1px solid #334155;border-radius:10px;padding:10px;background:#0b1220;
    }
    .avatar{
      width:46px;height:46px;border-radius:50%;object-fit:cover;border:1px solid #334155;background:#0b1220;
    }
    .avatar.big{
      width:72px;height:72px;
    }
    .row{display:flex;justify-content:space-between;align-items:center;gap:8px}
    .tag{font-size:11px;padding:4px 8px;border:1px solid #334155;border-radius:999px;color:#cbd5e1}
    .success{color:#86efac}
    .error{color:#fca5a5}
    .small-btn{padding:7px 10px;border-radius:8px;border:none;background:#1e293b;color:#fff;cursor:pointer;min-height:44px;touch-action:manipulation}
    .toast-host{position:fixed;bottom:max(12px,env(safe-area-inset-bottom));left:12px;right:12px;z-index:9999;display:flex;flex-direction:column;gap:8px;pointer-events:none;max-width:420px;margin:0 auto}
    .toast{background:#0f172a;border:1px solid #334155;color:#e5e7eb;padding:12px 14px;border-radius:12px;box-shadow:0 8px 28px rgba(0,0,0,.45);pointer-events:auto;font-size:14px;line-height:1.35}
    .notif-panel{position:fixed;right:12px;top:64px;width:min(380px,calc(100vw - 24px));max-height:min(72vh,520px);overflow:auto;background:#0f172a;border:1px solid #334155;border-radius:14px;padding:10px;z-index:9998;display:none;box-shadow:0 12px 40px rgba(0,0,0,.45);-webkit-overflow-scrolling:touch}
    .notif-panel.open{display:block}
    .notif-item{border-bottom:1px solid #1e293b;padding:10px 0;font-size:13px}
    .notif-item:last-child{border-bottom:none}
    .bell{position:relative;display:inline-block}
    .badge-notif{position:absolute;top:-8px;right:-6px;background:#ef4444;color:#fff;font-size:10px;font-weight:800;min-width:18px;height:18px;border-radius:999px;display:none;align-items:center;justify-content:center;padding:0 4px}
    .chat-avatar{width:36px;height:36px;border-radius:50%;object-fit:cover;border:1px solid #334155;flex-shrink:0}
    @media (max-width: 1020px){
      .kpi,.wide,.triple{grid-column:1/-1}
      .title{font-size:22px}
      .wrap{padding:12px;padding-bottom:max(24px,env(safe-area-inset-bottom))}
      .btn,.small-btn{width:100%;max-width:100%}
      .top .row{width:100%}
      .top .row .btn{flex:1;min-width:0}
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div class="title">Dashboard Club Business IA</div>
      <div class="row" style="flex-wrap:wrap;justify-content:flex-end">
        <a class="btn" style="display:inline-block;text-decoration:none;text-align:center" href="/vetrina">Vetrina</a>
        <div class="bell">
          <button type="button" class="btn secondary" onclick="toggleNotifPanel()">Notifiche <span id="notifBadge" class="badge-notif">0</span></button>
        </div>
        <button type="button" class="btn secondary" onclick="logout()">Logout</button>
      </div>
    </div>
    <div id="notifPanel" class="notif-panel"></div>
    <div id="toastHost" class="toast-host"></div>
    <div class="grid">
      <section class="card kpi">
        <h3>Utente</h3>
        <div class="row">
          <img id="meAvatar" class="avatar big" alt="avatar utente" />
          <div>
            <div id="meName">-</div>
            <div id="meTarget" class="muted">-</div>
          </div>
        </div>
        <div id="meEmail" class="muted">-</div>
      </section>
      <section class="card kpi">
        <h3>Ruolo</h3>
        <div id="meRole">-</div>
        <div class="muted">Gestione accessi protetti</div>
      </section>
      <section class="card kpi">
        <h3>Monete</h3>
        <div id="meCoins">0</div>
        <div class="muted">Wallet personale</div>
      </section>
      <section class="card kpi">
        <h3>API Backend</h3>
        <a class="btn" style="display:inline-block;text-decoration:none" href="${apiPublicBase}/docs" target="_blank" rel="noreferrer">Swagger</a>
      </section>

      <section class="card wide">
        <h2>Profilo utente</h2>
        <p class="muted">Nome, target, foto profilo privato o logo azienda (URL immagine).</p>
        <input id="profileName" placeholder="Nome completo o ragione sociale" />
        <select id="profileTarget">
          <option value="avvocati">Avvocati</option>
          <option value="pasticceri">Pasticceri</option>
          <option value="ristoratori">Ristoratori</option>
          <option value="gelatai">Gelatai</option>
          <option value="parrucchieri">Parrucchieri</option>
          <option value="medici">Medici</option>
          <option value="commercialisti">Commercialisti</option>
          <option value="ingegneri">Ingegneri</option>
          <option value="architetti">Architetti</option>
          <option value="geometri">Geometri</option>
          <option value="notai">Notai</option>
          <option value="ragionieri">Ragionieri</option>
          <option value="consulenti_fiscali">Consulenti fiscali</option>
          <option value="consulenti_lavoro">Consulenti del lavoro</option>
          <option value="agenti_immobiliari">Agenti immobiliari</option>
          <option value="farmacie">Farmacie</option>
          <option value="dentisti">Dentisti / odontoiatri</option>
          <option value="veterinari">Veterinari</option>
          <option value="psicologi">Psicologi</option>
          <option value="fotografi">Fotografi</option>
          <option value="videomaker">Videomaker</option>
          <option value="estetisti">Estetisti</option>
          <option value="personal_trainer">Personal trainer</option>
          <option value="alberghi">Hotel e alberghi</option>
          <option value="agriturismi">Agriturismi</option>
          <option value="imprese_edili">Imprese edili</option>
          <option value="elettricisti">Elettricisti</option>
          <option value="idraulici">Idraulici</option>
          <option value="meccanici">Meccanici</option>
          <option value="influencer">Creator / influencer</option>
          <option value="wedding_planner">Wedding planner</option>
          <option value="aziende">Aziende (generico)</option>
          <option value="privati">Privati</option>
        </select>
        <select id="profileMode">
          <option value="privato">Profilo: persona / privato</option>
          <option value="azienda">Profilo: azienda / brand</option>
        </select>
        <input id="profileAvatarUrl" placeholder="URL foto profilo privato (https://...)" />
        <input id="profileCompanyUrl" placeholder="URL logo o foto azienda (https://...)" />
        <button class="btn" onclick="saveProfile()">Salva profilo</button>
      </section>

      <section class="card wide">
        <h2>Spazio di lavoro</h2>
        <p class="muted">Crea e gestisci i tuoi workspace operativi.</p>
        <input id="wsName" placeholder="Nome workspace" />
        <input id="wsDesc" placeholder="Descrizione breve" />
        <button class="btn" onclick="createWorkspace()">Crea workspace</button>
        <div id="wsList" class="list" style="margin-top:10px"></div>
      </section>

      <section class="card full">
        <h2>Note, memo e promemoria (per workspace)</h2>
        <p class="muted">Scrivi note con data/ora; imposta un promemoria per il calendario personale.</p>
        <label class="muted">Workspace</label>
        <select id="wsNotesSelect" onchange="onWorkspaceChange()"></select>
        <input id="noteTitle" placeholder="Titolo (opzionale)" />
        <textarea id="noteContent" placeholder="Testo della nota / cosa da fare..."></textarea>
        <label class="muted">Data e ora della nota</label>
        <input id="noteAt" type="datetime-local" />
        <label class="muted">Promemoria (calendario)</label>
        <input id="noteReminder" type="datetime-local" />
        <div class="row">
          <button class="btn" onclick="createWorkspaceNote()">Salva nota</button>
          <button class="small-btn" onclick="loadWorkspaceNotes()">Aggiorna note</button>
        </div>
        <div id="noteList" class="list" style="margin-top:10px;max-height:320px"></div>
      </section>

      <section class="card full">
        <h2>Feed social nel workspace</h2>
        <p class="muted">Aggiornamenti tipo social nello stesso workspace selezionato sopra.</p>
        <textarea id="wsSocialContent" placeholder="Scrivi un post, aggiornamento o descrizione per il team..."></textarea>
        <div class="row">
          <button class="btn" onclick="createWorkspaceSocialPost()">Pubblica nel feed</button>
          <button class="small-btn" onclick="loadWorkspaceSocial()">Aggiorna feed</button>
        </div>
        <div id="wsSocialList" class="list" style="margin-top:10px;max-height:280px"></div>
      </section>

      <section class="card full">
        <h2>Calendario promemoria</h2>
        <p class="muted">Tutti i promemoria con data/ora dai tuoi workspace.</p>
        <div class="row">
          <button class="small-btn" onclick="loadCalendarReminders()">Carica promemoria</button>
        </div>
        <div id="calendarList" class="list" style="margin-top:10px;max-height:280px"></div>
      </section>

      <section class="card wide">
        <h2>I tuoi prodotti</h2>
        <p class="muted">Pubblica prodotti nel tuo spazio business.</p>
        <input id="prodTitle" placeholder="Titolo prodotto" />
        <input id="prodDesc" placeholder="Descrizione prodotto" />
        <input id="prodPrice" type="number" min="0" step="0.01" placeholder="Prezzo" />
        <select id="prodStatus">
          <option value="draft">Bozza</option>
          <option value="published">Pubblicato</option>
        </select>
        <button class="btn" onclick="createMyProduct()">Pubblica prodotto</button>
        <div id="prodList" class="list" style="margin-top:10px"></div>
      </section>

      <section class="card full">
        <h2>Chat community iscritti</h2>
        <p class="muted">Condividi aggiornamenti e parla con gli utenti del club.</p>
        <textarea id="postContent" placeholder="Scrivi un messaggio per la community..."></textarea>
        <div class="row">
          <button class="btn" onclick="createPost()">Invia messaggio</button>
          <button class="small-btn" onclick="loadPosts()">Aggiorna chat</button>
        </div>
        <div id="postList" class="list" style="margin-top:10px;max-height:360px"></div>
      </section>

      <section class="card full">
        <h2>Utenti registrati online</h2>
        <p class="muted">Elenco utenti del club visibili in community.</p>
        <div class="row" style="margin-bottom:8px">
          <button class="small-btn" onclick="loadCommunityUsers()">Aggiorna elenco utenti</button>
        </div>
        <div id="userList" class="list"></div>
      </section>

      <section class="card triple">
        <h2>Corsi</h2>
        <p class="muted">Crea corsi da vendere nel tuo spazio.</p>
        <input id="courseTitle" placeholder="Titolo corso" />
        <input id="courseDesc" placeholder="Descrizione corso" />
        <input id="coursePrice" type="number" min="0" step="0.01" placeholder="Prezzo" />
        <select id="courseStatus">
          <option value="draft">Bozza</option>
          <option value="published">Pubblicato</option>
        </select>
        <button class="btn" onclick="createCourse()">Crea corso</button>
      </section>
      <section class="card wide">
        <h2>I tuoi corsi</h2>
        <div id="courseList" class="list"></div>
      </section>

      <section class="card full">
        <h2>Missioni disponibili</h2>
        <div id="missionList" class="list"></div>
      </section>

      <section class="card full">
        <div id="statusBox" class="muted">Dashboard caricata.</div>
      </section>
    </div>
  </div>
  <script>
    const token = localStorage.getItem("club_access_token");
    if (!token) window.location.href = "/";

    let myUserId = null;
    const statusBox = document.getElementById("statusBox");
    const setStatus = (msg, isError=false) => {
      statusBox.className = isError ? "error" : "success";
      statusBox.textContent = msg;
    };
    const authHeaders = () => ({
      "Content-Type": "application/json",
      Authorization: "Bearer " + token
    });
    async function api(path, method="GET", payload=null) {
      const res = await fetch(path, {
        method,
        headers: authHeaders(),
        body: payload ? JSON.stringify(payload) : undefined
      });
      const text = await res.text();
      let data = {};
      if (text) {
        try {
          data = JSON.parse(text);
        } catch {
          throw new Error("Risposta non valida dal server (non JSON).");
        }
      }
      if (!res.ok) {
        const d = data?.detail;
        const detail =
          typeof d === "string"
            ? d
            : Array.isArray(d)
              ? d.map((x) => x?.msg || x?.detail || JSON.stringify(x)).join("; ")
              : JSON.stringify(data?.detail || data);
        throw new Error(detail || text.slice(0, 240) || "Errore API");
      }
      return data;
    }

    function escapeHtml(v){
      return String(v ?? "").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");
    }

    function isoToLocalInput(iso) {
      if (!iso) return "";
      const d = new Date(iso);
      if (isNaN(d.getTime())) return "";
      const pad = (n) => String(n).padStart(2, "0");
      return (
        d.getFullYear() +
        "-" +
        pad(d.getMonth() + 1) +
        "-" +
        pad(d.getDate()) +
        "T" +
        pad(d.getHours()) +
        ":" +
        pad(d.getMinutes())
      );
    }
    function localInputToIso(val) {
      if (!val) return null;
      const d = new Date(val);
      if (isNaN(d.getTime())) return null;
      return d.toISOString();
    }

    const toastHost = document.getElementById("toastHost");
    const notifPanel = document.getElementById("notifPanel");
    const notifBadge = document.getElementById("notifBadge");
    let prevOnlineIds = new Set();
    let onlineInitialized = false;
    let notifPanelOpen = false;

    function toast(msg) {
      const el = document.createElement("div");
      el.className = "toast";
      el.textContent = msg;
      toastHost.appendChild(el);
      setTimeout(() => el.remove(), 5200);
    }

    function toggleNotifPanel() {
      notifPanelOpen = !notifPanelOpen;
      notifPanel.classList.toggle("open", notifPanelOpen);
      if (notifPanelOpen) loadNotificationsPanel();
    }

    async function refreshNotifBadge() {
      try {
        const rows = await api("/api/notifications/me?unread_only=true");
        const n = rows.length;
        notifBadge.style.display = n ? "inline-flex" : "none";
        notifBadge.textContent = n > 99 ? "99+" : String(n);
      } catch (e) {
        notifBadge.style.display = "none";
      }
    }

    async function loadNotificationsPanel() {
      const rows = await api("/api/notifications/me");
      const head =
        '<div class="row" style="margin-bottom:10px"><button type="button" class="small-btn" onclick="markAllNotificationsRead()">Segna tutte lette</button></div>';
      notifPanel.innerHTML =
        head +
        (rows.length
          ? rows
              .map(
                (n) => \`
        <div class="notif-item" style="cursor:pointer" onclick="markOneNotificationRead(\${n.id})">
          <strong>\${escapeHtml(n.title)}</strong>
          <div class="muted" style="margin-top:4px">\${escapeHtml(n.body)}</div>
          <div class="muted" style="font-size:11px;margin-top:4px">\${new Date(n.created_at).toLocaleString("it-IT")}\${n.read_at ? " · letta" : ""}</div>
        </div>
      \`
              )
              .join("")
          : '<p class="muted">Nessuna notifica.</p>');
    }

    async function markOneNotificationRead(id) {
      await api("/api/notifications/" + id + "/read", "PATCH", {});
      await refreshNotifBadge();
      await loadNotificationsPanel();
    }

    async function markAllNotificationsRead() {
      await api("/api/notifications/read-all", "POST", {});
      await refreshNotifBadge();
      await loadNotificationsPanel();
    }

    async function pollOnlineUsers() {
      try {
        const rows = await api("/api/community/users");
        const onlineNow = new Set(rows.filter((u) => u.is_online).map((u) => u.id));
        if (onlineInitialized) {
          for (const u of rows) {
            if (u.is_online && !prevOnlineIds.has(u.id)) {
              toast(u.name + " e ora online");
            }
          }
        } else {
          onlineInitialized = true;
        }
        prevOnlineIds = onlineNow;
      } catch (e) {}
    }

    async function onWorkspaceChange() {
      await loadWorkspaceNotes();
      await loadWorkspaceSocial();
    }

    async function loadWorkspaceSocial() {
      const wsId = wsNotesSelect.value;
      if (!wsId) {
        wsSocialList.innerHTML = '<div class="muted">Seleziona un workspace.</div>';
        return;
      }
      const rows = await api("/api/account/workspaces/" + wsId + "/social-posts");
      wsSocialList.innerHTML = rows
        .map((p) => {
          const canDel = myUserId != null && p.owner_user_id === myUserId;
          return \`
        <div class="item">
          <div class="row">
            <strong>\${escapeHtml(p.author_name || "Utente")}</strong>
            <span class="muted">\${new Date(p.created_at).toLocaleString("it-IT")}</span>
          </div>
          <div style="margin-top:6px">\${escapeHtml(p.content)}</div>
          \${canDel ? \`<button class="small-btn" style="margin-top:8px" onclick="deleteWorkspaceSocialPost(\${p.id})">Elimina</button>\` : ""}
        </div>
      \`;
        })
        .join("") || '<div class="muted">Nessun post nel feed.</div>';
    }

    async function createWorkspaceSocialPost() {
      const wsId = wsNotesSelect.value;
      if (!wsId) {
        setStatus("Seleziona un workspace.", true);
        return;
      }
      await api("/api/account/workspaces/" + wsId + "/social-posts", "POST", {
        content: wsSocialContent.value
      });
      wsSocialContent.value = "";
      setStatus("Post pubblicato nel workspace.");
      await loadWorkspaceSocial();
    }

    async function deleteWorkspaceSocialPost(postId) {
      const wsId = wsNotesSelect.value;
      await api("/api/account/workspaces/" + wsId + "/social-posts/" + postId, "DELETE");
      setStatus("Post eliminato.");
      await loadWorkspaceSocial();
    }

    async function loadMe() {
      const me = await api("/api/auth/me");
      myUserId = me.id;
      const wallet = await api("/api/wallet/me");
      meName.textContent = me.name || "-";
      meEmail.textContent = me.email || "-";
      meTarget.textContent = me.target_segment || "-";
      meRole.textContent = me.role || "-";
      meCoins.textContent = String(wallet.coins ?? 0);
      const mode = me.profile_mode || "privato";
      const primary =
        mode === "azienda" && me.company_photo_url
          ? me.company_photo_url
          : me.avatar_url ||
            "https://ui-avatars.com/api/?background=111827&color=e5e7eb&name=" +
              encodeURIComponent(me.name || "User");
      meAvatar.src = primary;
      profileName.value = me.name || "";
      profileTarget.value = me.target_segment || "privati";
      profileMode.value = mode === "azienda" ? "azienda" : "privato";
      profileAvatarUrl.value = me.avatar_url || "";
      profileCompanyUrl.value = me.company_photo_url || "";
    }

    async function saveProfile() {
      await api("/api/account/profile", "PATCH", {
        name: profileName.value,
        target_segment: profileTarget.value,
        avatar_url: profileAvatarUrl.value || null,
        profile_mode: profileMode.value,
        company_photo_url: profileCompanyUrl.value || null
      });
      setStatus("Profilo aggiornato con successo.");
      await Promise.all([loadMe(), loadCommunityUsers()]);
    }

    async function loadWorkspaces() {
      const rows = await api("/api/account/workspaces");
      wsList.innerHTML = rows.map((x) => \`
        <div class="item">
          <div class="row">
            <strong>\${escapeHtml(x.name)}</strong>
            <button class="small-btn" onclick="deleteWorkspace(\${x.id})">Elimina</button>
          </div>
          <div class="muted">\${escapeHtml(x.description || "")}</div>
        </div>
      \`).join("") || '<div class="muted">Nessun workspace creato.</div>';
      wsNotesSelect.innerHTML = rows
        .map((x) => \`<option value="\${x.id}">\${escapeHtml(x.name)}</option>\`)
        .join("");
      if (rows.length) await onWorkspaceChange();
      else {
        noteList.innerHTML = '<div class="muted">Seleziona un workspace o creane uno.</div>';
        wsSocialList.innerHTML = '<div class="muted">Seleziona un workspace.</div>';
      }
    }

    async function createWorkspace() {
      await api("/api/account/workspaces", "POST", {
        name: wsName.value,
        description: wsDesc.value
      });
      wsName.value = "";
      wsDesc.value = "";
      setStatus("Workspace creato con successo.");
      await loadWorkspaces();
    }

    async function deleteWorkspace(id) {
      await api("/api/account/workspaces/" + id, "DELETE");
      setStatus("Workspace eliminato.");
      await loadWorkspaces();
    }

    async function loadWorkspaceNotes() {
      const wsId = wsNotesSelect.value;
      if (!wsId) {
        noteList.innerHTML = '<div class="muted">Seleziona un workspace o creane uno.</div>';
        return;
      }
      const rows = await api("/api/account/workspaces/" + wsId + "/notes");
      noteList.innerHTML = rows
        .map(
          (n) => \`
        <div class="item">
          <div class="row">
            <strong>\${escapeHtml(n.title || "Nota")}</strong>
            <span class="tag">\${n.is_done ? "Fatto" : "Da fare"}</span>
          </div>
          <div class="muted">Data nota: \${new Date(n.note_at).toLocaleString("it-IT")}</div>
          \${n.reminder_at ? '<div class="muted">Promemoria: ' + new Date(n.reminder_at).toLocaleString("it-IT") + "</div>" : ""}
          <div style="margin-top:6px">\${escapeHtml(n.content)}</div>
          <div class="row" style="margin-top:8px">
            <button class="small-btn" onclick="toggleNoteDone(\${n.id}, \${!n.is_done})">Segna \${n.is_done ? "da fare" : "fatto"}</button>
            <button class="small-btn" onclick="deleteWorkspaceNote(\${n.id})">Elimina</button>
          </div>
        </div>
      \`
        )
        .join("") || '<div class="muted">Nessuna nota in questo workspace.</div>';
    }

    async function createWorkspaceNote() {
      const wsId = wsNotesSelect.value;
      if (!wsId) {
        setStatus("Crea o seleziona un workspace.", true);
        return;
      }
      await api("/api/account/workspaces/" + wsId + "/notes", "POST", {
        title: noteTitle.value,
        content: noteContent.value,
        note_at: localInputToIso(noteAt.value),
        reminder_at: localInputToIso(noteReminder.value)
      });
      noteTitle.value = "";
      noteContent.value = "";
      noteAt.value = "";
      noteReminder.value = "";
      setStatus("Nota salvata.");
      await Promise.all([loadWorkspaceNotes(), loadCalendarReminders()]);
    }

    async function toggleNoteDone(noteId, nextDone) {
      const wsId = wsNotesSelect.value;
      await api("/api/account/workspaces/" + wsId + "/notes/" + noteId, "PATCH", {
        is_done: Boolean(nextDone)
      });
      setStatus("Nota aggiornata.");
      await loadWorkspaceNotes();
    }

    async function deleteWorkspaceNote(noteId) {
      const wsId = wsNotesSelect.value;
      await api("/api/account/workspaces/" + wsId + "/notes/" + noteId, "DELETE");
      setStatus("Nota eliminata.");
      await Promise.all([loadWorkspaceNotes(), loadCalendarReminders()]);
    }

    async function loadCalendarReminders() {
      const rows = await api("/api/account/calendar/reminders");
      calendarList.innerHTML = rows
        .map(
          (r) => \`
        <div class="item">
          <div class="row">
            <strong>\${escapeHtml(r.workspace_name || "Workspace")}</strong>
            <span class="tag">\${r.is_done ? "Fatto" : "Da fare"}</span>
          </div>
          <div class="muted">\${escapeHtml(r.title || "Promemoria")}</div>
          <div class="muted">\${r.reminder_at ? new Date(r.reminder_at).toLocaleString("it-IT") : ""}</div>
          <div style="margin-top:6px">\${escapeHtml(r.content || "")}</div>
        </div>
      \`
        )
        .join("") || '<div class="muted">Nessun promemoria impostato.</div>';
    }

    async function loadProducts() {
      const rows = await api("/api/account/my-products");
      prodList.innerHTML = rows.map((x) => \`
        <div class="item">
          <div class="row">
            <strong>\${escapeHtml(x.title)}</strong>
            <span class="tag">\${escapeHtml(x.status)}</span>
          </div>
          <div class="muted">\${escapeHtml(x.description || "")}</div>
          <div class="row" style="margin-top:8px">
            <span>EUR \${Number(x.price || 0).toFixed(2)}</span>
            <button class="small-btn" onclick="deleteMyProduct(\${x.id})">Elimina</button>
          </div>
        </div>
      \`).join("") || '<div class="muted">Nessun prodotto creato.</div>';
    }

    async function createMyProduct() {
      await api("/api/account/my-products", "POST", {
        title: prodTitle.value,
        description: prodDesc.value,
        price: Number(prodPrice.value || 0),
        status: prodStatus.value
      });
      prodTitle.value = "";
      prodDesc.value = "";
      prodPrice.value = "";
      setStatus("Prodotto creato con successo.");
      await loadProducts();
    }

    async function deleteMyProduct(id) {
      await api("/api/account/my-products/" + id, "DELETE");
      setStatus("Prodotto eliminato.");
      await loadProducts();
    }

    async function loadPosts() {
      const rows = await api("/api/community/posts");
      postList.innerHTML = rows
        .map((x) => {
          const pm = x.author_profile_mode || "privato";
          const av =
            pm === "azienda" && x.author_company_photo_url
              ? x.author_company_photo_url
              : x.author_avatar_url ||
                "https://ui-avatars.com/api/?background=1e293b&color=f1f5f9&name=" +
                  encodeURIComponent(x.author_name || "U");
          return \`
        <div class="item">
          <div class="row" style="align-items:flex-start;gap:10px">
            <img class="chat-avatar" src="\${escapeHtml(av)}" alt="" />
            <div style="flex:1;min-width:0">
              <div class="row">
                <strong>\${escapeHtml(x.author_name || "Utente")}</strong>
                <span class="muted">\${new Date(x.created_at).toLocaleString("it-IT")}</span>
              </div>
              <div style="margin-top:6px;word-break:break-word">\${escapeHtml(x.content)}</div>
            </div>
          </div>
        </div>
      \`;
        })
        .join("") || '<div class="muted">Nessun messaggio ancora.</div>';
    }

    async function createPost() {
      await api("/api/community/posts", "POST", { content: postContent.value });
      postContent.value = "";
      setStatus("Messaggio inviato in community.");
      await loadPosts();
      await refreshNotifBadge();
    }

    async function loadCommunityUsers() {
      const rows = await api("/api/community/users");
      userList.innerHTML = rows
        .map((u) => {
          const pm = u.profile_mode || "privato";
          const fallback =
            "https://ui-avatars.com/api/?background=0f172a&color=e2e8f0&name=" +
            encodeURIComponent(u.name || "U");
          const photo =
            pm === "azienda" && u.company_photo_url
              ? u.company_photo_url
              : u.avatar_url || fallback;
          return \`
        <div class="item row">
          <div class="row">
            <img class="avatar" src="\${escapeHtml(photo)}" alt="avatar utente" />
            <div>
              <div><strong>\${escapeHtml(u.name)}</strong></div>
              <div class="muted">\${escapeHtml(u.target_segment || "-")} · \${pm === "azienda" ? "Azienda" : "Privato"}</div>
            </div>
          </div>
          <span class="tag">\${u.is_online ? "Online" : "Offline"}</span>
        </div>
      \`;
        })
        .join("") || '<div class="muted">Nessun utente visibile.</div>';
    }

    async function loadCourses() {
      const data = await api("/api/account/my-courses");
      const rows = data.created || [];
      courseList.innerHTML = rows.map((c) => \`
        <div class="item">
          <div class="row">
            <strong>\${escapeHtml(c.title)}</strong>
            <span class="tag">\${escapeHtml(c.status)}</span>
          </div>
          <div class="muted">\${escapeHtml(c.description || "")}</div>
          <div style="margin-top:6px">EUR \${Number(c.price || 0).toFixed(2)}</div>
        </div>
      \`).join("") || '<div class="muted">Nessun corso creato.</div>';
    }

    async function createCourse() {
      await api("/api/account/my-courses", "POST", {
        title: courseTitle.value,
        description: courseDesc.value,
        price: Number(coursePrice.value || 0),
        status: courseStatus.value
      });
      courseTitle.value = "";
      courseDesc.value = "";
      coursePrice.value = "";
      setStatus("Corso creato con successo.");
      await loadCourses();
    }

    async function loadMissions() {
      const rows = await api("/api/missions");
      missionList.innerHTML = rows.map((m) => \`
        <div class="item row">
          <div>
            <strong>\${escapeHtml(m.title)}</strong>
            <div class="muted">\${escapeHtml(m.description || "")}</div>
            <div class="muted">Reward: +\${m.reward_coins} coins</div>
          </div>
          <button class="small-btn" onclick="completeMission(\${m.id})">Completa</button>
        </div>
      \`).join("") || '<div class="muted">Nessuna missione disponibile.</div>';
    }

    async function completeMission(id){
      await api("/api/missions/" + id + "/complete", "POST", {});
      setStatus("Missione completata, coins aggiornate.");
      await Promise.all([loadMe(), loadMissions()]);
    }

    function logout() {
      localStorage.removeItem("club_access_token");
      localStorage.removeItem("club_refresh_token");
      window.location.href = "/";
    }

    async function initDashboard() {
      try {
        await loadMe();
        await Promise.all([
          loadWorkspaces(),
          loadProducts(),
          loadPosts(),
          loadMissions(),
          loadCommunityUsers(),
          loadCourses(),
          loadCalendarReminders(),
          refreshNotifBadge()
        ]);
        setStatus("Area backend pronta.");
        setInterval(refreshNotifBadge, 25000);
        setInterval(pollOnlineUsers, 32000);
        pollOnlineUsers();
      } catch (e) {
        setStatus(e.message || "Errore caricamento dashboard", true);
      }
    }
    initDashboard();
   </script>
</body>
</html>`);
});

app.get("/", (_req, res) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  res.set("Pragma", "no-cache");
  res.type("html").send(`
<!doctype html>
<html lang="it" data-build="${FRONTEND_BUILD}">
<head>
  <meta charset="UTF-8" />
  <meta name="app-build" content="${FRONTEND_BUILD}" />
  <title>Club Business IA</title>
  <meta name="theme-color" content="#1f2850" />
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <style>
    :root{
      --bg1:#1f2850;
      --bg2:#6a1b9a;
      --bg3:#ec4899;
      --card:#111827cc;
      --border:#ffffff30;
      --text:#f3f4f6;
      --muted:#d1d5db;
      --cta:#ff7a1a;
      --cta2:#f97316;
      --ok:#22c55e;
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      font-family: Inter, Arial, sans-serif;
      color:var(--text);
      background:
        radial-gradient(circle at 10% 0%, #60a5fa55 0%, transparent 30%),
        radial-gradient(circle at 90% 100%, #22d3ee44 0%, transparent 35%),
        linear-gradient(135deg,var(--bg1) 0%, var(--bg2) 52%, var(--bg3) 100%);
      min-height:100vh;
    }
    .container{max-width:1180px;margin:0 auto;padding:20px}
    .topbar{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:12px;
      margin-bottom:14px;
    }
    .brand{
      font-weight:900;
      letter-spacing:.4px;
      font-size:20px;
    }
    .chip{
      font-size:12px;
      border:1px solid var(--border);
      background:#0f172ab5;
      border-radius:999px;
      padding:6px 10px;
      color:#dbeafe;
    }
    .hero{
      border:1px solid var(--border);
      border-radius:18px;
      padding:30px;
      background:linear-gradient(110deg,#0f172acc,#1f2937aa);
      box-shadow:0 14px 40px rgba(0,0,0,.28);
      margin-bottom:16px;
      position:relative;
      overflow:hidden;
      animation:fadeUp .7s ease-out both;
    }
    .hero::after{
      content:"";
      position:absolute;
      inset:auto -120px -120px auto;
      width:260px;
      height:260px;
      background:radial-gradient(circle,#22d3ee66 0%, transparent 65%);
      pointer-events:none;
    }
    .hero h1{font-size:44px;margin:0 0 10px 0}
    .hero p{font-size:20px;color:var(--muted);margin:0 0 14px 0;max-width:760px}
    .hero .cta{
      display:inline-block;
      background:linear-gradient(135deg,var(--cta),var(--cta2));
      color:#fff;
      text-decoration:none;
      font-weight:800;
      padding:12px 18px;
      border-radius:12px;
    }
    .features{
      display:grid;
      grid-template-columns:repeat(3,1fr);
      gap:14px;
      margin-bottom:16px;
    }
    .feature{
      border:1px solid var(--border);
      border-radius:14px;
      padding:14px;
      background:#0f172ab5;
      transition:transform .2s ease, box-shadow .2s ease;
      animation:fadeUp .7s ease both;
    }
    .feature:hover{
      transform:translateY(-2px);
      box-shadow:0 10px 24px rgba(0,0,0,.2);
    }
    .feature h3{margin:0 0 8px 0}
    .feature p{margin:0;color:var(--muted)}
    .showcase{
      display:grid;
      grid-template-columns:repeat(3,1fr);
      gap:14px;
      margin:0 0 16px 0;
    }
    .show-item{
      border:1px solid var(--border);
      border-radius:14px;
      padding:14px;
      background:linear-gradient(145deg,#111827d0,#1f2937a8);
      animation:fadeUp .8s ease both;
    }
    .show-item h4{margin:0 0 8px 0}
    .show-item p{margin:0;color:var(--muted);font-size:14px}
    .show-item .price{
      margin-top:10px;
      font-weight:800;
      color:#86efac;
    }
    .auth-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
    .card{
      border:1px solid var(--border);
      border-radius:14px;
      padding:16px;
      background:var(--card);
      backdrop-filter: blur(4px);
      animation:fadeUp .75s ease both;
    }
    input,select,button{
      width:100%;
      padding:11px 12px;
      margin:6px 0;
      border-radius:10px;
      border:1px solid #ffffff30;
      background:#ffffff10;
      color:#fff;
      font-size:14px;
    }
    option{color:#111}
    button{
      font-weight:800;
      border:none;
      background:linear-gradient(135deg,#2563eb,#06b6d4);
      cursor:pointer;
    }
    .secondary{background:linear-gradient(135deg,#6d28d9,#db2777)}
    .hidden{display:none}
    .output{
      margin-top:14px;
      border:1px solid var(--border);
      border-radius:12px;
      padding:10px;
      background:#020617cc;
      color:#86efac;
      min-height:70px;
      white-space:pre-wrap;
      font-size:13px;
    }
    .small{font-size:12px;color:var(--muted)}
    .quick-links{
      margin-top:12px;
      display:grid;
      gap:8px;
    }
    .quick-links a{
      text-align:center;
      text-decoration:none;
      color:#fff;
      font-weight:700;
      padding:10px 12px;
      border-radius:10px;
      background:linear-gradient(135deg,#334155,#0f172a);
      border:1px solid #475569;
    }
    .contact{
      margin-top:16px;
      border:1px solid var(--border);
      border-radius:14px;
      padding:16px;
      background:#0f172ab5;
    }
    .contact h3{margin:0 0 10px 0}
    .contact-grid{
      display:grid;
      grid-template-columns:1fr 1fr;
      gap:10px;
    }
    .contact .full{grid-column:1 / -1}
    .hook{
      margin-top:14px;
      border:1px solid var(--border);
      border-radius:14px;
      padding:16px;
      background:linear-gradient(135deg,#0f172acc,#312e81cc,#6d28d9b8);
      box-shadow:0 12px 28px rgba(0,0,0,.24);
    }
    .hook strong{
      display:block;
      margin-bottom:8px;
      font-size:22px;
      line-height:1.25;
    }
    .hook p{
      margin:0;
      color:#dbeafe;
      line-height:1.5;
      font-size:15px;
    }
    .footer{
      margin-top:16px;
      border:1px solid var(--border);
      border-radius:14px;
      padding:14px;
      background:#020617c7;
      display:flex;
      flex-wrap:wrap;
      align-items:center;
      justify-content:space-between;
      gap:10px;
    }
    .badges{
      display:flex;
      gap:8px;
      flex-wrap:wrap;
    }
    .badge{
      border:1px solid #334155;
      border-radius:999px;
      padding:6px 10px;
      font-size:12px;
      color:#cbd5e1;
      background:#0f172a;
    }
    @keyframes fadeUp{
      from{opacity:0;transform:translateY(8px)}
      to{opacity:1;transform:translateY(0)}
    }
    @media (max-width: 980px){
      .features{grid-template-columns:1fr}
      .showcase{grid-template-columns:1fr}
      .auth-grid{grid-template-columns:1fr}
      .contact-grid{grid-template-columns:1fr}
      .hero h1{font-size:32px}
      .hero p{font-size:18px}
      .container{padding:14px;padding-bottom:max(24px,env(safe-area-inset-bottom))}
      button,.cta{min-height:46px;touch-action:manipulation}
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="topbar">
      <div class="brand">Club Business IA</div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;justify-content:flex-end">
        <a class="chip" href="/vetrina" style="text-decoration:none;color:#dbeafe">Vetrina prodotti</a>
        <div class="chip">Piattaforma business per target professionali</div>
      </div>
    </div>

    <section class="hero">
      <h1>Club Business IA</h1>
      <p>Il contenitore professionale per vendere online prodotti e corsi, con strategia business, sicurezza e crescita nel tempo.</p>
      <p style="display:flex;flex-wrap:wrap;gap:10px;align-items:center">
        <a class="cta" href="#registrazione">Inizia ora</a>
        <a class="cta" href="/vetrina" style="background:linear-gradient(135deg,#334155,#0f172a)">Apri vetrina</a>
      </p>
    </section>

    <section class="features">
      <article class="feature">
        <h3>Veloce</h3>
        <p>Piattaforma orientata alla conversione con accesso immediato al tuo spazio business.</p>
      </article>
      <article class="feature">
        <h3>Sicura</h3>
        <p>Dopo la registrazione ricevi un codice via email per verificare l'account.</p>
      </article>
      <article class="feature">
        <h3>Personalizzabile</h3>
        <p>Ogni utente target lavora su obiettivi specifici: vendita, corsi, visibilita e crescita.</p>
      </article>
    </section>

    <section class="showcase">
      <article class="show-item">
        <h4>Vetrina Commerciale Target</h4>
        <p>Ogni profilo professionale ha offerte ottimizzate per conversione e fiducia cliente.</p>
        <div class="price">Setup rapido</div>
      </article>
      <article class="show-item">
        <h4>Programmi e Corsi</h4>
        <p>Spazio dedicato a prodotti digitali, formazione, upsell e abbonamenti.</p>
        <div class="price">Modello scalabile</div>
      </article>
      <article class="show-item">
        <h4>Sistema Reward Coins</h4>
        <p>Monete virtuali per attivare retention, cross-target e incremento valore medio ordine.</p>
        <div class="price">Fidelizzazione smart</div>
      </article>
    </section>

    <section class="auth-grid">
      <div id="registrazione" class="card">
        <h2>Registrazione Utenti</h2>
        <input id="regName" placeholder="Nome completo" />
        <input id="regEmail" placeholder="Email" />
        <input id="regPassword" type="password" placeholder="Password" />
        <select id="regTarget">
          <option value="avvocati">Avvocati</option>
          <option value="pasticceri">Pasticceri</option>
          <option value="ristoratori">Ristoratori</option>
          <option value="gelatai">Gelatai</option>
          <option value="parrucchieri">Parrucchieri</option>
          <option value="medici">Medici</option>
          <option value="commercialisti">Commercialisti</option>
          <option value="ingegneri">Ingegneri</option>
          <option value="architetti">Architetti</option>
          <option value="geometri">Geometri</option>
          <option value="notai">Notai</option>
          <option value="ragionieri">Ragionieri</option>
          <option value="consulenti_fiscali">Consulenti fiscali</option>
          <option value="consulenti_lavoro">Consulenti del lavoro</option>
          <option value="agenti_immobiliari">Agenti immobiliari</option>
          <option value="farmacie">Farmacie</option>
          <option value="dentisti">Dentisti / odontoiatri</option>
          <option value="veterinari">Veterinari</option>
          <option value="psicologi">Psicologi</option>
          <option value="fotografi">Fotografi</option>
          <option value="videomaker">Videomaker</option>
          <option value="estetisti">Estetisti</option>
          <option value="personal_trainer">Personal trainer</option>
          <option value="alberghi">Hotel e alberghi</option>
          <option value="agriturismi">Agriturismi</option>
          <option value="imprese_edili">Imprese edili</option>
          <option value="elettricisti">Elettricisti</option>
          <option value="idraulici">Idraulici</option>
          <option value="meccanici">Meccanici</option>
          <option value="influencer">Creator / influencer</option>
          <option value="wedding_planner">Wedding planner</option>
          <option value="aziende">Aziende (generico)</option>
          <option value="privati">Privati</option>
        </select>
        <button onclick="registerUser()">Crea account</button>
        <button class="secondary" onclick="showLoginCard()">Hai gia un account? Vai al login</button>
        <button
          type="button"
          class="secondary"
          style="margin-top:8px;background:transparent;border:1px solid #64748b;color:#e2e8f0;font-weight:700"
          onclick="showVerifyCard()"
        >
          Ho un codice di verifica email
        </button>
        <p class="small">Nessun codice qui: dopo la registrazione ricevi il codice via email e lo inserisci nella sezione che si apre sotto.</p>
      </div>

      <div id="verifyCard" class="card hidden">
        <h2>Verifica email (dopo registrazione)</h2>
        <input id="verifyEmail" placeholder="Email usata in registrazione" />
        <input id="verifyCode" placeholder="Codice a 6 cifre dall'email" />
        <button onclick="verifyRegistrationEmail()">Conferma codice</button>
        <button
          type="button"
          class="secondary"
          style="margin-top:8px;background:transparent;border:1px solid #64748b;color:#e2e8f0;font-weight:700"
          onclick="resendRegistrationVerification()"
        >
          Non arriva l'email? Reinvia codice
        </button>
        <p class="small">Inserisci il codice ricevuto dopo la registrazione per sbloccare il login. Controlla anche spam. Se il login dice di verificare l'email, apri questa sezione con il pulsante sotto al login.</p>
      </div>

      <div id="loginCard" class="card hidden">
        <h2>Login Utenti</h2>
        <input id="logEmail" placeholder="Email" />
        <input id="logPassword" type="password" placeholder="Password" />
        <input id="logTotp" placeholder="Codice Google Authenticator (se attivo)" />
        <input id="logEmailOtp" placeholder="Codice OTP Email (se richiesto)" />
        <button onclick="loginUser()">Accedi</button>
        <button
          type="button"
          class="secondary"
          style="margin-top:8px;background:transparent;border:1px solid #64748b;color:#e2e8f0;font-weight:700"
          onclick="forgotPassword()"
        >
          Password dimenticata
        </button>
        <button
          type="button"
          class="secondary"
          style="margin-top:8px;background:transparent;border:1px solid #64748b;color:#e2e8f0;font-weight:700"
          onclick="openVerifyFromLogin()"
        >
          Devo verificare l'email (codice)
        </button>
        <p class="small">Dopo il login il backend gestisce tutte le funzioni avanzate.</p>
      </div>
    </section>

    <section class="contact">
      <h3>Contattaci</h3>
      <div class="contact-grid">
        <input placeholder="Nome e cognome" />
        <input placeholder="Email professionale" />
        <input class="full" placeholder="Azienda / Categoria target" />
        <input class="full" placeholder="Messaggio (es: voglio attivare il mio spazio business)" />
        <button class="full">Invia richiesta</button>
      </div>
      <p class="small">Form dimostrativo design: il backend contatti verra collegato nel prossimo step.</p>
    </section>

    <section class="hook">
      <strong>Trasforma oggi il tuo business in una macchina di crescita.</strong>
      <p>Club Business IA unisce strategia, vendite e automazione in un solo ecosistema: acquisisci clienti migliori, aumenta conversioni e fidelizza nel tempo con un'esperienza professionale che fa la differenza.</p>
    </section>

    <div id="out" class="output">Benvenuto in Club Business IA.</div>

    <footer class="footer">
      <div><strong>Club Business IA</strong> · design professionale orientato alla conversione</div>
      <p class="small muted" style="margin:8px 0 0 0;opacity:0.75">Versione interfaccia: ${FRONTEND_BUILD}</p>
      <div class="badges">
        <span class="badge">SSL Ready</span>
        <span class="badge">Verifica email</span>
        <span class="badge">Role Based Access</span>
        <span class="badge">Scalabile</span>
      </div>
    </footer>
  </div>

  <script>
    const setOut = (x) => {
      const out = document.getElementById("out");
      out.textContent = typeof x === "string" ? x : JSON.stringify(x, null, 2);
    };
    function formatApiDetail(detail) {
      if (detail == null) return "";
      if (typeof detail === "string") return detail;
      if (Array.isArray(detail)) {
        return detail
          .map((item) => {
            if (!item) return "";
            if (typeof item === "string") return item;
            if (item.msg) return String(item.msg);
            if (item.detail) return String(item.detail);
            return JSON.stringify(item);
          })
          .filter(Boolean)
          .join("; ");
      }
      if (typeof detail === "object") {
        return detail.detail != null ? String(detail.detail) : JSON.stringify(detail);
      }
      return String(detail);
    }
    async function api(path, payload) {
      const res = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload || {}),
      });
      const text = await res.text();
      let data = {};
      if (text) {
        try {
          data = JSON.parse(text);
        } catch {
          throw new Error(
            "Risposta non valida dal server (non JSON). Controlla connessione e riprova."
          );
        }
      }
      if (!res.ok) {
        const msg =
          formatApiDetail(data.detail) ||
          (data.message ? String(data.message) : "") ||
          text.slice(0, 240) ||
          "Errore HTTP " + res.status;
        throw new Error(msg);
      }
      return data;
    }
    (function initLoginEmail() {
      try {
        const last = localStorage.getItem("club_last_email");
        const el = document.getElementById("logEmail");
        if (last && el && !el.value) el.value = last;
      } catch (_) {}
    })();
    function showLoginCard() {
      const loginCard = document.getElementById("loginCard");
      loginCard.classList.remove("hidden");
      loginCard.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    function showVerifyCard() {
      const verifyCard = document.getElementById("verifyCard");
      verifyCard.classList.remove("hidden");
      verifyCard.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    function openVerifyFromLogin() {
      const e = (document.getElementById("logEmail").value || "").trim();
      if (e) {
        const ve = document.getElementById("verifyEmail");
        if (ve) ve.value = e;
      }
      showVerifyCard();
    }

    async function resendRegistrationVerification() {
      try {
        const email = (document.getElementById("verifyEmail").value || "").trim();
        if (!email) {
          setOut("Inserisci l'email nel campo sopra, poi clicca Reinvia codice.");
          return;
        }
        const data = await api("/api/resend-registration-verification", { email });
        const payload = {
          message: data.message || "",
          dev_registration_code: data.dev_registration_code || null
        };
        setOut(payload);
      } catch (e) {
        setOut(e.message);
      }
    }

    async function registerUser() {
      try {
        const data = await api("/api/register", {
          name: regName.value,
          email: regEmail.value,
          password: regPassword.value,
          target_segment: regTarget.value
        });
        const email = (regEmail.value || "").trim().toLowerCase();
        const payload = {
          message: data.message || "",
          user: data.user || null,
          dev_registration_code: data.dev_registration_code || null
        };
        setOut(payload);
        if (email) {
          localStorage.setItem("club_last_email", email);
          const le = document.getElementById("logEmail");
          if (le) le.value = email;
          const ve = document.getElementById("verifyEmail");
          if (ve) ve.value = email;
        }
        const vc = document.getElementById("verifyCode");
        if (vc) vc.value = "";
        showVerifyCard();
      } catch (e) { setOut(e.message); }
    }
    async function verifyRegistrationEmail() {
      try {
        const email = (document.getElementById("verifyEmail").value || "").trim();
        const code = (document.getElementById("verifyCode").value || "").trim();
        if (!email || !code) {
          setOut("Inserisci email e codice a 6 cifre.");
          return;
        }
        const data = await api("/api/verify-registration-email", { email, code });
        setOut(data);
        document.getElementById("verifyCard")?.classList.add("hidden");
        showLoginCard();
      } catch (e) {
        setOut(e.message);
      }
    }
    async function loginUser() {
      try {
        const data = await api("/api/login", {
          email: logEmail.value,
          password: logPassword.value,
          totp_code: logTotp.value || null,
          email_otp_code: logEmailOtp.value || null
        });
        localStorage.setItem("club_access_token", data.access_token || "");
        localStorage.setItem("club_refresh_token", data.refresh_token || "");
        setOut({ status: "login_ok", message: "Accesso effettuato con successo." });
        setTimeout(() => { window.location.href = "/backend"; }, 600);
      } catch (e) { setOut(e.message); }
    }
    async function forgotPassword() {
      try {
        const email = (document.getElementById("logEmail").value || "").trim();
        if (!email) {
          setOut("Inserisci la tua email nel campo sopra, poi clicca Password dimenticata.");
          return;
        }
        const data = await api("/api/forgot-password", { email });
        setOut(data);
      } catch (e) {
        setOut(e.message);
      }
    }
  </script>
</body>
</html>`);
});

app.get("/vetrina", (_req, res) => {
  res.type("html").send(`
<!doctype html>
<html lang="it">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <meta name="theme-color" content="#0f172a" />
  <title>Vetrina prodotti - Club Business IA</title>
  <style>
    *{box-sizing:border-box}
    body{margin:0;font-family:Inter,system-ui,sans-serif;background:#020617;color:#e5e7eb;min-height:100vh;padding:16px;padding-bottom:max(24px,env(safe-area-inset-bottom))}
    .bar{max-width:1100px;margin:0 auto 20px;display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:12px}
    h1{margin:0;font-size:clamp(22px,4vw,30px)}
    .btn{display:inline-block;padding:10px 16px;border-radius:10px;text-decoration:none;font-weight:700;background:linear-gradient(135deg,#2563eb,#06b6d4);color:#fff}
    .grid{max-width:1100px;margin:0 auto;display:grid;gap:14px;grid-template-columns:repeat(auto-fill,minmax(260px,1fr))}
    .card{border:1px solid #334155;border-radius:14px;padding:14px;background:linear-gradient(160deg,#0f172a,#111827)}
    .price{color:#86efac;font-weight:800;font-size:18px}
    .seller{font-size:13px;color:#94a3b8;margin-top:8px}
    .muted{color:#64748b;font-size:13px}
    .empty{text-align:center;padding:40px;color:#94a3b8}
  </style>
</head>
<body>
  <div class="bar">
    <h1>Vetrina Club Business IA</h1>
    <div>
      <a class="btn" href="/">Home / Accedi</a>
    </div>
  </div>
  <div id="grid" class="grid"></div>
  <p id="empty" class="empty" style="display:none">Nessun prodotto pubblicato ancora. I membri possono pubblicare dalla dashboard.</p>
  <script>
    function esc(t){return String(t??"").replace(/&/g,"&amp;").replace(/</g,"&lt;") }
    async function load() {
      const res = await fetch("/api/vitrina/products");
      const data = await res.json();
      const grid = document.getElementById("grid");
      const empty = document.getElementById("empty");
      if (!res.ok || !Array.isArray(data) || data.length === 0) {
        empty.style.display = "block";
        return;
      }
      empty.style.display = "none";
      grid.innerHTML = data.map((p) => {
        const s = p.seller || {};
        const pm = s.profile_mode || "privato";
        const photo = pm === "azienda" && s.company_photo_url ? s.company_photo_url : s.avatar_url;
        const imgHtml = photo
          ? '<img src="' + esc(photo) + '" alt="" width="40" height="40" style="border-radius:50%;object-fit:cover;vertical-align:middle;margin-right:8px;border:1px solid #334155"/>'
          : "";
        const desc = (p.description || "").slice(0, 220);
        const dots = (p.description || "").length > 220 ? "…" : "";
        return (
          '<article class="card">' +
          '<div style="font-weight:800;font-size:17px">' + esc(p.title) + "</div>" +
          '<div class="price">EUR ' + Number(p.price || 0).toFixed(2) + "</div>" +
          '<p class="muted" style="margin:8px 0 0;line-height:1.4">' + esc(desc) + dots + "</p>" +
          '<div class="seller">' + imgHtml + "<strong>" + esc(s.name || "Venditore") + "</strong> · " + esc(s.target_segment || "-") + "</div>" +
          "</article>"
        );
      }).join("");
    }
    load();
  </script>
</body>
</html>`);
});

app.listen(port, () => {
  console.log(`Frontend attivo su http://localhost:${port}`);
});
