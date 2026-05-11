/* ════════════════════════════════════════
   GHOST IN THE CODE — script.js
   5 niveles · Encuentra la vulnerabilidad
   ════════════════════════════════════════ */

/* ── NIVELES ── */
const LEVELS = [
  /* ─ NIVEL 1: SQL Injection ─ */
  {
    title: "SQL INJECTION",
    objective: "Este código construye una consulta SQL con datos del usuario. Encuentra la línea que permite inyección.",
    hint: "¿Dónde se concatena input del usuario directamente en la query?",
    timeLimit: 70,
    vulnerableLine: 5,
    explanation: "La línea 5 concatena directamente `req.body.username` sin sanitizar en el SQL. Un atacante puede escribir `' OR '1'='1` y bypassear el login.",
    fix: "Usar prepared statements: `db.query('SELECT * FROM users WHERE name = ?', [username])`",
    code: [
      { t: "cmt",  c: "// auth.js — Sistema de autenticación" },
      { t: "kw",   c: "const express = require('express');" },
      { t: "kw",   c: "const db      = require('./database');" },
      { t: "fn",   c: "app.post('/login', async (req, res) => {" },
      { t: "var",  c: "  const username = req.body.username;" },
      { t: "vuln", c: "  const query = 'SELECT * FROM users WHERE name = \\'' + username + '\\'';" },
      { t: "fn",   c: "  const result = await db.query(query);" },
      { t: "kw",   c: "  if (result.length > 0) {" },
      { t: "fn",   c: "    req.session.user = result[0];" },
      { t: "fn",   c: "    res.redirect('/dashboard');" },
      { t: "kw",   c: "  } else {" },
      { t: "fn",   c: "    res.status(401).send('Acceso denegado');" },
      { t: "op",   c: "  }" },
      { t: "op",   c: "});" },
    ],
  },

  /* ─ NIVEL 2: XSS ─ */
  {
    title: "CROSS-SITE SCRIPTING",
    objective: "Esta función renderiza comentarios de usuarios en el HTML. Encuentra dónde se inyecta código sin sanitizar.",
    hint: "Busca donde se inserta texto del usuario directamente en el DOM.",
    timeLimit: 60,
    vulnerableLine: 7,
    explanation: "La línea 7 usa `innerHTML` con datos del usuario. Un atacante puede publicar `<script>document.cookie</script>` y robar sesiones.",
    fix: "Usar `textContent` en lugar de `innerHTML`, o sanitizar con DOMPurify.",
    code: [
      { t: "cmt",  c: "// comments.js — Renderizado de comentarios" },
      { t: "kw",   c: "function renderComments(comments) {" },
      { t: "var",  c: "  const container = document.getElementById('comments');" },
      { t: "fn",   c: "  comments.forEach(comment => {" },
      { t: "var",  c: "    const div = document.createElement('div');" },
      { t: "fn",   c: "    div.className = 'comment-card';" },
      { t: "vuln", c: "    div.innerHTML = comment.text;  // render directo" },
      { t: "fn",   c: "    container.appendChild(div);" },
      { t: "op",   c: "  });" },
      { t: "op",   c: "}" },
      { t: "cmt",  c: "" },
      { t: "cmt",  c: "// llamada al cargar la página" },
      { t: "fn",   c: "fetch('/api/comments')" },
      { t: "fn",   c: "  .then(r => r.json())" },
      { t: "fn",   c: "  .then(data => renderComments(data));" },
    ],
  },

  /* ─ NIVEL 3: Contraseña hardcoded ─ */
  {
    title: "HARDCODED SECRETS",
    objective: "Este script de deploy tiene credenciales escritas directamente en el código. Encuéntralas.",
    hint: "Las credenciales NUNCA deben estar en el código fuente. Busca strings sospechosos.",
    timeLimit: 55,
    vulnerableLine: 5,
    explanation: "La línea 5 tiene la contraseña de la base de datos escrita en texto plano. Si el repo es público, cualquiera puede acceder al servidor.",
    fix: "Usar variables de entorno: `process.env.DB_PASSWORD` y un archivo `.env` en el `.gitignore`.",
    code: [
      { t: "cmt",  c: "// deploy.js — Script de configuración" },
      { t: "kw",   c: "const mysql = require('mysql2');" },
      { t: "cmt",  c: "" },
      { t: "var",  c: "const DB_HOST = 'prod.db.empresa.com';" },
      { t: "vuln", c: "const DB_PASS = 'Admin1234!';  // contraseña prod" },
      { t: "var",  c: "const DB_USER = 'root';" },
      { t: "cmt",  c: "" },
      { t: "kw",   c: "const conn = mysql.createConnection({" },
      { t: "var",  c: "  host:     DB_HOST," },
      { t: "var",  c: "  user:     DB_USER," },
      { t: "var",  c: "  password: DB_PASS," },
      { t: "var",  c: "  database: 'produccion'" },
      { t: "op",   c: "});" },
      { t: "fn",   c: "conn.connect();" },
    ],
  },

  /* ─ NIVEL 4: Path Traversal ─ */
  {
    title: "PATH TRAVERSAL",
    objective: "Este endpoint sirve archivos al usuario. Encuentra la línea que permite acceder a archivos del sistema.",
    hint: "¿Qué pasa si el usuario envía `../../etc/passwd` como nombre de archivo?",
    timeLimit: 50,
    vulnerableLine: 6,
    explanation: "La línea 6 construye el path del archivo con input sin validar. Un atacante puede escribir `../../etc/passwd` y leer archivos del servidor.",
    fix: "Usar `path.resolve()` y verificar que el resultado empiece con el directorio base permitido.",
    code: [
      { t: "cmt",  c: "// files.js — Servidor de archivos estáticos" },
      { t: "kw",   c: "const path = require('path');" },
      { t: "kw",   c: "const fs   = require('fs');" },
      { t: "cmt",  c: "" },
      { t: "var",  c: "const BASE_DIR = '/var/www/uploads/';" },
      { t: "vuln", c: "  const filePath = BASE_DIR + req.query.file;" },
      { t: "cmt",  c: "" },
      { t: "fn",   c: "app.get('/download', (req, res) => {" },
      { t: "kw",   c: "  if (fs.existsSync(filePath)) {" },
      { t: "fn",   c: "    res.sendFile(filePath);" },
      { t: "kw",   c: "  } else {" },
      { t: "fn",   c: "    res.status(404).send('Not found');" },
      { t: "op",   c: "  }" },
      { t: "op",   c: "});" },
    ],
  },

  /* ─ NIVEL 5: Insecure Random ─ */
  {
    title: "INSECURE RANDOMNESS",
    objective: "Este sistema genera tokens de recuperación de contraseña. Encuentra por qué el token es predecible.",
    hint: "¿Es `Math.random()` suficientemente seguro para tokens de seguridad?",
    timeLimit: 45,
    vulnerableLine: 5,
    explanation: "La línea 5 usa `Math.random()` que NO es criptográficamente seguro. Un atacante puede predecir el token de reset y tomar control de cualquier cuenta.",
    fix: "Usar `crypto.randomBytes(32).toString('hex')` para tokens seguros.",
    code: [
      { t: "cmt",  c: "// reset.js — Recuperación de contraseña" },
      { t: "kw",   c: "const nodemailer = require('nodemailer');" },
      { t: "cmt",  c: "" },
      { t: "fn",   c: "async function sendResetLink(email) {" },
      { t: "vuln", c: "  const token = Math.random().toString(36).substr(2);" },
      { t: "fn",   c: "  await db.set(`reset:${token}`, email, 3600);" },
      { t: "cmt",  c: "" },
      { t: "var",  c: "  const link = `https://app.com/reset?token=${token}`;" },
      { t: "fn",   c: "  await mailer.sendMail({" },
      { t: "str",  c: "    to:      email," },
      { t: "str",  c: "    subject: 'Resetea tu contraseña'," },
      { t: "str",  c: "    text:    `Tu link: ${link}`" },
      { t: "op",   c: "  });" },
      { t: "op",   c: "}" },
    ],
  },
];

/* ── ESTADO DEL JUEGO ── */
let state = {
  level:     0,
  lives:     3,
  score:     0,
  timer:     null,
  timeLeft:  0,
  answered:  false,
  startTime: null,
  levelTimes: [],
};

/* ── ELEMENTOS DOM ── */
const $ = id => document.getElementById(id);
const screens = {
  intro: $("screen-intro"),
  game:  $("screen-game"),
  win:   $("screen-win"),
  lose:  $("screen-lose"),
};

/* ── MATRIX BACKGROUND ── */
function initMatrix() {
  const container = $("bg-matrix");
  const chars = "01アイウエオカキクケコサシスセソタチツテトナニヌネノ!@#$%^&*<>/\\";
  const cols = Math.floor(window.innerWidth / 16);

  for (let i = 0; i < cols; i++) {
    const col = document.createElement("div");
    col.className = "matrix-col";
    col.style.left = (i * 16) + "px";
    col.style.animationDuration = (6 + Math.random() * 14) + "s";
    col.style.animationDelay    = (-Math.random() * 15) + "s";
    let txt = "";
    for (let j = 0; j < 40; j++) {
      txt += chars[Math.floor(Math.random() * chars.length)] + "\n";
    }
    col.textContent = txt;
    container.appendChild(col);
  }
}

/* ── MOSTRAR PANTALLA ── */
function showScreen(name) {
  Object.values(screens).forEach(s => s.classList.add("hidden"));
  screens[name].classList.remove("hidden");
}

/* ── SYNTAX HIGHLIGHT ── */
function renderCode(lines) {
  const block = $("code-block");
  block.innerHTML = "";

  const colorMap = {
    kw:   "#c792ea",
    str:  "#c3e88d",
    fn:   "#82aaff",
    num:  "#ffb700",
    cmt:  "#546e7a",
    var:  "#f78c6c",
    op:   "#89ddff",
    vuln: "#f0e0f5",
  };

  lines.forEach((line, idx) => {
    const el = document.createElement("div");
    el.className = "code-line";
    el.dataset.index = idx;
    el.setAttribute("role", "listitem");

    const num = document.createElement("span");
    num.className = "line-num";
    num.textContent = String(idx + 1).padStart(2, "0");

    const code = document.createElement("span");
    code.className = "line-code";
    code.style.color = colorMap[line.t] || "#f0e0f5";
    code.textContent = line.c || " ";

    el.appendChild(num);
    el.appendChild(code);

    el.addEventListener("click", () => handleLineClick(idx));
    block.appendChild(el);
  });
}

/* ── TIMER ── */
function startTimer(seconds) {
  clearInterval(state.timer);
  state.timeLeft = seconds;
  updateTimerDisplay();

  state.timer = setInterval(() => {
    state.timeLeft--;
    updateTimerDisplay();

    if (state.timeLeft <= 10) {
      $("hud-timer").classList.add("danger");
    }

    if (state.timeLeft <= 0) {
      clearInterval(state.timer);
      if (!state.answered) timeOut();
    }
  }, 1000);
}

function updateTimerDisplay() {
  $("hud-timer").textContent = state.timeLeft;
}

function stopTimer() {
  clearInterval(state.timer);
}

/* ── CARGAR NIVEL ── */
function loadLevel(idx) {
  const lvl = LEVELS[idx];
  state.answered = false;
  state.startTime = Date.now();

  // HUD
  $("hud-level").textContent   = `0${idx + 1} / 05`;
  $("hud-mission").textContent = lvl.title;
  $("hud-timer").classList.remove("danger");

  // Track dots
  document.querySelectorAll(".level-dot").forEach((dot, i) => {
    dot.classList.remove("active", "done");
    if (i < idx)  dot.classList.add("done");
    if (i === idx) dot.classList.add("active");
  });

  // Panel info
  $("brief-text").textContent = lvl.objective;
  $("brief-hint").textContent = lvl.hint;
  $("feedback").textContent   = "";
  $("feedback").className     = "feedback";
  $("panel-hint").textContent = "Haz clic en la línea vulnerable";

  // Vidas
  updateLives();

  // Código
  renderCode(lvl.code);

  // Timer
  startTimer(lvl.timeLimit);
}

/* ── CLICK EN LÍNEA ── */
function handleLineClick(lineIdx) {
  if (state.answered) return;

  const lvl = LEVELS[state.level];
  const lines = document.querySelectorAll(".code-line");
  const clicked = lines[lineIdx];

  if (lineIdx === lvl.vulnerableLine) {
    // ✅ CORRECTO
    state.answered = true;
    stopTimer();

    const elapsed   = Math.round((Date.now() - state.startTime) / 1000);
    const timeBonus = Math.max(0, state.timeLeft) * 10;
    const points    = 100 + timeBonus;
    state.score    += points;
    state.levelTimes.push(elapsed);

    clicked.classList.add("correct");
    $("score-val").textContent = state.score;

    setFeedback("ok",
      `✓ ¡VULNERABILIDAD ENCONTRADA! +${points} pts\n\n` +
      `⚠ ${lvl.explanation}\n\n` +
      `🔧 Fix: ${lvl.fix}`
    );

    $("panel-hint").textContent = "✓ Correcto";

    setTimeout(() => nextLevel(), 3500);

  } else {
    // ❌ INCORRECTO
    clicked.classList.add("wrong");
    setTimeout(() => clicked.classList.remove("wrong"), 400);

    state.lives--;
    updateLives();

    if (state.lives <= 0) {
      stopTimer();
      // Revelar la línea correcta
      lines[lvl.vulnerableLine].classList.add("revealed");
      setFeedback("fail",
        `✗ Sin vidas. La línea era la ${lvl.vulnerableLine + 1}.\n` +
        lvl.explanation
      );
      setTimeout(() => endGame(false), 2500);
    } else {
      setFeedback("fail",
        `✗ Esa línea no es la vulnerable. Te quedan ${state.lives} intento${state.lives === 1 ? "" : "s"}.`
      );
    }
  }
}

/* ── TIME OUT ── */
function timeOut() {
  if (state.answered) return;
  state.answered = true;

  const lvl   = LEVELS[state.level];
  const lines = document.querySelectorAll(".code-line");
  lines[lvl.vulnerableLine].classList.add("revealed");

  state.lives--;
  updateLives();

  setFeedback("info",
    `⏱ ¡Tiempo agotado! Era la línea ${lvl.vulnerableLine + 1}.\n` +
    lvl.explanation
  );

  if (state.lives <= 0) {
    setTimeout(() => endGame(false), 2500);
  } else {
    setTimeout(() => nextLevel(), 3000);
  }
}

/* ── SIGUIENTE NIVEL ── */
function nextLevel() {
  state.level++;
  if (state.level >= LEVELS.length) {
    endGame(true);
  } else {
    loadLevel(state.level);
  }
}

/* ── ACTUALIZAR VIDAS ── */
function updateLives() {
  const dots = document.querySelectorAll(".life");
  dots.forEach((d, i) => {
    d.classList.toggle("lost", i >= state.lives);
  });
}

/* ── FEEDBACK ── */
function setFeedback(type, text) {
  const el = $("feedback");
  el.className = `feedback ${type}`;
  el.textContent = text;
}

/* ── FIN DEL JUEGO ── */
function endGame(won) {
  stopTimer();

  if (won) {
    $("final-score").textContent = state.score;

    const avgTime = state.levelTimes.length
      ? Math.round(state.levelTimes.reduce((a,b) => a+b, 0) / state.levelTimes.length)
      : "—";

    $("end-stats").innerHTML = `
      Niveles completados: <strong>5 / 5</strong><br>
      Tiempo promedio por nivel: <strong>${avgTime}s</strong><br>
      Vidas restantes: <strong>${state.lives} / 3</strong>
    `;
    showScreen("win");
  } else {
    $("lose-level").textContent = `${state.level + 1} / 5`;
    $("lose-reason").textContent = state.lives <= 0
      ? "Sin vidas restantes. El ghost escapó."
      : "Tiempo agotado en todos los intentos.";
    showScreen("lose");
  }
}

/* ── RESET ── */
function resetGame() {
  state = {
    level: 0, lives: 3, score: 0,
    timer: null, timeLeft: 0,
    answered: false, startTime: null,
    levelTimes: [],
  };
}

/* ── INIT ── */
function startGame() {
  resetGame();
  showScreen("game");
  loadLevel(0);
}

document.addEventListener("DOMContentLoaded", () => {
  initMatrix();

  $("btn-start").addEventListener("click", startGame);
  $("btn-replay-win").addEventListener("click", startGame);
  $("btn-replay-lose").addEventListener("click", startGame);

  // Cambio de tab
  document.addEventListener("visibilitychange", () => {
    if (document.hidden && state.timer) {
      // Pausar timer al salir (opcional)
    }
    document.title = document.hidden
      ? "👻 no mires para allá..."
      : "Ghost in the Code — CTF";
  });
});