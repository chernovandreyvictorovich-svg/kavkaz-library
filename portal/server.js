const express = require('express');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const mammoth = require('mammoth');

const app = express();
const PORT = process.env.PORT || 3001;

// Путь к библиотеке документов — папка рядом с portal/
const LIBRARY = process.env.LIBRARY_PATH
  || path.resolve(__dirname, '..', '12. КАВКАЗ');

const CONFIG_FILE = path.join(__dirname, 'config.json');

// ── Логи аналитики (NDJSON, без БД) ─────────────────────────────────────────
const DATA_DIR = path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
const SEARCHES_LOG = path.join(DATA_DIR, 'searches.ndjson');
const OPENS_LOG    = path.join(DATA_DIR, 'opens.ndjson');

// Пропускаемые системные файлы
const SKIP_FILES = new Set(['Thumbs.db', 'desktop.ini', '.DS_Store']);

// ── Конфигурация ─────────────────────────────────────────────────────────────

function loadConfig() {
  try { return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); }
  catch { return {}; }
}

function saveConfig(cfg) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
}

function getJwtSecret() {
  const cfg = loadConfig();
  if (!cfg.jwtSecret) {
    cfg.jwtSecret = crypto.randomBytes(32).toString('hex');
    saveConfig(cfg);
  }
  return cfg.jwtSecret;
}

// ── Безопасность путей ───────────────────────────────────────────────────────

function resolveSafe(relPath) {
  const normalized = (relPath || '').replace(/\//g, path.sep);
  const abs = path.resolve(LIBRARY, normalized);
  const lib = path.resolve(LIBRARY);
  if (abs !== lib && !abs.startsWith(lib + path.sep)) {
    throw new Error('Path outside library');
  }
  return abs;
}

function toRelative(absPath) {
  return path.relative(LIBRARY, absPath).replace(/\\/g, '/');
}

function appendLog(file, obj) {
  try { fs.appendFileSync(file, JSON.stringify(obj) + '\n'); } catch {}
}

function readLog(file) {
  try {
    return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
  } catch { return []; }
}

// ── Auth middleware ──────────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    jwt.verify(token, getJwtSecret());
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ── Express setup ────────────────────────────────────────────────────────────

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── API: дерево папок ────────────────────────────────────────────────────────

app.get('/api/tree', (req, res) => {
  function walk(dir, depth = 0) {
    if (depth > 6) return [];
    try {
      return fs.readdirSync(dir, { withFileTypes: true })
        .filter(e => e.isDirectory() && !e.name.startsWith('.') && !e.name.startsWith('~'))
        .sort((a, b) => a.name.localeCompare(b.name, 'ru', { numeric: true }))
        .map(e => ({
          name: e.name,
          path: toRelative(path.join(dir, e.name)),
          children: walk(path.join(dir, e.name), depth + 1)
        }));
    } catch { return []; }
  }
  res.json(walk(LIBRARY));
});

// ── API: файлы в папке ───────────────────────────────────────────────────────

app.get('/api/files', (req, res) => {
  try {
    const dir = req.query.path ? resolveSafe(req.query.path) : LIBRARY;
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    const folders = entries
      .filter(e => e.isDirectory() && !e.name.startsWith('.') && !e.name.startsWith('~'))
      .sort((a, b) => a.name.localeCompare(b.name, 'ru', { numeric: true }))
      .map(e => ({
        type: 'folder',
        name: e.name,
        path: toRelative(path.join(dir, e.name))
      }));

    const files = entries
      .filter(e => e.isFile() && !e.name.startsWith('~') && !e.name.startsWith('.') && !SKIP_FILES.has(e.name))
      .sort((a, b) => a.name.localeCompare(b.name, 'ru', { numeric: true }))
      .map(e => {
        const fp = path.join(dir, e.name);
        const s = fs.statSync(fp);
        return {
          type: 'file',
          name: e.name,
          path: toRelative(fp),
          size: s.size,
          modified: s.mtime
        };
      });

    res.json([...folders, ...files]);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ── API: поиск по всему дереву ───────────────────────────────────────────────

app.get('/api/search', (req, res) => {
  const q = (req.query.q || '').toLowerCase().trim();
  if (q.length < 2) return res.json([]);

  const results = [];

  function walk(dir) {
    if (results.length >= 100) return;
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const e of entries) {
        if (results.length >= 100) break;
        if (e.name.startsWith('~') || e.name.startsWith('.') || SKIP_FILES.has(e.name)) continue;
        const fp = path.join(dir, e.name);
        if (e.isDirectory()) {
          walk(fp);
        } else if (e.name.toLowerCase().includes(q)) {
          const s = fs.statSync(fp);
          results.push({
            type: 'file',
            name: e.name,
            path: toRelative(fp),
            size: s.size,
            modified: s.mtime
          });
        }
      }
    } catch {}
  }

  walk(LIBRARY);
  res.json(results);
});

// ── API: открыть файл в браузере ─────────────────────────────────────────────

app.get('/api/view', (req, res) => {
  try {
    const fp = resolveSafe(req.query.path);
    if (!fs.statSync(fp).isFile()) return res.status(400).json({ error: 'Not a file' });
    res.sendFile(fp);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ── API: DOCX → HTML (просмотр без редактирования) ──────────────────────────

app.get('/api/docx-html', async (req, res) => {
  try {
    const fp = resolveSafe(req.query.path);
    if (!fs.statSync(fp).isFile()) return res.status(400).json({ error: 'Not a file' });
    const ext = path.extname(fp).toLowerCase();
    if (ext !== '.docx') return res.status(400).json({ error: 'Только .docx поддерживается' });
    const result = await mammoth.convertToHtml({ path: fp });
    res.json({ html: result.value });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ── API: скачать файл ────────────────────────────────────────────────────────

app.get('/api/download', (req, res) => {
  try {
    const fp = resolveSafe(req.query.path);
    if (!fs.statSync(fp).isFile()) return res.status(400).json({ error: 'Not a file' });
    res.download(fp);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ── API: статус администратора ───────────────────────────────────────────────

app.get('/api/admin-status', (req, res) => {
  const cfg = loadConfig();
  res.json({ configured: !!cfg.adminHash });
});

// ── API: первичная настройка пароля ─────────────────────────────────────────

app.post('/api/setup', async (req, res) => {
  const cfg = loadConfig();
  if (cfg.adminHash) return res.status(400).json({ error: 'Already configured' });
  const { password } = req.body;
  if (!password || password.length < 6) {
    return res.status(400).json({ error: 'Минимум 6 символов' });
  }
  cfg.adminHash = await bcrypt.hash(password, 10);
  saveConfig(cfg);
  res.json({ ok: true });
});

// ── API: смена пароля ────────────────────────────────────────────────────────

app.post('/api/change-password', requireAuth, async (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 6) {
    return res.status(400).json({ error: 'Минимум 6 символов' });
  }
  const cfg = loadConfig();
  cfg.adminHash = await bcrypt.hash(password, 10);
  saveConfig(cfg);
  res.json({ ok: true });
});

// ── API: вход ────────────────────────────────────────────────────────────────

app.post('/api/login', async (req, res) => {
  const cfg = loadConfig();
  if (!cfg.adminHash) return res.status(400).json({ error: 'Пароль не настроен' });
  const ok = await bcrypt.compare(req.body.password || '', cfg.adminHash);
  if (!ok) return res.status(401).json({ error: 'Неверный пароль' });
  const token = jwt.sign({ role: 'admin' }, getJwtSecret(), { expiresIn: '8h' });
  res.json({ token });
});

// ── API: загрузить файл ──────────────────────────────────────────────────────

const storage = multer.diskStorage({
  destination(req, file, cb) {
    try {
      const dir = req.body.path ? resolveSafe(req.body.path) : LIBRARY;
      fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    } catch (e) { cb(e); }
  },
  filename(req, file, cb) {
    // Восстанавливаем UTF-8 из latin1 (браузерная кодировка)
    const name = Buffer.from(file.originalname, 'latin1').toString('utf8');
    cb(null, name);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 200 * 1024 * 1024 } // 200 МБ
});

app.post('/api/upload', requireAuth, upload.array('files', 20), (req, res) => {
  if (!req.files?.length) return res.status(400).json({ error: 'Файлы не выбраны' });
  res.json({ ok: true, uploaded: req.files.map(f => f.filename) });
});

// ── API: создать папку ───────────────────────────────────────────────────────

app.post('/api/mkdir', requireAuth, (req, res) => {
  try {
    const { path: relPath } = req.body;
    if (!relPath) return res.status(400).json({ error: 'Укажите путь' });
    const dir = resolveSafe(relPath);
    fs.mkdirSync(dir, { recursive: true });
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ── API: логирование поиска ───────────────────────────────────────────────────

app.post('/api/log/search', (req, res) => {
  const { q, n } = req.body;
  if (q && typeof q === 'string' && q.trim().length >= 2) {
    appendLog(SEARCHES_LOG, { q: q.trim().slice(0, 200), n: n || 0, t: Math.floor(Date.now() / 1000) });
  }
  res.json({ ok: true });
});

app.post('/api/log/open', (req, res) => {
  const { p } = req.body;
  if (p && typeof p === 'string') {
    appendLog(OPENS_LOG, { p: p.slice(0, 500), t: Math.floor(Date.now() / 1000) });
  }
  res.json({ ok: true });
});

// ── API: статистика (только для админа) ──────────────────────────────────────

app.get('/api/stats', requireAuth, (req, res) => {
  const searches = readLog(SEARCHES_LOG);
  const opens    = readLog(OPENS_LOG);

  // Агрегация поисковых запросов
  const qAll = {}, qZero = {};
  for (const s of searches) {
    const k = s.q.toLowerCase();
    qAll[k]  = (qAll[k]  || 0) + 1;
    if (s.n === 0) qZero[k] = (qZero[k] || 0) + 1;
  }

  const topSearches  = Object.entries(qAll).sort((a,b) => b[1]-a[1]).slice(0,20).map(([q,c]) => ({ q, c }));
  const zeroSearches = Object.entries(qZero).sort((a,b) => b[1]-a[1]).slice(0,20).map(([q,c]) => ({ q, c }));

  // Агрегация открытий
  const oCounts = {};
  for (const o of opens) oCounts[o.p] = (oCounts[o.p] || 0) + 1;
  const topOpens = Object.entries(oCounts).sort((a,b) => b[1]-a[1]).slice(0,20)
    .map(([p,c]) => ({ p, name: p.split('/').pop(), section: p.split('/').slice(0,-1).pop() || '', c }));

  // Ежедневная активность за 30 дней
  const now = Math.floor(Date.now() / 1000), day = 86400;
  const daily = {};
  for (let i = 29; i >= 0; i--) {
    const k = new Date((now - i * day) * 1000).toISOString().slice(0,10);
    daily[k] = { s: 0, o: 0 };
  }
  for (const s of searches) {
    const k = new Date(s.t * 1000).toISOString().slice(0,10);
    if (daily[k]) daily[k].s++;
  }
  for (const o of opens) {
    const k = new Date(o.t * 1000).toISOString().slice(0,10);
    if (daily[k]) daily[k].o++;
  }

  res.json({
    total: { searches: searches.length, opens: opens.length,
      zeroRate: searches.length ? Math.round(searches.filter(s => s.n === 0).length / searches.length * 100) : 0 },
    topSearches, zeroSearches, topOpens,
    daily: Object.entries(daily).map(([date,v]) => ({ date, ...v }))
  });
});

// ── Старт ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`📚 Библиотека КАВКАЗ → http://localhost:${PORT}`);
  console.log(`   Папка: ${LIBRARY}`);
});
