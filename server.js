const express = require('express');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'change-this-secret-before-deploying';
const FILE = path.join(__dirname, 'data.json');

// --- Tiny JSON-file "database" (swap for SQLite/Postgres/Mongo later) ---
let db = { users: [], tasks: [] };
try { db = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) {}
const save = () => fs.writeFileSync(FILE, JSON.stringify(db, null, 2));

const app = express();
app.use(express.json({ limit: '50kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const sign = u => jwt.sign({ id: u.id, name: u.name }, SECRET, { expiresIn: '7d' });
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });

// --- Auth ---
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return bad(res, 'Name, email and password are required.');
  if (String(password).length < 6) return bad(res, 'Password must be at least 6 characters.');
  const mail = String(email).trim().toLowerCase();
  if (db.users.some(u => u.email === mail)) return bad(res, 'That email is already registered.', 409);
  const user = { id: crypto.randomUUID(), name: String(name).trim().slice(0, 60), email: mail,
                 hash: await bcrypt.hash(String(password), 10) };
  db.users.push(user); save();
  res.status(201).json({ token: sign(user), user: { id: user.id, name: user.name } });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = db.users.find(u => u.email === String(email || '').trim().toLowerCase());
  if (!user || !(await bcrypt.compare(String(password || ''), user.hash)))
    return bad(res, 'Wrong email or password.', 401);
  res.json({ token: sign(user), user: { id: user.id, name: user.name } });
});

// Authorization: every /api/tasks route requires a valid token
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  try { req.user = jwt.verify(h.replace('Bearer ', ''), SECRET); next(); }
  catch (e) { bad(res, 'Please sign in again.', 401); }
}

// --- Real-time: one socket set per user ---
const sockets = new Map();
const notify = uid => (sockets.get(uid) || []).forEach(ws => ws.readyState === 1 && ws.send('changed'));

// --- Task CRUD (users can only touch their own tasks) ---
const PRIOS = ['High', 'Medium', 'Low'], STATUSES = ['todo', 'doing', 'done'];
function clean(b, partial) {
  const t = {};
  if (b.title !== undefined) t.title = String(b.title).trim().slice(0, 120);
  if (b.notes !== undefined) t.notes = String(b.notes).trim().slice(0, 2000);
  if (PRIOS.includes(b.prio)) t.prio = b.prio;
  if (STATUSES.includes(b.status)) t.status = b.status;
  if (b.due !== undefined) t.due = /^\d{4}-\d{2}-\d{2}$/.test(b.due) ? b.due : '';
  if (!partial && !t.title) return null;
  return t;
}

app.get('/api/tasks', auth, (req, res) => res.json(db.tasks.filter(t => t.owner === req.user.id)));

app.post('/api/tasks', auth, (req, res) => {
  const t = clean(req.body || {}, false);
  if (!t) return bad(res, 'Title is required.');
  const task = { notes: '', prio: 'Medium', due: '', status: 'todo', ...t,
                 id: crypto.randomUUID(), owner: req.user.id, created: Date.now() };
  db.tasks.push(task); save(); notify(req.user.id);
  res.status(201).json(task);
});

app.put('/api/tasks/:id', auth, (req, res) => {
  const task = db.tasks.find(t => t.id === req.params.id && t.owner === req.user.id);
  if (!task) return bad(res, 'Task not found.', 404);
  const t = clean(req.body || {}, true);
  if (t.title === '') return bad(res, 'Title cannot be empty.');
  Object.assign(task, t); save(); notify(req.user.id);
  res.json(task);
});

app.delete('/api/tasks/:id', auth, (req, res) => {
  const i = db.tasks.findIndex(t => t.id === req.params.id && t.owner === req.user.id);
  if (i < 0) return bad(res, 'Task not found.', 404);
  db.tasks.splice(i, 1); save(); notify(req.user.id);
  res.status(204).end();
});

// --- WebSocket server (auth via ?token=) ---
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });
wss.on('connection', (ws, req) => {
  let user;
  try { user = jwt.verify(new URL(req.url, 'http://x').searchParams.get('token'), SECRET); }
  catch (e) { return ws.close(1008, 'Unauthorized'); }
  if (!sockets.has(user.id)) sockets.set(user.id, new Set());
  sockets.get(user.id).add(ws);
  ws.on('close', () => sockets.get(user.id).delete(ws));
});

server.listen(PORT, () => console.log(`Taskboard running at http://localhost:${PORT}`));
