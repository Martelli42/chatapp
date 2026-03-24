const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const Database = require('better-sqlite3');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const db = new Database('chat.db');
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey_changeme';

// Setup DB
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    display_name TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    display_name TEXT NOT NULL,
    text TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Register
app.post('/api/register', (req, res) => {
  const { username, password, display_name } = req.body;
  if (!username || !password || !display_name)
    return res.status(400).json({ error: 'All fields required' });

  const hash = bcrypt.hashSync(password, 10);
  try {
    const stmt = db.prepare('INSERT INTO users (username, password, display_name) VALUES (?, ?, ?)');
    const result = stmt.run(username.trim().toLowerCase(), hash, display_name.trim());
    const token = jwt.sign({ id: result.lastInsertRowid, username }, JWT_SECRET);
    res.json({ token, display_name: display_name.trim() });
  } catch (e) {
    res.status(400).json({ error: 'Username already taken' });
  }
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim().toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Invalid username or password' });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
  res.json({ token, display_name: user.display_name });
});

// Update display name
app.post('/api/update-name', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const { id } = jwt.verify(auth, JWT_SECRET);
    const { display_name } = req.body;
    if (!display_name) return res.status(400).json({ error: 'Name required' });
    db.prepare('UPDATE users SET display_name = ? WHERE id = ?').run(display_name.trim(), id);
    res.json({ ok: true });
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
});

// Get last 50 messages
app.get('/api/messages', (req, res) => {
  const msgs = db.prepare('SELECT display_name, text, created_at FROM messages ORDER BY id DESC LIMIT 50').all();
  res.json(msgs.reverse());
});

// Socket.io auth + chat
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    socket.userId = payload.id;
    socket.username = payload.username;
    next();
  } catch {
    next(new Error('Unauthorized'));
  }
});

io.on('connection', (socket) => {
  const user = db.prepare('SELECT display_name FROM users WHERE id = ?').get(socket.userId);
  socket.displayName = user?.display_name || socket.username;

  socket.on('message', (text) => {
    if (!text || typeof text !== 'string' || text.trim().length === 0) return;
    const trimmed = text.trim().slice(0, 1000);
    const fresh = db.prepare('SELECT display_name FROM users WHERE id = ?').get(socket.userId);
    const name = fresh?.display_name || socket.displayName;
    db.prepare('INSERT INTO messages (user_id, display_name, text) VALUES (?, ?, ?)').run(socket.userId, name, trimmed);
    io.emit('message', { display_name: name, text: trimmed, created_at: new Date().toISOString() });
  });

  socket.on('name-updated', () => {
    const fresh = db.prepare('SELECT display_name FROM users WHERE id = ?').get(socket.userId);
    if (fresh) socket.displayName = fresh.display_name;
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
