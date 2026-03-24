const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const path = require('path');
const Database = require('better-sqlite3');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const db = new Database('chat.db');
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey_changeme';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    google_id TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    email TEXT
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
app.use(session({ secret: JWT_SECRET, resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));

passport.use(new GoogleStrategy({
  clientID: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  callbackURL: `${BASE_URL}/auth/google/callback`
}, (accessToken, refreshToken, profile, done) => {
  const email = profile.emails?.[0]?.value || '';
  const googleName = profile.displayName || 'User';
  let user = db.prepare('SELECT * FROM users WHERE google_id = ?').get(profile.id);
  let isNew = false;
  if (!user) {
    const result = db.prepare('INSERT INTO users (google_id, display_name, email) VALUES (?, ?, ?)').run(profile.id, googleName, email);
    user = { id: result.lastInsertRowid, google_id: profile.id, display_name: googleName, email, isNew: true };
    isNew = true;
  }
  user.isNew = isNew;
  return done(null, user);
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  done(null, user);
});

// Google auth routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    const user = req.user;
    const token = jwt.sign({ id: user.id }, JWT_SECRET);
    res.redirect(`/?token=${token}&name=${encodeURIComponent(user.display_name)}&new=${user.isNew ? '1' : '0'}`);
  }
);

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

// Socket.io
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    socket.userId = payload.id;
    next();
  } catch {
    next(new Error('Unauthorized'));
  }
});

io.on('connection', (socket) => {
  const user = db.prepare('SELECT display_name FROM users WHERE id = ?').get(socket.userId);
  socket.displayName = user?.display_name || 'Unknown';

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
