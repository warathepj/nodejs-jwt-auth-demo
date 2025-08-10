// index.js
require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite'); // lightweight promise wrapper

const app = express();
app.use(express.json());
app.use(express.static('node-sqlite-jwt'));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';
const DB_FILE = process.env.DB_FILE || './data/auth.db';

let db;

// init DB connection and ensure users table exists
async function initDb() {
  db = await open({
    filename: DB_FILE,
    driver: sqlite3.Database
  });

  await db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email TEXT UNIQUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
}
initDb().catch(err => {
  console.error('DB init error:', err);
  process.exit(1);
});

// helper: create JWT
function createToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

// middleware: verify token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = decoded; // e.g. { id: 1, iat, exp }
    next();
  });
}

// Register
app.post('/register', async (req, res) => {
  try {
    const { username, password, email } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });

    const hashed = await bcrypt.hash(password, 10);
    const result = await db.run(
      `INSERT INTO users (username, password, email) VALUES (?, ?, ?)`,
      [username, hashed, email || null]
    );

    res.status(201).json({ id: result.lastID, username, email });
  } catch (err) {
    if (err && err.message && err.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'Username or email already taken' });
    }
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });

    const user = await db.get(`SELECT * FROM users WHERE username = ?`, [username]);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const token = createToken({ id: user.id, username: user.username });
    res.json({ token, expiresIn: JWT_EXPIRES_IN });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected route
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await db.get(`SELECT id, username, email, created_at FROM users WHERE id = ?`, [req.user.id]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/signin', (req, res) => {
  res.sendFile(__dirname + '/signin.html');
});

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
