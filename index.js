// index.js
require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite'); // lightweight promise wrapper
const cookieParser = require('cookie-parser'); // Import cookie-parser

const app = express();
app.use(express.json());
app.use(cookieParser()); // Use cookie-parser middleware
app.use(express.static(__dirname));

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
async function authenticateToken(req, res, next) {
  const token = req.cookies.jwtToken; // Get token from cookie
  if (!token) {
    // No token, redirect to signin page
    return res.redirect('/signin');
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await db.get(`SELECT id, username, email FROM users WHERE id = ?`, [decoded.id]);

    if (!user) {
      // Invalid user, clear cookie and redirect
      res.clearCookie('jwtToken');
      return res.redirect('/signin');
    }

    req.user = { ...decoded, email: user.email }; // Add email to req.user
    next();
  } catch (err) {
    // Invalid or expired token, clear cookie and redirect
    res.clearCookie('jwtToken');
    return res.redirect('/signin');
  }
}

// middleware: authorize admin
function authorizeAdmin(req, res, next) {
  if (req.user && req.user.email === 'admin@gmail.com') {
    next();
  } else {
    res.status(403).json({ error: 'Access denied: Admin privilege required' });
  }
}

// Register
app.post('/register', async (req, res) => {
  try {
    const { username, password, email } = req.body;
    console.log('Received registration data:', { username, email, password: '[REDACTED]' }); // Log data to terminal
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
    res.cookie('jwtToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
      maxAge: 1000 * 60 * 60 * 24 // 1 day
    });
    res.json({ message: 'Login successful', email: user.email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected route to fetch user data
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await db.get(`SELECT id, username, email, created_at FROM users WHERE id = ?`, [req.user.id]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected route to fetch all users for admin page
app.get('/admin/users', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const users = await db.all(`SELECT id, username, email, created_at FROM users`);
    res.json({ users });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/signin', (req, res) => {
  res.sendFile(__dirname + '/signin.html');
});

app.get('/profile', authenticateToken, (req, res) => {
  res.sendFile(__dirname + '/profile.html');
});

app.get('/admin', authenticateToken, authorizeAdmin, (req, res) => {
  res.sendFile(__dirname + '/admin.html');
});

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
