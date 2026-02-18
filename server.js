const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================
// ENV CONFIG
// ==========================
const SECRET_KEY = process.env.JWT_SECRET || "kunci_rahasia_akses";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://geo-patrol-server-production.up.railway.app";

// ==========================
// CORS
// ==========================
app.use(cors({
  origin: FRONTEND_URL,
  methods: ['GET', 'POST']
}));

app.use(express.json());

// ==========================
// STATIC FOLDER
// ==========================
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}
app.use('/uploads', express.static(uploadDir));

// ==========================
// DATABASE POOL
// ==========================
let db;

async function initDB() {
  try {
    db = await mysql.createPool({
      host: process.env.MYSQLHOST,
      user: process.env.MYSQLUSER,
      password: process.env.MYSQLPASSWORD,
      database: process.env.MYSQLDATABASE,
      port: process.env.MYSQLPORT,
      connectionLimit: 10
    });

    console.log('✅ Database terkoneksi!');
  } catch (err) {
    console.error('❌ Database gagal terkoneksi:', err);
    process.exit(1);
  }
}
initDB();

// ==========================
// MULTER
// ==========================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

// ==========================
// VERIFY TOKEN
// ==========================
function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  if (!bearerHeader) return res.status(403).json({ error: 'Token tidak ditemukan' });

  const token = bearerHeader.split(' ')[1];

  jwt.verify(token, SECRET_KEY, (err, authData) => {
    if (err) return res.status(403).json({ error: 'Token tidak valid' });
    req.user = authData;
    next();
  });
}

// ==========================
// REGISTER
// ==========================
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username dan Password wajib diisi!' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    await db.query(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)',
      [username, hashedPassword]
    );

    res.status(201).json({ message: 'Registrasi Berhasil!' });

  } catch (err) {

    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: 'Username sudah digunakan!' });
    }

    res.status(500).json({ error: 'Gagal registrasi' });
  }
});

// ==========================
// LOGIN
// ==========================
app.post('/api/login', async (req, res) => {

  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username dan Password wajib diisi!' });
  }

  try {
    const [rows] = await db.query(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Username tidak ditemukan!' });
    }

    const user = rows[0];

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Password salah!' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      SECRET_KEY,
      { expiresIn: '1h' }
    );

    res.json({ message: 'Login sukses', token });

  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==========================
// SIMPAN LAPORAN
// ==========================
app.post('/api/laporan', verifyToken, upload.single('foto'), async (req, res) => {

  const { no_resi, latitude, longitude } = req.body;

  if (!no_resi || !latitude || !longitude) {
    return res.status(400).json({ error: 'Data tidak lengkap!' });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'Foto wajib diupload!' });
  }

  try {

    await db.query(`
      INSERT INTO laporan_pengiriman
      (id_kurir, no_resi, foto_path, latitude, longitude, status)
      VALUES (?, ?, ?, ?, ?, 'Terkirim')
    `,
    [req.user.id, no_resi, req.file.filename, latitude, longitude]);

    res.json({ message: 'Laporan berhasil disimpan' });

  } catch (err) {
    res.status(500).json({ error: 'Gagal simpan laporan' });
  }
});

// ==========================
// HISTORY LAPORAN
// ==========================
app.get('/api/laporan', verifyToken, async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT * FROM laporan_pengiriman
      WHERE id_kurir = ?
      ORDER BY created_at DESC
    `, [req.user.id]);

    res.json(rows);

  } catch (err) {
    res.status(500).json({ error: 'Gagal ambil data' });
  }
});

// ==========================
// ROOT
// ==========================
app.get('/', (req, res) => {
  res.send('API GEO PATROL RUNNING');
});

app.get('/init-db', async (req, res) => {
  try {

    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE,
        password_hash VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await db.query(`
      CREATE TABLE IF NOT EXISTS laporan_pengiriman (
        id INT AUTO_INCREMENT PRIMARY KEY,
        id_kurir INT,
        no_resi VARCHAR(100),
        foto_path VARCHAR(255),
        latitude VARCHAR(50),
        longitude VARCHAR(50),
        status VARCHAR(20),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    res.send("Database initialized successfully 🚀");

  } catch (err) {
    res.status(500).send(err.message);
  }
});

// ==========================
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
