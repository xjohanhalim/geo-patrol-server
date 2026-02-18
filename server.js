const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================
// SECURITY CONFIG
// ==========================
const SECRET_KEY = "kunci_rahasia_akses";

app.use(cors({
  origin: 'http://dana-api-production.up.railway.app:8100',
  methods: ['GET', 'POST'],
}));

app.use(express.json());

// ==========================
// STATIC FOLDER (AKSES FOTO)
// ==========================
app.use('/uploads', express.static('uploads'));

// ==========================
// KONEKSI DATABASE
// ==========================
const db = mysql.createConnection({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT
});

db.connect(err => {
  if (err) {
    console.error('❌ Database gagal terkoneksi:', err);
    process.exit(1);
  }
  console.log('✅ Database terkoneksi!');
});

// ==========================
// SETUP MULTER (UPLOAD FOTO)
// ==========================
const storage = multer.diskStorage({
  destination: function (req, file, cb) {

    const uploadDir = './uploads';

    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }

    cb(null, uploadDir);
  },

  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });

// ==========================
// MIDDLEWARE VERIFY TOKEN
// ==========================
function verifyToken(req, res, next) {

  const bearerHeader = req.headers['authorization'];

  if (!bearerHeader) {
    return res.status(403).json({ error: 'Token tidak ditemukan' });
  }

  const token = bearerHeader.split(' ')[1];

  jwt.verify(token, SECRET_KEY, (err, authData) => {
    if (err) {
      return res.status(403).json({ error: 'Token tidak valid' });
    }

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
    return res.status(400).json({
      error: 'Username dan Password wajib diisi!'
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = 'INSERT INTO users (username, password_hash) VALUES (?, ?)';

    db.query(sql, [username, hashedPassword], (err) => {

      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({
            error: 'Username sudah digunakan!'
          });
        }

        return res.status(500).json({
          error: 'Gagal registrasi'
        });
      }

      res.status(201).json({
        message: 'Registrasi Berhasil!'
      });
    });

  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==========================
// LOGIN
// ==========================
app.post('/api/login', (req, res) => {

  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      error: 'Username dan Password wajib diisi!'
    });
  }

  db.query(
    'SELECT * FROM users WHERE username = ?',
    [username],
    async (err, results) => {

      if (err) {
        return res.status(500).json({ error: 'Server error' });
      }

      if (results.length === 0) {
        return res.status(401).json({
          error: 'Username tidak ditemukan!'
        });
      }

      const user = results[0];

      const isPasswordValid = await bcrypt.compare(
        password,
        user.password_hash
      );

      if (!isPasswordValid) {
        return res.status(401).json({
          error: 'Password salah!'
        });
      }

      const token = jwt.sign(
        {
          id: user.id,
          username: user.username
        },
        SECRET_KEY,
        { expiresIn: '1h' }
      );

      res.json({
        message: 'Login sukses',
        token: token
      });
    }
  );
});

// ==========================
// SIMPAN LAPORAN PENGIRIMAN
// ==========================
app.post(
  '/api/laporan',
  verifyToken,
  upload.single('foto'),
  (req, res) => {

    const { no_resi, latitude, longitude } = req.body;

    if (!no_resi || !latitude || !longitude) {
      return res.status(400).json({
        error: 'Data tidak lengkap!'
      });
    }

    if (!req.file) {
      return res.status(400).json({
        error: 'Foto wajib diupload!'
      });
    }

    const id_kurir = req.user.id;
    const fotoPath = req.file.path;

    const sql = `
      INSERT INTO laporan_pengiriman
      (id_kurir, no_resi, foto_path, latitude, longitude, status)
      VALUES (?, ?, ?, ?, ?, 'Terkirim')
    `;

    db.query(
      sql,
      [id_kurir, no_resi, fotoPath, latitude, longitude],
      (err) => {

        if (err) {
          return res.status(500).json({
            error: 'Gagal simpan laporan'
          });
        }

        res.json({
          message: 'Laporan berhasil disimpan'
        });
      }
    );
  }
);

// ==========================
// HISTORY LAPORAN USER
// ==========================
app.get(
  '/api/laporan',
  verifyToken,
  (req, res) => {

    const id_kurir = req.user.id;

    const sql = `
      SELECT * FROM laporan_pengiriman
      WHERE id_kurir = ?
      ORDER BY created_at DESC
    `;

    db.query(sql, [id_kurir], (err, results) => {

      if (err) {
        return res.status(500).json({
          error: 'Gagal ambil data'
        });
      }

      res.json(results);
    });
  }
);

// ==========================
app.listen(PORT, () => {
  console.log(`🚀 Server jalan di http://localhost:${PORT}`);
});
