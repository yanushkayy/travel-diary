const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const DB_PATH = path.join(__dirname, 'data.sqlite');

const db = new sqlite3.Database(DB_PATH);

const dbRun = (sql, params = []) =>
    new Promise((resolve, reject) => {
        db.run(sql, params, function onRun(err) {
            if (err) reject(err);
            else resolve(this);
        });
    });
const dbGet = (sql, params = []) =>
    new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
const dbAll = (sql, params = []) =>
    new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });

db.serialize(() => {
    db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    )
  `);
    db.run(`
    CREATE TABLE IF NOT EXISTS trips (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      location TEXT,
      lat REAL,
      lng REAL,
      cost REAL,
      image_url TEXT,
      heritage TEXT,
      places TEXT,
      rating_safety INTEGER,
      rating_comfort INTEGER,
      rating_density INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);
});

async function seed() {
    const count = await dbGet(`SELECT COUNT(*) as c FROM users`);
    if (count.c === 0) {
        const hash = await bcrypt.hash('password', 10);
        const user = await dbRun(`INSERT INTO users (username, password_hash) VALUES (?, ?)`, [
            'traveler',
            hash
        ]);
        await dbRun(
            `INSERT INTO trips (user_id, title, description, location, lat, lng, cost, image_url, heritage, places, rating_safety, rating_comfort, rating_density)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                user.lastID,
                'Лиссабон весной',
                'Трамваи, океан, пастель де ната',
                'Лиссабон, Португалия',
                38.7223,
                -9.1393,
                950,
                'https://upload.wikimedia.org/wikipedia/commons/7/77/Lisbon_Tramway.JPG',
                'Белемская башня, Монастырь Жеронимуш',
                'Альфама, Байру Алту, океан, троллейбусы',
                8,
                9,
                6
            ]
        );
        console.log('Seeded default user and trip');
    }
}
seed().catch(console.error);

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function authRequired(req, res, next) {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ error: 'Нет токена' });
    const [, token] = header.split(' ');
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        req.user = payload;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Неверный или истёкший токен' });
    }
}

// Auth
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Нужны username и password' });
    try {
        const existing = await dbGet(`SELECT id FROM users WHERE username = ?`, [username]);
        if (existing) return res.status(409).json({ error: 'Пользователь уже есть' });
        const hash = await bcrypt.hash(password, 10);
        await dbRun(`INSERT INTO users (username, password_hash) VALUES (?, ?)`, [username, hash]);
        return res.json({ message: 'Регистрация успешна' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal error' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Нужны username и password' });
    try {
        const user = await dbGet(`SELECT * FROM users WHERE username = ?`, [username]);
        if (!user) return res.status(401).json({ error: 'Неверные данные' });
        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) return res.status(401).json({ error: 'Неверные данные' });
        const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: '7d' });
        return res.json({ token });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal error' });
    }
});

// Trips
app.post('/api/trips', authRequired, async (req, res) => {
    const {
        title,
        description,
        location,
        lat,
        lng,
        cost,
        imageUrl,
        heritage,
        places,
        ratingSafety,
        ratingComfort,
        ratingDensity
    } = req.body;
    if (!title || !location) {
        return res.status(400).json({ error: 'title и location обязательны' });
    }
    try {
        const result = await dbRun(
            `INSERT INTO trips (user_id, title, description, location, lat, lng, cost, image_url, heritage, places, rating_safety, rating_comfort, rating_density)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                req.user.id,
                title,
                description || '',
                location,
                lat || null,
                lng || null,
                cost || null,
                imageUrl || '',
                heritage || '',
                places || '',
                ratingSafety || null,
                ratingComfort || null,
                ratingDensity || null
            ]
        );
        return res.json({ id: result.lastID, message: 'Путешествие добавлено' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal error' });
    }
});

app.get('/api/trips', async (req, res) => {
    try {
        const rows = await dbAll(
            `SELECT trips.*, users.username as author
       FROM trips JOIN users ON trips.user_id = users.id
       ORDER BY trips.created_at DESC`
        );
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal error' });
    }
});

app.get('/api/trips/:id', async (req, res) => {
    try {
        const row = await dbGet(
            `SELECT trips.*, users.username as author
       FROM trips JOIN users ON trips.user_id = users.id
       WHERE trips.id = ?`,
            [req.params.id]
        );
        if (!row) return res.status(404).json({ error: 'Не найдено' });
        res.json(row);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal error' });
    }
});

app.get('/api/users/:username/trips', async (req, res) => {
    try {
        const user = await dbGet(`SELECT id FROM users WHERE username = ?`, [req.params.username]);
        if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
        const rows = await dbAll(
            `SELECT trips.*, users.username as author
       FROM trips JOIN users ON trips.user_id = users.id
       WHERE trips.user_id = ?
       ORDER BY trips.created_at DESC`,
            [user.id]
        );
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal error' });
    }
});

app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));

app.listen(PORT, () => {
    console.log(`Travel diary running at http://localhost:${PORT}`);
});

