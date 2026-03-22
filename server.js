/**
 * server.js - Backend API สำหรับระบบบัญชีคุมวัสดุ อปท.
 * ใช้ Express + PostgreSQL + bcrypt + express-session + helmet + rate-limit
 */
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const helmet = require('helmet');

const {
    sanitize,
    isPositiveInt,
    validateId,
    validateItem,
    validateTransaction,
    validateSetting,
    validateRestore,
    validateNewUser,
    validateNewPassword,
} = require('./validators');

const app = express();
const PORT = process.env.PORT || 3000;
const BCRYPT_ROUNDS = 10;

// ===== Trust Proxy (Railway อยู่หลัง reverse proxy) =====
app.set('trust proxy', 1);

// ===== PostgreSQL Connection Pool =====
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' || (process.env.DATABASE_URL && process.env.DATABASE_URL.includes('railway'))
        ? { rejectUnauthorized: false }
        : false,
    max: 20,
    idleTimeoutMillis: 30000
});

pool.query('SELECT NOW()')
    .then(() => console.log('✅ เชื่อมต่อ PostgreSQL สำเร็จ'))
    .catch(err => { console.error('❌ เชื่อมต่อ PostgreSQL ไม่ได้:', err.message); process.exit(1); });

// Helper: DB query
async function query(sql, params = []) {
    return pool.query(sql, params);
}

// Helper: ส่ง validation error 400
function badRequest(res, errors) {
    return res.status(400).json({ success: false, error: errors.join(' | '), errors });
}

// ============================
// AUDIT LOG
// ============================
/**
 * บันทึก audit log — fire-and-forget (ไม่ block request)
 * @param {object} opts
 * @param {number|null} opts.userId
 * @param {string}      opts.username
 * @param {string}      opts.action     — เช่น 'LOGIN_SUCCESS'
 * @param {string}      opts.resource   — เช่น 'items'
 * @param {string|null} opts.resourceId
 * @param {object|null} opts.details    — ข้อมูลเพิ่มเติม (jsonb)
 * @param {string}      opts.ip
 */
function auditLog({ userId = null, username = '', action, resource = '', resourceId = null, details = null, ip = '' }) {
    pool.query(
        `INSERT INTO audit_logs (user_id, username, action, resource, resource_id, details, ip_address)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [userId, username, action, resource, resourceId ? String(resourceId) : null,
         details ? JSON.stringify(details) : null, ip]
    ).catch(err => console.error('⚠️ audit log error:', err.message));
}

/** ดึง IP จาก request (รองรับ Railway reverse proxy) */
function getIp(req) {
    return req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';
}

// ===== Security Headers (Helmet) =====
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: [
                "'self'",
                "'unsafe-inline'",          // inline JS ใน index.html / login.html
                'https://cdn.jsdelivr.net', // Chart.js, xlsx
            ],
            scriptSrcAttr: ["'unsafe-inline'"],  // อนุญาต onclick/onchange inline handlers
            styleSrc: [
                "'self'",
                "'unsafe-inline'",
                'https://fonts.googleapis.com',
                'https://cdnjs.cloudflare.com',
            ],
            fontSrc: [
                "'self'",
                'https://fonts.gstatic.com',
                'https://cdnjs.cloudflare.com',
            ],
            imgSrc: ["'self'", 'data:'],
            connectSrc: ["'self'"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
        },
    },
    crossOriginEmbedderPolicy: false, // ปิดเพื่อให้โหลด CDN ได้ปกติ
}));

// ===== CORS =====
const rawOrigins = process.env.ALLOWED_ORIGINS || '';
const allowedOrigins = rawOrigins
    ? rawOrigins.split(',').map(o => o.trim()).filter(Boolean)
    : [];  // ถ้าไม่ตั้ง จะใช้โหมด same-origin (ไม่อนุญาต cross-origin)

app.use(cors({
    origin: (origin, callback) => {
        // อนุญาตถ้า same-origin (origin = undefined) หรืออยู่ใน allowedOrigins
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        callback(new Error(`CORS: origin "${origin}" ไม่ได้รับอนุญาต`));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type'],
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ===== Session Middleware =====
app.use(session({
    store: new pgSession({
        pool,
        createTableIfMissing: true
    }),
    secret: process.env.SESSION_SECRET || 'stock-aot-secret-2024-xK9pL',
    resave: false,
    saveUninitialized: false,
    rolling: true,           // ต่ออายุ session ทุกครั้งที่มี request
    cookie: {
        httpOnly: true,
        sameSite: 'strict',
        secure: 'auto',
        maxAge: 30 * 60 * 1000  // 30 นาที inactivity timeout
    }
}));

// ============================
// AUTH MIDDLEWARE
// ============================
function checkAuth(req, res, next) {
    if (req.session && req.session.user) return next();
    return res.status(401).json({ success: false, error: 'กรุณาเข้าสู่ระบบ' });
}

function checkAdmin(req, res, next) {
    if (req.session && req.session.user && req.session.user.role === 'admin') return next();
    return res.status(403).json({ success: false, error: 'เฉพาะผู้ดูแลระบบเท่านั้น' });
}

// ป้องกันทุก /api/* ยกเว้น /login และ /logout
app.use('/api', (req, res, next) => {
    if (req.path === '/login' || req.path === '/logout') return next();
    return checkAuth(req, res, next);
});

// ============================
// API: Auth
// ============================
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password)
            return res.status(400).json({ success: false, error: 'กรุณากรอกชื่อผู้ใช้และรหัสผ่าน' });

        const result = await query('SELECT * FROM users WHERE username = $1', [username.trim()]);
        if (result.rows.length === 0)
            return res.status(401).json({ success: false, error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });

        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
            auditLog({ username: username.trim(), action: 'LOGIN_FAILED', resource: 'auth', ip: getIp(req) });
            return res.status(401).json({ success: false, error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
        }

        req.session.user = { id: user.id, username: user.username, role: user.role };
        auditLog({ userId: user.id, username: user.username, action: 'LOGIN_SUCCESS', resource: 'auth', ip: getIp(req) });

        const orgRes = await query("SELECT value FROM settings WHERE key = 'orgName'");
        const orgName = orgRes.rows.length > 0 ? orgRes.rows[0].value : '';
        res.json({ success: true, user: { username: user.username, role: user.role }, orgName });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(() => {
        res.json({ success: true });
    });
});

app.get('/api/me', (req, res) => {
    if (!req.session || !req.session.user)
        return res.status(401).json({ success: false, error: 'ยังไม่ได้เข้าสู่ระบบ' });
    res.json({ success: true, user: req.session.user });
});

app.post('/api/change-password', async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        if (!oldPassword || !newPassword)
            return res.status(400).json({ success: false, error: 'กรุณากรอกข้อมูลให้ครบ' });
        if (newPassword.length < 6)
            return res.status(400).json({ success: false, error: 'รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร' });

        const result = await query('SELECT * FROM users WHERE id = $1', [req.session.user.id]);
        if (result.rows.length === 0)
            return res.status(404).json({ success: false, error: 'ไม่พบผู้ใช้' });

        const match = await bcrypt.compare(oldPassword, result.rows[0].password_hash);
        if (!match)
            return res.status(401).json({ success: false, error: 'รหัสผ่านเดิมไม่ถูกต้อง' });

        const newHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
        await query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, req.session.user.id]);
        auditLog({ userId: req.session.user.id, username: req.session.user.username, action: 'PASSWORD_CHANGE', resource: 'users', resourceId: req.session.user.id, ip: getIp(req) });
        res.json({ success: true, message: 'เปลี่ยนรหัสผ่านสำเร็จ' });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================
// API: User Management (Admin only)
// ============================
app.get('/api/users', checkAdmin, async (req, res) => {
    try {
        const result = await query('SELECT id, username, role, created_at FROM users ORDER BY id');
        res.json({ success: true, data: result.rows });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/users', checkAdmin, async (req, res) => {
    const v = validateNewUser(req.body);
    if (!v.ok) return badRequest(res, v.errors);
    try {
        const { username, password, role } = v.cleaned;
        const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
        const result = await query(
            'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id',
            [username, hash, role]
        );
        auditLog({ userId: req.session.user.id, username: req.session.user.username, action: 'USER_CREATE', resource: 'users', resourceId: result.rows[0].id, details: { newUsername: username, role }, ip: getIp(req) });
        res.json({ success: true, id: result.rows[0].id });
    } catch (err) {
        if (err.code === '23505')
            return res.status(400).json({ success: false, error: 'ชื่อผู้ใช้นี้มีอยู่แล้ว' });
        res.status(500).json({ success: false, error: err.message });
    }
});

app.delete('/api/users/:id', checkAdmin, async (req, res) => {
    const vId = validateId(req.params.id);
    if (!vId.ok) return badRequest(res, vId.errors);
    try {
        const targetId = parseInt(req.params.id);
        if (targetId === req.session.user.id)
            return res.status(400).json({ success: false, error: 'ไม่สามารถลบบัญชีตัวเองได้' });

        const targetUser = await query('SELECT role, username FROM users WHERE id = $1', [targetId]);
        if (!targetUser.rows.length)
            return res.status(404).json({ success: false, error: 'ไม่พบผู้ใช้' });

        if (targetUser.rows[0].role === 'admin') {
            const adminCount = await query("SELECT COUNT(*) as cnt FROM users WHERE role = 'admin'");
            if (parseInt(adminCount.rows[0].cnt) <= 1)
                return res.status(400).json({ success: false, error: 'ต้องมีผู้ดูแลระบบอย่างน้อย 1 คน' });
        }

        const deletedUsername = targetUser.rows[0].username || '';
        await query('DELETE FROM users WHERE id = $1', [targetId]);
        auditLog({ userId: req.session.user.id, username: req.session.user.username, action: 'USER_DELETE', resource: 'users', resourceId: targetId, details: { deletedUsername }, ip: getIp(req) });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.put('/api/users/:id/password', checkAdmin, async (req, res) => {
    const vId = validateId(req.params.id);
    if (!vId.ok) return badRequest(res, vId.errors);
    const vPw = validateNewPassword(req.body);
    if (!vPw.ok) return badRequest(res, vPw.errors);
    try {
        const hash = await bcrypt.hash(vPw.cleaned.newPassword, BCRYPT_ROUNDS);
        await query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.params.id]);
        auditLog({ userId: req.session.user.id, username: req.session.user.username, action: 'PASSWORD_CHANGE', resource: 'users', resourceId: req.params.id, details: { changedBy: req.session.user.username }, ip: getIp(req) });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================
// API: Settings
// ============================
app.get('/api/settings', async (req, res) => {
    try {
        const result = await query("SELECT key, value FROM settings");
        const settings = {};
        result.rows.forEach(r => settings[r.key] = r.value);
        res.json({ success: true, data: settings });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.put('/api/settings/:key', async (req, res) => {
    const v = validateSetting(req.params.key, req.body);
    if (!v.ok) return badRequest(res, v.errors);
    try {
        await query(
            `INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2`,
            [req.params.key, v.cleaned.value]
        );
        auditLog({ userId: req.session.user.id, username: req.session.user.username, action: 'SETTINGS_UPDATE', resource: 'settings', resourceId: req.params.key, details: { key: req.params.key, value: v.cleaned.value }, ip: getIp(req) });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================
// API: Categories
// ============================
app.get('/api/categories', async (req, res) => {
    try {
        const result = await query('SELECT code, name FROM categories ORDER BY code');
        res.json({ success: true, data: result.rows });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================
// API: Items (Master)
// ============================
app.get('/api/items', async (req, res) => {
    try {
        const { search, cat, limit, offset } = req.query;
        let sql = 'SELECT * FROM items WHERE 1=1';
        const params = [];
        let paramIdx = 1;

        if (search) {
            sql += ` AND (code ILIKE $${paramIdx} OR name ILIKE $${paramIdx + 1})`;
            params.push(`%${search}%`, `%${search}%`);
            paramIdx += 2;
        }
        if (cat) {
            sql += ` AND cat_code = $${paramIdx}`;
            params.push(cat);
            paramIdx++;
        }
        sql += ' ORDER BY code';
        if (limit) {
            sql += ` LIMIT $${paramIdx}`;
            params.push(parseInt(limit));
            paramIdx++;
            if (offset) {
                sql += ` OFFSET $${paramIdx}`;
                params.push(parseInt(offset));
                paramIdx++;
            }
        }

        const result = await query(sql, params);
        const totalRes = await query('SELECT COUNT(*) as cnt FROM items');
        res.json({ success: true, data: result.rows, total: parseInt(totalRes.rows[0].cnt) });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get('/api/items/:id', async (req, res) => {
    try {
        const result = await query('SELECT * FROM items WHERE id = $1', [req.params.id]);
        if (result.rows.length === 0) return res.status(404).json({ success: false, error: 'ไม่พบวัสดุ' });
        res.json({ success: true, data: result.rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/items', async (req, res) => {
    const v = validateItem(req.body);
    if (!v.ok) return badRequest(res, v.errors);
    try {
        const { code, name, spec, cat_code, cat_name, unit, min_qty, location, last_price } = v.cleaned;
        const result = await query(
            `INSERT INTO items (code, name, spec, cat_code, cat_name, unit, min_qty, location, last_price)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
            [code, name, spec || '-', cat_code, cat_name, unit, min_qty, location, last_price]
        );
        auditLog({ userId: req.session.user.id, username: req.session.user.username, action: 'ITEM_CREATE', resource: 'items', resourceId: result.rows[0].id, details: { code, name }, ip: getIp(req) });
        res.json({ success: true, id: result.rows[0].id });
    } catch (err) {
        if (err.code === '23505')
            return res.status(400).json({ success: false, error: 'รหัสวัสดุนี้มีอยู่แล้ว' });
        res.status(500).json({ success: false, error: err.message });
    }
});

app.put('/api/items/:id', async (req, res) => {
    const vId = validateId(req.params.id);
    if (!vId.ok) return badRequest(res, vId.errors);
    const v = validateItem(req.body);
    if (!v.ok) return badRequest(res, v.errors);
    try {
        const { code, name, spec, cat_code, cat_name, unit, min_qty, location, last_price } = v.cleaned;
        await query(
            `UPDATE items SET code=$1, name=$2, spec=$3, cat_code=$4, cat_name=$5, unit=$6, min_qty=$7, location=$8, last_price=$9, updated_at=NOW()
             WHERE id=$10`,
            [code, name, spec, cat_code, cat_name, unit, min_qty, location, last_price, req.params.id]
        );
        auditLog({ userId: req.session.user.id, username: req.session.user.username, action: 'ITEM_UPDATE', resource: 'items', resourceId: req.params.id, details: { code, name }, ip: getIp(req) });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.delete('/api/items/:id', async (req, res) => {
    const vId = validateId(req.params.id);
    if (!vId.ok) return badRequest(res, vId.errors);
    try {
        const used = await query('SELECT COUNT(*) as cnt FROM transaction_lines WHERE item_id = $1', [req.params.id]);
        if (parseInt(used.rows[0].cnt) > 0)
            return res.status(400).json({ success: false, error: 'ไม่สามารถลบได้ มีรายการเอกสารอ้างอิง' });
        await query('DELETE FROM items WHERE id = $1', [req.params.id]);
        auditLog({ userId: req.session.user.id, username: req.session.user.username, action: 'ITEM_DELETE', resource: 'items', resourceId: req.params.id, ip: getIp(req) });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================
// API: Balance (คงเหลือ)
// ============================
app.get('/api/balance/:itemId', async (req, res) => {
    try {
        const { dateLimit } = req.query;
        let sql = `
            SELECT COALESCE(SUM(CASE WHEN t.type='IN' THEN tl.qty ELSE 0 END), 0) -
                   COALESCE(SUM(CASE WHEN t.type='OUT' THEN tl.qty ELSE 0 END), 0) as balance
            FROM transaction_lines tl
            JOIN transactions t ON t.id = tl.tx_id
            WHERE tl.item_id = $1
        `;
        const params = [req.params.itemId];
        if (dateLimit) { sql += ' AND t.date <= $2'; params.push(dateLimit); }
        const result = await query(sql, params);
        res.json({ success: true, balance: parseFloat(result.rows[0].balance) });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get('/api/balance-all', async (req, res) => {
    try {
        const { dateLimit } = req.query;
        let sql = `
            SELECT tl.item_id,
                   COALESCE(SUM(CASE WHEN t.type='IN' THEN tl.qty ELSE 0 END), 0) -
                   COALESCE(SUM(CASE WHEN t.type='OUT' THEN tl.qty ELSE 0 END), 0) as balance
            FROM transaction_lines tl
            JOIN transactions t ON t.id = tl.tx_id
        `;
        const params = [];
        if (dateLimit) { sql += ' WHERE t.date <= $1'; params.push(dateLimit); }
        sql += ' GROUP BY tl.item_id';
        const result = await query(sql, params);
        const balMap = {};
        result.rows.forEach(r => balMap[r.item_id] = parseFloat(r.balance));
        res.json({ success: true, data: balMap });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================
// API: Transactions
// ============================
app.get('/api/transactions', async (req, res) => {
    try {
        const { limit, type } = req.query;
        let sql = 'SELECT * FROM transactions WHERE 1=1';
        const params = [];
        let paramIdx = 1;
        if (type) { sql += ` AND type = $${paramIdx}`; params.push(type); paramIdx++; }
        sql += ' ORDER BY id DESC';
        if (limit) { sql += ` LIMIT $${paramIdx}`; params.push(parseInt(limit)); paramIdx++; }

        const result = await query(sql, params);
        for (const tx of result.rows) {
            const lines = await query('SELECT * FROM transaction_lines WHERE tx_id = $1', [tx.id]);
            tx.lines = lines.rows;
        }
        res.json({ success: true, data: result.rows });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get('/api/transactions/:id', async (req, res) => {
    try {
        const txRes = await query('SELECT * FROM transactions WHERE id = $1', [req.params.id]);
        if (txRes.rows.length === 0) return res.status(404).json({ success: false, error: 'ไม่พบเอกสาร' });
        const tx = txRes.rows[0];
        const lines = await query('SELECT * FROM transaction_lines WHERE tx_id = $1', [tx.id]);
        tx.lines = lines.rows;
        res.json({ success: true, data: tx });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/transactions', async (req, res) => {
    const v = validateTransaction(req.body);
    if (!v.ok) return badRequest(res, v.errors);
    const client = await pool.connect();
    try {
        const { date, type, doc_no, ref, note, user_name, approver, checker, lines } = v.cleaned;
        await client.query('BEGIN');
        const txResult = await client.query(
            `INSERT INTO transactions (date, type, doc_no, ref, note, user_name, approver, checker)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
            [date, type, doc_no, ref, note, user_name, approver, checker]
        );
        const txId = txResult.rows[0].id;
        for (const line of lines) {
            const itemId = line.itemId || line.item_id;
            await client.query(
                `INSERT INTO transaction_lines (tx_id, item_id, code, name, spec, unit, qty, price)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                [txId, itemId, line.code, line.name, line.spec || '-', line.unit, line.qty, line.price || 0]
            );
            if (type === 'IN' && line.price > 0) {
                await client.query(
                    'UPDATE items SET last_price = $1, updated_at = NOW() WHERE id = $2',
                    [line.price, itemId]
                );
            }
        }
        await client.query('COMMIT');
        auditLog({ userId: req.session.user.id, username: req.session.user.username, action: 'TRANSACTION_CREATE', resource: 'transactions', resourceId: txId, details: { type, doc_no, lineCount: lines.length }, ip: getIp(req) });
        res.json({ success: true, id: txId });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ success: false, error: err.message });
    } finally {
        client.release();
    }
});

app.delete('/api/transactions/:id', async (req, res) => {
    const vId = validateId(req.params.id);
    if (!vId.ok) return badRequest(res, vId.errors);
    try {
        await query('DELETE FROM transaction_lines WHERE tx_id = $1', [req.params.id]);
        await query('DELETE FROM transactions WHERE id = $1', [req.params.id]);
        auditLog({ userId: req.session.user.id, username: req.session.user.username, action: 'TRANSACTION_DELETE', resource: 'transactions', resourceId: req.params.id, ip: getIp(req) });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================
// API: Dashboard
// ============================
app.get('/api/dashboard', async (req, res) => {
    try {
        const totalRes = await query('SELECT COUNT(*) as cnt FROM items');
        const totalItems = parseInt(totalRes.rows[0].cnt);

        const balResult = await query(`
            SELECT i.id, i.name, i.cat_name, i.last_price, i.min_qty,
                   COALESCE(SUM(CASE WHEN t.type='IN' THEN tl.qty ELSE 0 END), 0) -
                   COALESCE(SUM(CASE WHEN t.type='OUT' THEN tl.qty ELSE 0 END), 0) as balance
            FROM items i
            LEFT JOIN transaction_lines tl ON tl.item_id = i.id
            LEFT JOIN transactions t ON t.id = tl.tx_id
            GROUP BY i.id, i.name, i.cat_name, i.last_price, i.min_qty
        `);

        let totalValue = 0, lowStock = [], catValue = {};
        balResult.rows.forEach(row => {
            const bal = parseFloat(row.balance);
            const val = bal * row.last_price;
            totalValue += val;
            catValue[row.cat_name] = (catValue[row.cat_name] || 0) + val;
            if (bal <= row.min_qty) lowStock.push({ name: row.name, balance: bal, min: row.min_qty });
        });

        const now = new Date();
        const month = now.getMonth() + 1;
        const fyStart = month >= 10 ? `${now.getFullYear()}-10-01` : `${now.getFullYear() - 1}-10-01`;
        const docsRes = await query('SELECT COUNT(*) as cnt FROM transactions WHERE date >= $1', [fyStart]);
        const docsThisYear = parseInt(docsRes.rows[0].cnt);

        res.json({ success: true, data: { totalItems, totalValue, lowStock, docsThisYear, catValue } });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================
// API: Report
// ============================
app.get('/api/report', async (req, res) => {
    try {
        const { dateLimit, cat } = req.query;
        let itemSql = 'SELECT * FROM items WHERE 1=1';
        const itemParams = [];
        let paramIdx = 1;
        if (cat) { itemSql += ` AND cat_code = $${paramIdx}`; itemParams.push(cat); paramIdx++; }
        itemSql += ' ORDER BY cat_code, code';

        const itemsRes = await query(itemSql, itemParams);
        let balSql = `
            SELECT tl.item_id,
                   COALESCE(SUM(CASE WHEN t.type='IN' THEN tl.qty ELSE 0 END), 0) -
                   COALESCE(SUM(CASE WHEN t.type='OUT' THEN tl.qty ELSE 0 END), 0) as balance
            FROM transaction_lines tl
            JOIN transactions t ON t.id = tl.tx_id
        `;
        const balParams = [];
        if (dateLimit) { balSql += ' WHERE t.date <= $1'; balParams.push(dateLimit); }
        balSql += ' GROUP BY tl.item_id';

        const balRes = await query(balSql, balParams);
        const balMap = {};
        balRes.rows.forEach(r => balMap[r.item_id] = parseFloat(r.balance));

        const report = itemsRes.rows.map(i => ({
            ...i,
            balance: balMap[i.id] || 0,
            total_value: (balMap[i.id] || 0) * i.last_price
        })).filter(i => i.balance > 0);

        res.json({ success: true, data: report });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================
// API: Stock Card
// ============================
app.get('/api/stockcard/:itemId', async (req, res) => {
    try {
        const itemRes = await query('SELECT * FROM items WHERE id = $1', [req.params.itemId]);
        if (itemRes.rows.length === 0) return res.status(404).json({ success: false, error: 'ไม่พบวัสดุ' });
        const item = itemRes.rows[0];

        const txRes = await query(`
            SELECT t.date, t.type, t.doc_no, t.ref, t.note, tl.qty, tl.price
            FROM transaction_lines tl
            JOIN transactions t ON t.id = tl.tx_id
            WHERE tl.item_id = $1
            ORDER BY t.date, t.id
        `, [req.params.itemId]);

        let balance = 0;
        const movements = txRes.rows.map(row => {
            if (row.type === 'IN') balance += parseFloat(row.qty);
            else balance -= parseFloat(row.qty);
            return { ...row, qty: parseFloat(row.qty), price: parseFloat(row.price), balance };
        });

        res.json({ success: true, item, movements });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================
// API: Doc Number Generation
// ============================
app.get('/api/next-docno', async (req, res) => {
    try {
        const { type, date } = req.query;
        const d = new Date(date);
        const year = d.getFullYear();
        const month = d.getMonth() + 1;
        const fy = (month >= 10) ? year + 1 : year;
        const budgetYear = fy + 543;
        const fyShort = String(budgetYear).slice(-2);

        const fyStart = month >= 10 ? `${year}-10-01` : `${year - 1}-10-01`;
        const fyEnd = month >= 10 ? `${year + 1}-09-30` : `${year}-09-30`;

        const countRes = await query(
            'SELECT COUNT(*) as cnt FROM transactions WHERE type = $1 AND date >= $2 AND date <= $3',
            [type, fyStart, fyEnd]
        );
        const count = parseInt(countRes.rows[0].cnt) + 1;
        const run = String(count).padStart(4, '0');
        res.json({ success: true, docNo: `${type}-${run}/${fyShort}` });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================
// API: Backup / Restore / Reset (Admin only)
// ============================
app.get('/api/backup', checkAdmin, async (req, res) => {
    try {
        const [settings, items, transactions, txLines] = await Promise.all([
            query('SELECT * FROM settings'),
            query('SELECT * FROM items'),
            query('SELECT * FROM transactions'),
            query('SELECT * FROM transaction_lines')
        ]);
        const payload = {
            settings: settings.rows,
            items: items.rows,
            transactions: transactions.rows,
            transaction_lines: txLines.rows,
            exportDate: new Date().toISOString(),
            version: 'PG_V1'
        };
        auditLog({ userId: req.session.user.id, username: req.session.user.username, action: 'DATA_BACKUP', resource: 'backup', details: { itemCount: items.rows.length, txCount: transactions.rows.length }, ip: getIp(req) });
        res.json({ success: true, data: payload });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/restore', checkAdmin, async (req, res) => {
    const v = validateRestore(req.body);
    if (!v.ok) return badRequest(res, v.errors);
    const client = await pool.connect();
    try {
        const { data } = req.body;

        // Auto-backup ข้อมูลปัจจุบันก่อน restore
        const [bkSettings, bkItems, bkTx, bkLines] = await Promise.all([
            query('SELECT * FROM settings'),
            query('SELECT * FROM items'),
            query('SELECT * FROM transactions'),
            query('SELECT * FROM transaction_lines'),
        ]);
        const autoBackup = {
            settings: bkSettings.rows,
            items: bkItems.rows,
            transactions: bkTx.rows,
            transaction_lines: bkLines.rows,
            exportDate: new Date().toISOString(),
            version: 'PG_V1',
        };

        await client.query('BEGIN');
        await client.query('DELETE FROM transaction_lines');
        await client.query('DELETE FROM transactions');
        await client.query('DELETE FROM items');
        await client.query('DELETE FROM settings');

        for (const s of data.settings) {
            await client.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [s.key, s.value]);
        }
        for (const i of data.items) {
            await client.query(
                `INSERT INTO items (id, code, name, spec, cat_code, cat_name, unit, min_qty, location, last_price)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
                [i.id, i.code, i.name, i.spec, i.cat_code, i.cat_name, i.unit, i.min_qty, i.location, i.last_price]
            );
        }
        await client.query(`SELECT setval('items_id_seq', (SELECT COALESCE(MAX(id),0) FROM items))`);

        for (const t of data.transactions) {
            await client.query(
                `INSERT INTO transactions (id, date, type, doc_no, ref, note, user_name, approver, checker)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
                [t.id, t.date, t.type, t.doc_no, t.ref, t.note, t.user_name, t.approver, t.checker]
            );
        }
        await client.query(`SELECT setval('transactions_id_seq', (SELECT COALESCE(MAX(id),0) FROM transactions))`);

        for (const l of data.transaction_lines) {
            await client.query(
                `INSERT INTO transaction_lines (id, tx_id, item_id, code, name, spec, unit, qty, price)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
                [l.id, l.tx_id, l.item_id, l.code, l.name, l.spec, l.unit, l.qty, l.price]
            );
        }
        await client.query(`SELECT setval('transaction_lines_id_seq', (SELECT COALESCE(MAX(id),0) FROM transaction_lines))`);

        await client.query('COMMIT');
        auditLog({ userId: req.session.user.id, username: req.session.user.username, action: 'DATA_RESTORE', resource: 'restore', details: { version: data.version, itemCount: data.items.length }, ip: getIp(req) });
        res.json({ success: true, message: 'นำเข้าข้อมูลสำเร็จ', autoBackup });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ success: false, error: err.message });
    } finally {
        client.release();
    }
});

// ============================
// API: Audit Logs (Admin only)
// ============================
app.get('/api/audit-logs', checkAdmin, async (req, res) => {
    try {
        const page   = Math.max(1, parseInt(req.query.page  || '1'));
        const limit  = Math.min(100, Math.max(1, parseInt(req.query.limit || '50')));
        const offset = (page - 1) * limit;
        const action = req.query.action ? String(req.query.action).trim() : '';
        const dateFrom = req.query.dateFrom || '';
        const dateTo   = req.query.dateTo   || '';

        const params = [];
        let where = 'WHERE 1=1';
        let idx = 1;
        if (action) { where += ` AND action = $${idx++}`; params.push(action); }
        if (dateFrom) { where += ` AND timestamp >= $${idx++}`; params.push(dateFrom); }
        if (dateTo)   { where += ` AND timestamp <= $${idx++}`; params.push(dateTo + 'T23:59:59'); }

        const countRes = await query(`SELECT COUNT(*) as cnt FROM audit_logs ${where}`, params);
        const total = parseInt(countRes.rows[0].cnt);

        const rows = await query(
            `SELECT * FROM audit_logs ${where} ORDER BY timestamp DESC LIMIT $${idx++} OFFSET $${idx++}`,
            [...params, limit, offset]
        );

        res.json({ success: true, data: rows.rows, total, page, limit, pages: Math.ceil(total / limit) });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/reset', checkAdmin, async (req, res) => {
    if (req.body.confirm_text !== 'ยืนยันการลบ')
        return res.status(400).json({ success: false, error: 'กรุณาพิมพ์ "ยืนยันการลบ" เพื่อยืนยันการดำเนินการ' });
    try {
        await query('DELETE FROM transaction_lines');
        await query('DELETE FROM transactions');
        auditLog({ userId: req.session.user.id, username: req.session.user.username, action: 'DATA_RESET', resource: 'transactions', ip: getIp(req) });
        res.json({ success: true, message: 'ล้างเอกสารทั้งหมดสำเร็จ' });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================
// API: Keep-Alive (ต่ออายุ session)
// ============================
app.post('/api/keep-alive', (req, res) => {
    // checkAuth ได้รันแล้วจาก middleware; เรียก request นี้ก็เพียงพอสำหรับ rolling session
    res.json({ success: true, expiresIn: 30 * 60 * 1000 });
});

// ============================
// AUTO-INIT
// ============================
async function autoInit() {
    try {
        const check = await pool.query(`SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'items')`);
        if (!check.rows[0].exists) {
            console.log('📦 ไม่พบตาราง — กำลัง init ฐานข้อมูล...');
            const { initDB } = require('./init-db');
            await initDB();
            console.log('✅ Init ฐานข้อมูลสำเร็จ');
        } else {
            const cnt = await pool.query('SELECT COUNT(*) as cnt FROM items');
            console.log(`📦 ฐานข้อมูลพร้อม: ${cnt.rows[0].cnt} รายการวัสดุ`);
        }

        // ตรวจสอบและ seed ผู้ใช้เริ่มต้น
        const userTableCheck = await pool.query(`SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'users')`);
        if (!userTableCheck.rows[0].exists) {
            await pool.query(`
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin','user')),
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            `);
            console.log('✅ สร้างตาราง users สำเร็จ');
        }

        const userCheck = await pool.query('SELECT COUNT(*) as cnt FROM users');
        if (parseInt(userCheck.rows[0].cnt) === 0) {
            const adminHash = await bcrypt.hash('admin123', BCRYPT_ROUNDS);
            const userHash = await bcrypt.hash('user123', BCRYPT_ROUNDS);
            await pool.query(
                'INSERT INTO users (username, password_hash, role) VALUES ($1,$2,$3)',
                ['admin', adminHash, 'admin']
            );
            await pool.query(
                'INSERT INTO users (username, password_hash, role) VALUES ($1,$2,$3)',
                ['user', userHash, 'user']
            );
            console.log('🔑 สร้างผู้ใช้เริ่มต้น: admin/admin123, user/user123');
        }

        // ตรวจและสร้างตาราง audit_logs ถ้ายังไม่มี (upgrade เซิร์ฟเวอร์เก่า)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ DEFAULT NOW() NOT NULL,
                user_id INTEGER,
                username TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL,
                resource TEXT NOT NULL DEFAULT '',
                resource_id TEXT,
                details JSONB,
                ip_address TEXT
            )
        `);
        await pool.query('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC)');
        await pool.query('CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action)');
        await pool.query('CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id)');

        // Seed default orgName
        await pool.query(
            "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING",
            ['orgName', 'องค์การบริหารส่วนตำบลตัวอย่าง']
        );
    } catch (err) {
        console.error('❌ Auto-init error:', err.message);
    }
}

// ============================
// Serve Frontend
// ============================
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================
// Start Server
// ============================
autoInit().then(() => {
    app.listen(PORT, '0.0.0.0', () => {
        console.log('');
        console.log('╔══════════════════════════════════════════════════╗');
        console.log('║  🏛️  ระบบบัญชีคุมวัสดุ อปท. (PostgreSQL Edition) ║');
        console.log('╠══════════════════════════════════════════════════╣');
        console.log(`║  🌐 http://localhost:${PORT}                         ║`);
        console.log('║  📦 ฐานข้อมูล: PostgreSQL                        ║');
        console.log('║  🔐 Authentication: bcrypt + express-session      ║');
        console.log('║  🚀 Railway Ready                                ║');
        console.log('╚══════════════════════════════════════════════════╝');
        console.log('');
    });
});

process.on('SIGINT', async () => {
    console.log('\n🛑 กำลังปิดเซิร์ฟเวอร์...');
    await pool.end();
    process.exit(0);
});
