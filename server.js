/**
 * server.js - Backend API สำหรับระบบบัญชีคุมวัสดุ อปท.
 * ใช้ Express + PostgreSQL (pg)
 * 
 * สำหรับ Railway: ตั้ง DATABASE_URL อัตโนมัติจาก PostgreSQL Plugin
 * สำหรับ Local: สร้างไฟล์ .env ตาม .env.example
 */
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

// ===== Password Hash Helper =====
function hashPassword(pwd) {
    return crypto.createHash('sha256').update(pwd).digest('hex');
}

const app = express();
const PORT = process.env.PORT || 3000;

// ===== PostgreSQL Connection Pool =====
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' || (process.env.DATABASE_URL && process.env.DATABASE_URL.includes('railway'))
        ? { rejectUnauthorized: false }
        : false,
    max: 20,
    idleTimeoutMillis: 30000
});

// ทดสอบเชื่อมต่อ
pool.query('SELECT NOW()')
    .then(() => console.log('✅ เชื่อมต่อ PostgreSQL สำเร็จ'))
    .catch(err => { console.error('❌ เชื่อมต่อ PostgreSQL ไม่ได้:', err.message); process.exit(1); });

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Helper: query shortcut
async function query(sql, params = []) {
    const res = await pool.query(sql, params);
    return res;
}

// ============================
// AUTO-INIT: สร้างตารางอัตโนมัติเมื่อ deploy ครั้งแรก
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
        // Seed default password if not exists
        const pwCheck = await pool.query("SELECT value FROM settings WHERE key = 'password'");
        if (pwCheck.rows.length === 0) {
            await pool.query("INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING", ['password', hashPassword('1234')]);
            console.log('🔑 ตั้งรหัสผ่านเริ่มต้น: 1234');
        }
        // Seed default orgName
        await pool.query("INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING", ['orgName', 'ศูนย์พัฒนาเด็กองค์การบริหารส่วนตำบลเขิน1']);
    } catch (err) {
        console.error('❌ Auto-init error:', err.message);
    }
}

// ============================
// API: Settings
// ============================
app.get('/api/settings', async (req, res) => {
    try {
        const result = await query("SELECT key, value FROM settings WHERE key NOT IN ('password', 'auth_token')");
        const settings = {};
        result.rows.forEach(r => settings[r.key] = r.value);
        res.json({ success: true, data: settings });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.put('/api/settings/:key', async (req, res) => {
    try {
        const { key } = req.params;
        const { value } = req.body;
        await query(
            `INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2`,
            [key, value]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================
// API: Login / Auth
// ============================
app.post('/api/login', async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ success: false, error: 'กรุณาใส่รหัสผ่าน' });
        
        const result = await query("SELECT value FROM settings WHERE key = 'password'");
        const storedHash = result.rows.length > 0 ? result.rows[0].value : hashPassword('1234');
        
        if (hashPassword(password) === storedHash) {
            // สร้าง token ง่ายๆ
            const token = crypto.randomBytes(32).toString('hex');
            // เก็บ token ใน settings (ง่ายสำหรับระบบเล็ก)
            await query("INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2", ['auth_token', token]);
            
            // ดึงชื่อหน่วยงาน
            const orgRes = await query("SELECT value FROM settings WHERE key = 'orgName'");
            const orgName = orgRes.rows.length > 0 ? orgRes.rows[0].value : '';
            
            res.json({ success: true, token, orgName });
        } else {
            res.status(401).json({ success: false, error: 'รหัสผ่านไม่ถูกต้อง' });
        }
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/change-password', async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        if (!oldPassword || !newPassword) return res.status(400).json({ success: false, error: 'กรุณากรอกข้อมูลให้ครบ' });
        if (newPassword.length < 4) return res.status(400).json({ success: false, error: 'รหัสผ่านต้องมีอย่างน้อย 4 ตัว' });
        
        const result = await query("SELECT value FROM settings WHERE key = 'password'");
        const storedHash = result.rows.length > 0 ? result.rows[0].value : hashPassword('1234');
        
        if (hashPassword(oldPassword) !== storedHash) {
            return res.status(401).json({ success: false, error: 'รหัสผ่านเดิมไม่ถูกต้อง' });
        }
        
        await query("INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2", ['password', hashPassword(newPassword)]);
        res.json({ success: true, message: 'เปลี่ยนรหัสผ่านสำเร็จ' });
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
    try {
        const { code, name, spec, cat_code, cat_name, unit, min_qty, location, last_price } = req.body;
        const result = await query(
            `INSERT INTO items (code, name, spec, cat_code, cat_name, unit, min_qty, location, last_price)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
            [code, name, spec || '-', cat_code, cat_name, unit, min_qty || 5, location || 'กองพัสดุ', last_price || 0]
        );
        res.json({ success: true, id: result.rows[0].id });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.put('/api/items/:id', async (req, res) => {
    try {
        const { code, name, spec, cat_code, cat_name, unit, min_qty, location, last_price } = req.body;
        await query(
            `UPDATE items SET code=$1, name=$2, spec=$3, cat_code=$4, cat_name=$5, unit=$6, min_qty=$7, location=$8, last_price=$9, updated_at=NOW()
             WHERE id=$10`,
            [code, name, spec, cat_code, cat_name, unit, min_qty, location, last_price, req.params.id]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.delete('/api/items/:id', async (req, res) => {
    try {
        const used = await query('SELECT COUNT(*) as cnt FROM transaction_lines WHERE item_id = $1', [req.params.id]);
        if (parseInt(used.rows[0].cnt) > 0) {
            return res.status(400).json({ success: false, error: 'ไม่สามารถลบได้ มีรายการเอกสารอ้างอิง' });
        }
        await query('DELETE FROM items WHERE id = $1', [req.params.id]);
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
        if (dateLimit) {
            sql += ' AND t.date <= $2';
            params.push(dateLimit);
        }
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
        if (dateLimit) {
            sql += ' WHERE t.date <= $1';
            params.push(dateLimit);
        }
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
        // แนบ lines
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
    const client = await pool.connect();
    try {
        const { date, type, doc_no, ref, note, user_name, approver, checker, lines } = req.body;
        
        await client.query('BEGIN');
        
        // บันทึก header
        const txResult = await client.query(
            `INSERT INTO transactions (date, type, doc_no, ref, note, user_name, approver, checker)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
            [date, type, doc_no, ref || '', note || '', user_name || '', approver || '', checker || '']
        );
        const txId = txResult.rows[0].id;
        
        // บันทึก lines
        for (const line of lines) {
            const itemId = line.itemId || line.item_id;
            await client.query(
                `INSERT INTO transaction_lines (tx_id, item_id, code, name, spec, unit, qty, price)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                [txId, itemId, line.code, line.name, line.spec || '-', line.unit, line.qty, line.price || 0]
            );
            
            // อัพเดทราคาล่าสุดถ้าเป็นรับเข้า
            if (type === 'IN' && line.price > 0) {
                await client.query(
                    'UPDATE items SET last_price = $1, updated_at = NOW() WHERE id = $2',
                    [line.price, itemId]
                );
            }
        }
        
        await client.query('COMMIT');
        res.json({ success: true, id: txId });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ success: false, error: err.message });
    } finally {
        client.release();
    }
});

app.delete('/api/transactions/:id', async (req, res) => {
    try {
        await query('DELETE FROM transaction_lines WHERE tx_id = $1', [req.params.id]);
        await query('DELETE FROM transactions WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================
// API: Dashboard Summary
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
        
        let totalValue = 0;
        let lowStock = [];
        let catValue = {};
        
        balResult.rows.forEach(row => {
            const bal = parseFloat(row.balance);
            const val = bal * row.last_price;
            totalValue += val;
            catValue[row.cat_name] = (catValue[row.cat_name] || 0) + val;
            if (bal <= row.min_qty) {
                lowStock.push({ name: row.name, balance: bal, min: row.min_qty });
            }
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
// API: Backup / Restore
// ============================
app.get('/api/backup', async (req, res) => {
    try {
        const [settings, items, transactions, txLines] = await Promise.all([
            query('SELECT * FROM settings'),
            query('SELECT * FROM items'),
            query('SELECT * FROM transactions'),
            query('SELECT * FROM transaction_lines')
        ]);
        res.json({
            success: true,
            data: {
                settings: settings.rows,
                items: items.rows,
                transactions: transactions.rows,
                transaction_lines: txLines.rows,
                exportDate: new Date().toISOString(),
                version: 'PG_V1'
            }
        });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/restore', async (req, res) => {
    const client = await pool.connect();
    try {
        const { data } = req.body;
        if (!data || !data.version) {
            return res.status(400).json({ success: false, error: 'รูปแบบข้อมูลไม่ถูกต้อง' });
        }
        
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
        // Reset sequence
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
        res.json({ success: true, message: 'นำเข้าข้อมูลสำเร็จ' });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ success: false, error: err.message });
    } finally {
        client.release();
    }
});

// ============================
// API: Reset
// ============================
app.post('/api/reset', async (req, res) => {
    try {
        await query('DELETE FROM transaction_lines');
        await query('DELETE FROM transactions');
        res.json({ success: true, message: 'ล้างเอกสารทั้งหมดสำเร็จ' });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================
// Serve Frontend
// ============================
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
