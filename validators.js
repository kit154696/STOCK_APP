/**
 * validators.js — Input validation สำหรับทุก API endpoint
 *
 * แต่ละ validator คืน { ok: boolean, errors: string[] }
 * ถ้า ok = false ให้ส่ง 400 + errors กลับ client
 */

// ============================================================
// Helpers
// ============================================================

/**
 * ลบ HTML tags และ trim whitespace เพื่อป้องกัน XSS
 * ใช้กับทุก string field ก่อน insert/update
 */
function sanitize(value) {
    if (typeof value !== 'string') return value;
    return value
        .replace(/<[^>]*>/g, '')   // strip HTML tags
        .trim();
}

/** sanitize object ทุก field พร้อมกัน */
function sanitizeAll(obj) {
    const result = {};
    for (const [k, v] of Object.entries(obj)) {
        result[k] = typeof v === 'string' ? sanitize(v) : v;
    }
    return result;
}

/** ตรวจว่า val เป็น integer บวก (สำหรับ :id param) */
function isPositiveInt(val) {
    const n = Number(val);
    return Number.isInteger(n) && n > 0;
}

/** ตรวจรูปแบบ YYYY-MM-DD และเป็นวันที่จริง */
function isValidDate(str) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(str)) return false;
    const d = new Date(str);
    return d instanceof Date && !isNaN(d.getTime());
}

/** รวม errors แล้วคืน result */
function fail(...msgs) {
    return { ok: false, errors: msgs.flat() };
}
function pass() {
    return { ok: true, errors: [] };
}

// ============================================================
// ID param validator (ใช้กับทุก DELETE และ PUT /:id)
// ============================================================
function validateId(id) {
    if (!isPositiveInt(id))
        return fail('ID ต้องเป็นตัวเลขจำนวนเต็มที่มากกว่า 0');
    return pass();
}

// ============================================================
// Items
// ============================================================

// รหัสหมวดหมู่ที่ถูกต้อง (ตรงกับ init-db.js)
const VALID_CAT_CODES = new Set([
    'A0000','B0000','C0000','D0000','E0000','F0000','G0000',
    'H0000','I0000','J0000','K0000','L0000','M0000','N0000',
    'O0000','P0000','Q0000',
]);

/**
 * ตรวจสอบ payload สำหรับ POST/PUT /api/items
 * คืน { ok, errors, cleaned } — cleaned คือ object ที่ผ่าน sanitize แล้ว
 */
function validateItem(body) {
    const errors = [];
    const b = sanitizeAll({
        code:       body.code       ?? '',
        name:       body.name       ?? '',
        spec:       body.spec       ?? '-',
        cat_code:   body.cat_code   ?? '',
        cat_name:   body.cat_name   ?? '',
        unit:       body.unit       ?? '',
        location:   body.location   ?? 'กองพัสดุ',
    });

    if (!b.code)
        errors.push('รหัสวัสดุ (code) ต้องไม่ว่าง');
    else if (b.code.length > 20)
        errors.push('รหัสวัสดุ (code) ต้องไม่เกิน 20 ตัวอักษร');

    if (!b.name)
        errors.push('ชื่อวัสดุ (name) ต้องไม่ว่าง');
    else if (b.name.length > 200)
        errors.push('ชื่อวัสดุ (name) ต้องไม่เกิน 200 ตัวอักษร');

    if (!b.cat_code)
        errors.push('ประเภทวัสดุ (cat_code) ต้องไม่ว่าง');
    else if (!VALID_CAT_CODES.has(b.cat_code))
        errors.push(`ประเภทวัสดุ (cat_code) "${b.cat_code}" ไม่ถูกต้อง ต้องเป็นหนึ่งใน: ${[...VALID_CAT_CODES].join(', ')}`);

    if (!b.unit)
        errors.push('หน่วยนับ (unit) ต้องไม่ว่าง');

    const minQty = body.min_qty !== undefined && body.min_qty !== '' ? Number(body.min_qty) : 0;
    if (isNaN(minQty) || !Number.isFinite(minQty) || minQty < 0)
        errors.push('จำนวนขั้นต่ำ (min_qty) ต้องเป็นตัวเลข >= 0');

    const lastPrice = body.last_price !== undefined && body.last_price !== '' ? Number(body.last_price) : 0;
    if (isNaN(lastPrice) || lastPrice < 0)
        errors.push('ราคาล่าสุด (last_price) ต้องเป็นตัวเลข >= 0');

    if (errors.length) return { ok: false, errors };

    return {
        ok: true,
        errors: [],
        cleaned: {
            ...b,
            min_qty:    minQty,
            last_price: lastPrice,
        },
    };
}

// ============================================================
// Transactions
// ============================================================

/**
 * ตรวจสอบ payload สำหรับ POST /api/transactions
 * คืน { ok, errors, cleaned }
 */
function validateTransaction(body) {
    const errors = [];

    // --- date ---
    const date = sanitize(String(body.date ?? ''));
    if (!date)
        errors.push('วันที่เอกสาร (date) ต้องไม่ว่าง');
    else if (!isValidDate(date))
        errors.push('วันที่เอกสาร (date) ต้องอยู่ในรูปแบบ YYYY-MM-DD และเป็นวันที่ที่ถูกต้อง');

    // --- type ---
    const type = sanitize(String(body.type ?? ''));
    if (!['IN', 'OUT'].includes(type))
        errors.push('ประเภทเอกสาร (type) ต้องเป็น "IN" (รับเข้า) หรือ "OUT" (เบิกจ่าย) เท่านั้น');

    // --- doc_no ---
    const doc_no = sanitize(String(body.doc_no ?? ''));
    if (!doc_no)
        errors.push('เลขที่เอกสาร (doc_no) ต้องไม่ว่าง');
    else if (doc_no.length > 50)
        errors.push('เลขที่เอกสาร (doc_no) ต้องไม่เกิน 50 ตัวอักษร');

    // --- lines ---
    if (!Array.isArray(body.lines) || body.lines.length === 0)
        errors.push('รายการวัสดุ (lines) ต้องมีอย่างน้อย 1 รายการ');
    else {
        body.lines.forEach((line, i) => {
            const num = i + 1;
            const itemId = line.itemId ?? line.item_id;
            if (!isPositiveInt(itemId))
                errors.push(`รายการที่ ${num}: item_id ต้องเป็นตัวเลขจำนวนเต็มที่ > 0`);

            const qty = Number(line.qty);
            if (isNaN(qty) || qty <= 0)
                errors.push(`รายการที่ ${num}: จำนวน (qty) ต้องมากกว่า 0`);

            const price = Number(line.price ?? 0);
            if (isNaN(price) || price < 0)
                errors.push(`รายการที่ ${num}: ราคา (price) ต้องเป็นตัวเลข >= 0`);

            if (!line.code)
                errors.push(`รายการที่ ${num}: รหัสวัสดุ (code) ต้องไม่ว่าง`);
            if (!line.name)
                errors.push(`รายการที่ ${num}: ชื่อวัสดุ (name) ต้องไม่ว่าง`);
        });
    }

    if (errors.length) return { ok: false, errors };

    // sanitize optional text fields
    return {
        ok: true,
        errors: [],
        cleaned: {
            date,
            type,
            doc_no,
            ref:        sanitize(String(body.ref        ?? '')).slice(0, 200),
            note:       sanitize(String(body.note       ?? '')).slice(0, 500),
            user_name:  sanitize(String(body.user_name  ?? '')).slice(0, 100),
            approver:   sanitize(String(body.approver   ?? '')).slice(0, 100),
            checker:    sanitize(String(body.checker    ?? '')).slice(0, 100),
            lines: body.lines.map(line => ({
                itemId:  line.itemId ?? line.item_id,
                code:    sanitize(String(line.code  ?? '')),
                name:    sanitize(String(line.name  ?? '')),
                spec:    sanitize(String(line.spec  ?? '-')).slice(0, 200),
                unit:    sanitize(String(line.unit  ?? '')).slice(0, 50),
                qty:     Number(line.qty),
                price:   Number(line.price ?? 0),
            })),
        },
    };
}

// ============================================================
// Settings
// ============================================================

// keys ที่อนุญาตเท่านั้น (whitelist)
const ALLOWED_SETTING_KEYS = new Set(['orgName']);

/**
 * ตรวจสอบ PUT /api/settings/:key
 */
function validateSetting(key, body) {
    const errors = [];

    if (!ALLOWED_SETTING_KEYS.has(key))
        errors.push(`key "${sanitize(String(key))}" ไม่อนุญาต ต้องเป็นหนึ่งใน: ${[...ALLOWED_SETTING_KEYS].join(', ')}`);

    const value = body.value;
    if (value === undefined || value === null)
        errors.push('value ต้องไม่ว่าง');
    else if (typeof value !== 'string')
        errors.push('value ต้องเป็นข้อความ');
    else if (value.length > 500)
        errors.push('value ต้องไม่เกิน 500 ตัวอักษร');

    if (errors.length) return { ok: false, errors };
    return { ok: true, errors: [], cleaned: { value: sanitize(value) } };
}

// ============================================================
// Restore
// ============================================================

/**
 * ตรวจโครงสร้าง data ก่อน POST /api/restore
 */
function validateRestore(body) {
    const errors = [];
    const { data } = body;

    if (!data || typeof data !== 'object')
        return fail('ข้อมูล (data) ต้องเป็น object');

    if (!data.version || typeof data.version !== 'string')
        errors.push('data.version ต้องเป็น string (เช่น "PG_V1")');

    const requiredArrays = ['settings', 'items', 'transactions', 'transaction_lines'];
    for (const field of requiredArrays) {
        if (!Array.isArray(data[field]))
            errors.push(`data.${field} ต้องเป็น array`);
    }

    if (errors.length) return fail(errors);

    // ตรวจโครงสร้างตัวอย่าง items (ถ้ามี)
    if (data.items.length > 0) {
        const item = data.items[0];
        const requiredItemFields = ['id', 'code', 'name', 'cat_code', 'unit'];
        const missingItem = requiredItemFields.filter(f => item[f] === undefined || item[f] === null);
        if (missingItem.length)
            errors.push(`data.items[0] ขาด field: ${missingItem.join(', ')}`);
    }

    // ตรวจโครงสร้าง transactions (ถ้ามี)
    if (data.transactions.length > 0) {
        const tx = data.transactions[0];
        const requiredTxFields = ['id', 'date', 'type', 'doc_no'];
        const missingTx = requiredTxFields.filter(f => tx[f] === undefined || tx[f] === null);
        if (missingTx.length)
            errors.push(`data.transactions[0] ขาด field: ${missingTx.join(', ')}`);
    }

    // ตรวจ transaction_lines (ถ้ามี)
    if (data.transaction_lines.length > 0) {
        const line = data.transaction_lines[0];
        const requiredLineFields = ['id', 'tx_id', 'item_id', 'qty'];
        const missingLine = requiredLineFields.filter(f => line[f] === undefined || line[f] === null);
        if (missingLine.length)
            errors.push(`data.transaction_lines[0] ขาด field: ${missingLine.join(', ')}`);
    }

    if (errors.length) return fail(errors);
    return pass();
}

// ============================================================
// Users (admin management)
// ============================================================

function validateNewUser(body) {
    const errors = [];
    const username = sanitize(String(body.username ?? ''));
    const password = String(body.password ?? '');
    const role = String(body.role ?? '');

    if (!username)
        errors.push('ชื่อผู้ใช้ (username) ต้องไม่ว่าง');
    else if (username.length > 50)
        errors.push('ชื่อผู้ใช้ (username) ต้องไม่เกิน 50 ตัวอักษร');
    else if (!/^[a-zA-Z0-9_.-]+$/.test(username))
        errors.push('ชื่อผู้ใช้ (username) ใช้ได้เฉพาะตัวอักษรภาษาอังกฤษ ตัวเลข และ _ . -');

    if (!password)
        errors.push('รหัสผ่าน (password) ต้องไม่ว่าง');
    else if (password.length < 6)
        errors.push('รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร');
    else if (password.length > 100)
        errors.push('รหัสผ่านต้องไม่เกิน 100 ตัวอักษร');

    if (!['admin', 'user'].includes(role))
        errors.push('สิทธิ์ (role) ต้องเป็น "admin" หรือ "user" เท่านั้น');

    if (errors.length) return { ok: false, errors };
    return { ok: true, errors: [], cleaned: { username, password, role } };
}

function validateNewPassword(body) {
    const errors = [];
    const pwd = String(body.newPassword ?? '');
    if (!pwd)
        errors.push('รหัสผ่านใหม่ (newPassword) ต้องไม่ว่าง');
    else if (pwd.length < 6)
        errors.push('รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร');
    else if (pwd.length > 100)
        errors.push('รหัสผ่านต้องไม่เกิน 100 ตัวอักษร');
    if (errors.length) return { ok: false, errors };
    return { ok: true, errors: [], cleaned: { newPassword: pwd } };
}

// ============================================================
// Exports
// ============================================================
module.exports = {
    sanitize,
    sanitizeAll,
    isPositiveInt,
    isValidDate,
    validateId,
    validateItem,
    validateTransaction,
    validateSetting,
    validateRestore,
    validateNewUser,
    validateNewPassword,
};
