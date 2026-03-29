# 🏛️ ระบบทะเบียนคุมวัสดุ — Railway + PostgreSQL

## สิ่งที่เปลี่ยนจากเวอร์ชัน SQLite

| หัวข้อ | เวอร์ชันเดิม | เวอร์ชันนี้ |
|--------|-------------|------------|
| ฐานข้อมูล | SQLite (ไฟล์) | **PostgreSQL** (เซิร์ฟเวอร์) |
| Hosting | ในเครื่อง | **Railway** (ออนไลน์) |
| เปิดดูข้อมูลด้วย | - | **TablePlus** |
| ข้อมูลหายเมื่อ redeploy | ❌ หาย (SQLite) | ✅ **ไม่หาย** (PostgreSQL แยก) |
| API เหมือนเดิม | ✅ | ✅ เหมือนเดิม 100% |
| หน้าเว็บ | ✅ | ✅ เหมือนเดิม 100% |

---

## 🚀 Deploy ขึ้น Railway (ทีละขั้นตอน)

### ขั้นตอนที่ 1: สมัคร Railway
1. ไปที่ https://railway.app
2. กด **Login** → เข้าด้วย GitHub

### ขั้นตอนที่ 2: สร้าง GitHub Repository
```bash
# ในโฟลเดอร์โปรเจกต์นี้
git init
git add .
git commit -m "first commit"
git branch -M main
git remote add origin https://github.com/ชื่อคุณ/stock-app.git
git push -u origin main
```

### ขั้นตอนที่ 3: สร้าง Project บน Railway
1. ไปที่ **Railway Dashboard** → กด **New Project**
2. เลือก **Deploy from GitHub Repo**
3. เลือก repo ที่เพิ่ง push
4. Railway จะ detect เป็น Node.js อัตโนมัติ

### ขั้นตอนที่ 4: เพิ่ม PostgreSQL Database
1. ในหน้า Project → กด **+ New** (มุมขวาบน)
2. เลือก **Database** → **Add PostgreSQL**
3. Railway จะสร้าง PostgreSQL และตั้ง **DATABASE_URL** ให้อัตโนมัติ

### ขั้นตอนที่ 5: เชื่อม Database กับ App
1. คลิกที่ **Service** ของแอป (ตัวที่ deploy จาก GitHub)
2. ไปที่แท็บ **Variables**
3. กด **Add Reference Variable**
4. เลือก **DATABASE_URL** จาก PostgreSQL service
5. Railway จะ redeploy อัตโนมัติ

### ขั้นตอนที่ 6: เปิดใช้งาน
1. ไปที่แท็บ **Settings** ของ service
2. กด **Generate Domain** เพื่อสร้าง URL สาธารณะ
3. เปิด URL ที่ได้ เช่น `https://stock-app-xxxxx.up.railway.app`
4. **ครั้งแรก**: ระบบจะสร้างตารางและ seed ข้อมูล 433 รายการอัตโนมัติ!

---

## 🔌 เชื่อมต่อ TablePlus

### หา Connection Info
1. ใน Railway Dashboard → คลิกที่ **PostgreSQL** service
2. ไปแท็บ **Connect**
3. จะเห็นข้อมูล:
   - **Host**: `xxxxx.railway.internal` (ใช้ Public URL แทน)
   - **Port**: `xxxxx`
   - **User**: `postgres`
   - **Password**: `xxxxx`
   - **Database**: `railway`
4. **สำคัญ**: กดเปิด **Public Networking** ใน Settings ของ PostgreSQL เพื่อเชื่อมต่อจากภายนอก
5. จะได้ Public Host + Port ใหม่

### ตั้งค่า TablePlus
1. เปิด TablePlus → กด **+** สร้าง Connection ใหม่
2. เลือก **PostgreSQL**
3. กรอกข้อมูล:
   - **Name**: `Stock อปท. (Railway)`
   - **Host**: (Public Host จาก Railway)
   - **Port**: (Public Port จาก Railway)
   - **User**: `postgres`
   - **Password**: (จาก Railway)
   - **Database**: `railway`
   - ✅ เปิด **SSL**
4. กด **Test** → ถ้าขึ้นเขียว กด **Connect**

### ตารางที่จะเห็นใน TablePlus
| ตาราง | คำอธิบาย |
|-------|---------|
| `settings` | ค่าตั้งค่าระบบ (ชื่อหน่วยงาน) |
| `categories` | ประเภทวัสดุ 17 ประเภท |
| `items` | ทะเบียนวัสดุ 433 รายการ |
| `transactions` | เอกสารรับเข้า/เบิกจ่าย |
| `transaction_lines` | รายการวัสดุในเอกสาร |

---

## 📁 โครงสร้างไฟล์

```
railway-app/
├── server.js          ← Backend API (Express + PostgreSQL)
├── init-db.js         ← สร้างตาราง + seed (ทำงานอัตโนมัติ)
├── package.json       ← Dependencies (pg, express, cors, dotenv)
├── Procfile           ← Railway start command
├── .gitignore
├── .env.example       ← ตัวอย่าง config สำหรับ local
├── README.md          ← คู่มือนี้
└── public/
    └── index.html     ← หน้าเว็บ (เหมือนเดิมทุกอย่าง)
```

---

## 💻 ใช้งาน Local (สำหรับพัฒนา)

```bash
# 1. ติดตั้ง PostgreSQL ในเครื่อง (หรือใช้ Docker)
docker run --name stock-pg -e POSTGRES_PASSWORD=password -e POSTGRES_DB=stock_db -p 5432:5432 -d postgres:16

# 2. สร้างไฟล์ .env
cp .env.example .env

# 3. ติดตั้ง dependencies
npm install

# 4. สร้างตารางและ seed ข้อมูล
npm run init-db

# 5. เริ่มเซิร์ฟเวอร์
npm start

# เปิด http://localhost:3000
```

---

## ❓ FAQ

**Q: ทำไมไม่ใช้ SQLite?**
A: Railway ใช้ ephemeral filesystem — ไฟล์จะหายทุกครั้งที่ redeploy. PostgreSQL เป็น service แยก ข้อมูลไม่หาย.

**Q: Railway ฟรีไหม?**
A: Railway ให้ $5 credit/เดือนในแพลน Trial. สำหรับ อปท. ขนาดเล็ก ปกติจะพออยู่ ถ้าเกินจ่ายตามใช้จริง.

**Q: Backup ข้อมูลยังไง?**
A: ใช้ปุ่ม "สำรองข้อมูล" ในเว็บ หรือ export จาก TablePlus หรือใช้ `pg_dump` จาก command line.

**Q: ใช้ Neon / Supabase แทน Railway PostgreSQL ได้ไหม?**
A: ได้ครับ แค่เปลี่ยน DATABASE_URL ใน Environment Variables เป็นของ provider นั้น.
