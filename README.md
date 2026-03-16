# 🏛️ ระบบบัญชีคุมวัสดุ อปท. (ว.1095) - SQL Edition

## 📋 สิ่งที่เปลี่ยนแปลงจากเวอร์ชันเดิม

| หัวข้อ | เวอร์ชันเดิม (localStorage) | เวอร์ชันใหม่ (SQL) |
|--------|----------------------------|---------------------|
| ฐานข้อมูล | localStorage (เบราว์เซอร์) | SQLite (ไฟล์ stock.db) |
| ข้อจำกัดข้อมูล | ~5-10 MB | ไม่จำกัด |
| ใช้งานหลายเครื่อง | ❌ ไม่ได้ | ✅ ผ่าน Network |
| ข้อมูลหายเมื่อเคลียร์ Browser | ❌ หาย | ✅ ไม่หาย (เก็บในไฟล์) |
| Backend Server | ❌ ไม่มี | ✅ Node.js + Express |
| API | ❌ ไม่มี | ✅ RESTful API |
| หน้าตา UI | เหมือนเดิม 100% | เหมือนเดิม + badge SQL/LOCAL |

## 🚀 วิธีติดตั้งและใช้งาน

### ขั้นตอนที่ 1: ติดตั้ง Node.js
ดาวน์โหลดจาก https://nodejs.org (แนะนำ v18 ขึ้นไป)

### ขั้นตอนที่ 2: ติดตั้ง Dependencies
```bash
cd stock-app
npm install
```

### ขั้นตอนที่ 3: สร้างฐานข้อมูล (ครั้งแรกเท่านั้น)
```bash
npm run init-db
```
จะสร้างไฟล์ `stock.db` พร้อมวัสดุ 433 รายการ

### ขั้นตอนที่ 4: เริ่มเซิร์ฟเวอร์
```bash
npm start
```

### ขั้นตอนที่ 5: เปิดเบราว์เซอร์
ไปที่ http://localhost:3000

## 📁 โครงสร้างไฟล์

```
stock-app/
├── server.js          ← Backend API (Express + SQLite)
├── init-db.js         ← สร้างฐานข้อมูลและ seed ข้อมูล
├── package.json       ← Dependencies
├── stock.db           ← ไฟล์ฐานข้อมูล (สร้างหลัง init-db)
├── README.md          ← คู่มือนี้
└── public/
    └── index.html     ← หน้าเว็บ (แก้ไข JS ให้เรียก API)
```

## 🔌 API Endpoints

| Method | Endpoint | คำอธิบาย |
|--------|----------|----------|
| GET | /api/settings | ดึงค่า settings |
| PUT | /api/settings/:key | อัพเดท setting |
| GET | /api/categories | ดึงประเภทวัสดุ |
| GET | /api/items | ดึงรายการวัสดุ (?search=&cat=&limit=) |
| GET | /api/items/:id | ดึงวัสดุตาม id |
| POST | /api/items | เพิ่มวัสดุ |
| PUT | /api/items/:id | แก้ไขวัสดุ |
| DELETE | /api/items/:id | ลบวัสดุ |
| GET | /api/balance/:itemId | ดึงยอดคงเหลือ |
| GET | /api/balance-all | ดึงยอดคงเหลือทุกรายการ |
| GET | /api/transactions | ดึงเอกสาร (?limit=&type=) |
| POST | /api/transactions | บันทึกเอกสาร |
| DELETE | /api/transactions/:id | ลบเอกสาร |
| GET | /api/dashboard | ดึงข้อมูลแดชบอร์ด |
| GET | /api/report | ดึงรายงานคงเหลือ |
| GET | /api/stockcard/:itemId | ดึงบัญชีวัสดุ (Stock Card) |
| GET | /api/next-docno | สร้างเลขที่เอกสาร |
| GET | /api/backup | สำรองข้อมูล |
| POST | /api/restore | นำเข้าข้อมูล |
| POST | /api/reset | ล้างเอกสารทั้งหมด |

## 💡 หมายเหตุ

- หน้าเว็บจะตรวจสอบอัตโนมัติว่าเชื่อมต่อ API ได้หรือไม่
- ถ้าเชื่อมต่อได้ → แสดง badge **SQL** (สีเขียว)
- ถ้าเชื่อมต่อไม่ได้ → แสดง badge **LOCAL** (สีส้ม) = ใช้งานไม่ได้จนกว่าจะเปิด server
- ไฟล์ `stock.db` คือฐานข้อมูลหลัก สำรองไฟล์นี้เป็นการ backup ได้เลย
# STOCK_APP
