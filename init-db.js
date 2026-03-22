/**
 * init-db.js - สร้างตาราง PostgreSQL และ seed ข้อมูลเริ่มต้น 433 รายการ
 * 
 * ใช้งาน:
 *   - Local:   node init-db.js
 *   - Railway: ทำงานอัตโนมัติตอน server start (ถ้าตารางยังไม่มี)
 */
require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('railway')
        ? { rejectUnauthorized: false }
        : false
});

// ===== ประเภทวัสดุ =====
const CATEGORIES = {
    'A0000': 'วัสดุสำนักงาน', 'B0000': 'วัสดุไฟฟ้าและวิทยุ', 'C0000': 'วัสดุงานบ้านงานครัว',
    'D0000': 'วัสดุก่อสร้าง', 'E0000': 'วัสดุยานพาหนะและขนส่ง', 'F0000': 'วัสดุวิทยาศาสตร์และการแพทย์',
    'G0000': 'วัสดุการเกษตร', 'H0000': 'วัสดุเครื่องแต่งกาย', 'I0000': 'วัสดุกกีฬา',
    'J0000': 'วัสดุคอมพิวเตอร์', 'K0000': 'วัสดุการศึกษา', 'L0000': 'วัสดุเครื่องดับเพลิง',
    'M0000': 'วัสดุสนาม', 'N0000': 'วัสดุสำรวจ', 'O0000': 'วัสดุดนตรี',
    'P0000': 'วัสดุจราจร', 'Q0000': 'วัสดุอื่น'
};

// ===== วัสดุ 433 รายการ =====
const INITIAL_ITEMS = [
    {code:"A0001",name:"หนังสือ",cat:"A0000",unit:"เล่ม"},{code:"A0002",name:"เครื่องคิดเลขขนาดเล็ก",cat:"A0000",unit:"เครื่อง"},{code:"A0003",name:"เครื่องเจาะกระดาษขนาดเล็ก",cat:"A0000",unit:"อัน"},{code:"A0004",name:"ที่เย็บกระดาษขนาดเล็ก",cat:"A0000",unit:"อัน"},{code:"A0005",name:"ไม้บรรทัดเหล็ก",cat:"A0000",unit:"อัน"},{code:"A0006",name:"กรรไกร",cat:"A0000",unit:"อัน"},{code:"A0007",name:"เก้าอี้พลาสติก",cat:"A0000",unit:"ตัว"},{code:"A0008",name:"ตรายาง",cat:"A0000",unit:"อัน"},{code:"A0009",name:"ที่ถูพื้น",cat:"A0000",unit:"อัน"},{code:"A0010",name:"ตระแกรงวางเอกสาร",cat:"A0000",unit:"อัน"},
    {code:"A0011",name:"เครื่องตัดโฟม",cat:"A0000",unit:"เครื่อง"},{code:"A0012",name:"เครื่องตัดกระดาษ",cat:"A0000",unit:"เครื่อง"},{code:"A0013",name:"เครื่องเย็บกระดาษ",cat:"A0000",unit:"เครื่อง"},{code:"A0014",name:"กุญแจ",cat:"A0000",unit:"ดอก"},{code:"A0015",name:"ภาพเขียน, แผนที่",cat:"A0000",unit:"แผ่น"},{code:"A0016",name:"พระบรมฉายาลักษณ์",cat:"A0000",unit:"องค์"},{code:"A0017",name:"แผงปิดประกาศ",cat:"A0000",unit:"แผง"},{code:"A0018",name:"แผ่นป้ายชื่อสำนักงานหรือหน่วยงาน",cat:"A0000",unit:"แผ่น"},{code:"A0019",name:"มู่ลี่,ม่านปรับแสง",cat:"A0000",unit:"ผืน"},{code:"A0020",name:"พรม",cat:"A0000",unit:"ผืน"},
    {code:"A0021",name:"นาฬิกาตั้งหรือแขวน",cat:"A0000",unit:"เรือน"},{code:"A0022",name:"พระพุทธรูป",cat:"A0000",unit:"องค์"},{code:"A0023",name:"พระบรมรูปจำลอง",cat:"A0000",unit:"องค์"},{code:"A0024",name:"กระเป๋า",cat:"A0000",unit:"ใบ"},{code:"A0025",name:"ตาชั่งขนาดเล็ก",cat:"A0000",unit:"เครื่อง"},{code:"A0026",name:"ผ้าใบติดตั้งในสำนักงาน",cat:"A0000",unit:"ผืน"},{code:"A0027",name:"ผ้าใบเต้นท์ขนาดใหญ่",cat:"A0000",unit:"ผืน"},{code:"A0028",name:"ตู้ยาสามัญประจำบ้าน",cat:"A0000",unit:"ตู้"},{code:"A0029",name:"แผงกันห้องแบบรื้อถอน",cat:"A0000",unit:"แผง"},{code:"A0030",name:"กระดาษ",cat:"A0000",unit:"รีม"},
    {code:"A0031",name:"หมึก",cat:"A0000",unit:"ขวด"},{code:"A0032",name:"ดินสอ",cat:"A0000",unit:"แท่ง"},{code:"A0033",name:"ปากกา",cat:"A0000",unit:"ด้าม"},{code:"A0034",name:"ยางลบ",cat:"A0000",unit:"ก้อน"},{code:"A0035",name:"น้ำยาลบคำผิด",cat:"A0000",unit:"ขวด"},{code:"A0036",name:"เทปกาว",cat:"A0000",unit:"ม้วน"},{code:"A0037",name:"ลวดเย็บกระดาษ",cat:"A0000",unit:"กล่อง"},{code:"A0038",name:"กาว",cat:"A0000",unit:"ขวด"},{code:"A0039",name:"สมุด",cat:"A0000",unit:"เล่ม"},{code:"A0040",name:"ซองเอกสาร",cat:"A0000",unit:"ซอง"},
    {code:"A0041",name:"ตลับผงหมึก",cat:"A0000",unit:"ตลับ"},{code:"A0042",name:"น้ำหมึกปรินท์",cat:"A0000",unit:"ขวด"},{code:"A0043",name:"เทป พี วี ซี แบบใส",cat:"A0000",unit:"ม้วน"},{code:"A0044",name:"น้ำยาลบกระดาษไข",cat:"A0000",unit:"ขวด"},{code:"A0045",name:"ไม้บรรทัด",cat:"A0000",unit:"อัน"},{code:"A0046",name:"คลิป",cat:"A0000",unit:"กล่อง"},{code:"A0047",name:"ตัวเย็บกระดาษ",cat:"A0000",unit:"ตัว"},{code:"A0048",name:"เข็มหมุด",cat:"A0000",unit:"กล่อง"},{code:"A0049",name:"กระดาษคาร์บอน",cat:"A0000",unit:"กล่อง"},{code:"A0050",name:"กระดาษไข",cat:"A0000",unit:"กล่อง"},
    {code:"A0051",name:"แฟ้ม",cat:"A0000",unit:"แฟ้ม"},{code:"A0052",name:"สมุดบัญชี",cat:"A0000",unit:"เล่ม"},{code:"A0053",name:"สมุดประวัติข้าราชการ",cat:"A0000",unit:"เล่ม"},{code:"A0054",name:"แบบพิมพ์",cat:"A0000",unit:"เล่ม"},{code:"A0055",name:"ผ้าสำลี",cat:"A0000",unit:"พับ"},{code:"A0056",name:"ธงชาติ",cat:"A0000",unit:"ผืน"},{code:"A0057",name:"สิ่งพิมพ์ที่ได้จากการซื้อ",cat:"A0000",unit:"ชิ้น"},{code:"A0058",name:"ของใช้ในการบรรจุหีบห่อ",cat:"A0000",unit:"ชิ้น"},{code:"A0059",name:"น้ำมัน ไข ขี้ผึ้ง",cat:"A0000",unit:"ขวด/ก้อน"},{code:"A0060",name:"น้ำดื่มบริการ",cat:"A0000",unit:"ขวด/แก้ว"},
    {code:"A0061",name:"พวงมาลัย",cat:"A0000",unit:"พวง"},{code:"A0062",name:"พวงมาลา",cat:"A0000",unit:"พวง"},{code:"A0063",name:"พานพุ่ม",cat:"A0000",unit:"พาน"},{code:"A0064",name:"กรวยดอกไม้",cat:"A0000",unit:"กรวย"},{code:"A0065",name:"อื่นๆ",cat:"A0000",unit:"ชิ้น"},
    {code:"B0001",name:"ไมโครโฟน",cat:"B0000",unit:"ตัว"},{code:"B0002",name:"ขาตั้งไมโครโฟน",cat:"B0000",unit:"อัน"},{code:"B0003",name:"หัวแร้งไฟฟ้า",cat:"B0000",unit:"อัน"},{code:"B0004",name:"เครื่องวัดกระแสไฟฟ้า",cat:"B0000",unit:"เครื่อง"},{code:"B0005",name:"เครื่องวัดแรงดันไฟฟ้า",cat:"B0000",unit:"เครื่อง"},{code:"B0006",name:"มาตรตรวจวงจรไฟฟ้า",cat:"B0000",unit:"เครื่อง"},{code:"B0007",name:"เครื่องประจุไฟ",cat:"B0000",unit:"เครื่อง"},{code:"B0008",name:"โคมไฟ",cat:"B0000",unit:"อัน"},{code:"B0009",name:"โทรโข่ง",cat:"B0000",unit:"ตัว"},{code:"B0010",name:"ไม้ชักฟิวส์",cat:"B0000",unit:"อัน"},
    {code:"B0011",name:"ไมค์ลอย",cat:"B0000",unit:"ชุด"},{code:"B0012",name:"ฟิวส์",cat:"B0000",unit:"ตัว"},{code:"B0013",name:"เทปพันสายไฟ",cat:"B0000",unit:"ม้วน"},{code:"B0014",name:"สายไฟฟ้า",cat:"B0000",unit:"ม้วน"},{code:"B0015",name:"หลอดไฟฟ้า",cat:"B0000",unit:"หลอด"},{code:"B0016",name:"หลอดไฟ",cat:"B0000",unit:"หลอด"},{code:"B0017",name:"เข็มขัดรัดสายไฟฟ้า",cat:"B0000",unit:"ถุง"},{code:"B0018",name:"ปลั๊กไฟฟ้า",cat:"B0000",unit:"อัน"},{code:"B0019",name:"สวิตช์ไฟฟ้า",cat:"B0000",unit:"อัน"},{code:"B0020",name:"หลอดวิทยุ",cat:"B0000",unit:"ชิ้น"},
    {code:"B0021",name:"ลูกถ้วยสายอากาศ",cat:"B0000",unit:"ลูก"},{code:"B0022",name:"รีซีสเตอร์",cat:"B0000",unit:"ตัว"},{code:"B0023",name:"คอนเดนเซอร์",cat:"B0000",unit:"ตัว"},{code:"B0024",name:"ขาหลอดฟลูออเรสเชนซ์",cat:"B0000",unit:"อัน"},{code:"B0025",name:"เบรกเกอร์",cat:"B0000",unit:"ตัว"},{code:"B0026",name:"สายอากาศ/จานดาวเทียม",cat:"B0000",unit:"ชุด"},{code:"B0027",name:"แบตเตอรี่โซล่าเซลล์",cat:"B0000",unit:"ลูก"},{code:"B0028",name:"กล่องรับสัญญาณ",cat:"B0000",unit:"กล่อง"},{code:"B0029",name:"ดอกลำโพง",cat:"B0000",unit:"ดอก"},{code:"B0030",name:"ฮอร์นลำโพง",cat:"B0000",unit:"ตัว"},
    {code:"B0031",name:"แผงวงจร",cat:"B0000",unit:"แผง"},{code:"B0032",name:"ผังแสดงวงจร",cat:"B0000",unit:"แผ่น"},{code:"B0033",name:"แผงบังคับทางไฟ",cat:"B0000",unit:"แผง"},{code:"B0034",name:"อื่นๆ",cat:"B0000",unit:"ชิ้น"},
    {code:"C0001",name:"หม้อ",cat:"C0000",unit:"ใบ"},{code:"C0002",name:"กระทะ",cat:"C0000",unit:"ใบ"},{code:"C0003",name:"กะละมัง",cat:"C0000",unit:"ใบ"},{code:"C0004",name:"ตะหลิว",cat:"C0000",unit:"อัน"},{code:"C0005",name:"กรอบรูป",cat:"C0000",unit:"กรอบ"},{code:"C0006",name:"มีด",cat:"C0000",unit:"เล่ม"},{code:"C0007",name:"ถัง",cat:"C0000",unit:"ใบ"},{code:"C0008",name:"ถาด",cat:"C0000",unit:"ใบ"},{code:"C0009",name:"แก้วน้ำ",cat:"C0000",unit:"ใบ"},{code:"C0010",name:"จานรอง",cat:"C0000",unit:"ใบ"},
    {code:"C0011",name:"ถ้วยชาม",cat:"C0000",unit:"ใบ"},{code:"C0012",name:"ช้อนส้อม",cat:"C0000",unit:"คู่"},{code:"C0013",name:"กระจกเงา",cat:"C0000",unit:"บาน"},{code:"C0014",name:"โอ่งน้ำ",cat:"C0000",unit:"ใบ"},{code:"C0015",name:"ที่นอน",cat:"C0000",unit:"หลัง"},{code:"C0016",name:"กระโถน",cat:"C0000",unit:"ใบ"},{code:"C0017",name:"เตาไฟฟ้า",cat:"C0000",unit:"เตา"},{code:"C0018",name:"เตาน้ำมัน",cat:"C0000",unit:"เตา"},{code:"C0019",name:"เตารีด",cat:"C0000",unit:"เตา"},{code:"C0020",name:"เครื่องบดอาหาร",cat:"C0000",unit:"เครื่อง"},
    {code:"C0021",name:"เครื่องตีไข่ไฟฟ้า",cat:"C0000",unit:"เครื่อง"},{code:"C0022",name:"เครื่องปิ้งขนมปัง",cat:"C0000",unit:"เครื่อง"},{code:"C0023",name:"กระทะไฟฟ้า",cat:"C0000",unit:"ใบ"},{code:"C0024",name:"หม้อไฟฟ้า",cat:"C0000",unit:"ใบ"},{code:"C0025",name:"กระติกน้ำร้อน",cat:"C0000",unit:"ใบ"},{code:"C0026",name:"กระติกน้ำแข็ง",cat:"C0000",unit:"ใบ"},{code:"C0027",name:"ถังแก็ส",cat:"C0000",unit:"ถัง"},{code:"C0028",name:"เตา",cat:"C0000",unit:"เตา"},{code:"C0029",name:"ตู้เก็บอุปกรณ์ดับเพลิง",cat:"C0000",unit:"ตู้"},{code:"C0030",name:"สายยางฉีดน้ำ",cat:"C0000",unit:"เส้น"},
    {code:"C0031",name:"ถังขยะแบบขาตั้ง",cat:"C0000",unit:"ใบ"},{code:"C0032",name:"ถังขยะแบบล้อลาก",cat:"C0000",unit:"ใบ"},{code:"C0033",name:"อ่างล้างจาน",cat:"C0000",unit:"ใบ"},{code:"C0034",name:"ถังน้ำ",cat:"C0000",unit:"ใบ"},{code:"C0035",name:"ผงซักฟอก",cat:"C0000",unit:"ถุง"},{code:"C0036",name:"สบู่",cat:"C0000",unit:"ก้อน"},{code:"C0037",name:"น้ำยาดับกลิ่น",cat:"C0000",unit:"ขวด"},{code:"C0038",name:"แปรง",cat:"C0000",unit:"อัน"},{code:"C0039",name:"ไม้กวาด",cat:"C0000",unit:"ด้าม"},{code:"C0040",name:"เข่ง",cat:"C0000",unit:"ใบ"},
    {code:"C0041",name:"มุ้ง",cat:"C0000",unit:"หลัง"},{code:"C0042",name:"ผ้าปูที่นอน",cat:"C0000",unit:"ผืน"},{code:"C0043",name:"ปลอกหมอน",cat:"C0000",unit:"ใบ"},{code:"C0044",name:"หมอน",cat:"C0000",unit:"ใบ"},{code:"C0045",name:"ผ้าห่ม",cat:"C0000",unit:"ผืน"},{code:"C0046",name:"ผ้าปูโต๊ะ",cat:"C0000",unit:"ผืน"},{code:"C0047",name:"น้ำจืด",cat:"C0000",unit:"ลิตร"},{code:"C0048",name:"หัวดูดตะกอนสระว่ายน้ำ",cat:"C0000",unit:"อัน"},{code:"C0049",name:"นมโรงเรียน",cat:"C0000",unit:"กล่อง/ถุง"},{code:"C0050",name:"วัสดุประกอบอาหาร",cat:"C0000",unit:"ชิ้น"},
    {code:"C0051",name:"อาหารสำเร็จรูป",cat:"C0000",unit:"ชิ้น"},{code:"C0052",name:"อื่นๆ",cat:"C0000",unit:"ชิ้น"},
    {code:"D0001",name:"ไม้ต่าง ๆ",cat:"D0000",unit:"แผ่น/ท่อน"},{code:"D0002",name:"ค้อน",cat:"D0000",unit:"อัน"},{code:"D0003",name:"คีม",cat:"D0000",unit:"อัน"},{code:"D0004",name:"ชะแลง",cat:"D0000",unit:"อัน"},{code:"D0005",name:"จอบ",cat:"D0000",unit:"ด้าม"},{code:"D0006",name:"สิ่ว",cat:"D0000",unit:"อัน"},{code:"D0007",name:"เสียม",cat:"D0000",unit:"ด้าม"},{code:"D0008",name:"เลื่อย",cat:"D0000",unit:"ปื้น"},{code:"D0009",name:"ขวาน",cat:"D0000",unit:"เล่ม"},{code:"D0010",name:"กบไสไม้",cat:"D0000",unit:"ตัว"},
    {code:"D0011",name:"เทปวัดระยะ",cat:"D0000",unit:"ม้วน"},{code:"D0012",name:"ตลับเมตร/ลูกดิ่ง",cat:"D0000",unit:"อัน"},{code:"D0013",name:"สว่านมือ",cat:"D0000",unit:"ตัว"},{code:"D0014",name:"โถส้วม",cat:"D0000",unit:"โถ"},{code:"D0015",name:"อ่างล้างมือ",cat:"D0000",unit:"อ่าง"},{code:"D0016",name:"ราวพาดผ้า",cat:"D0000",unit:"อัน"},{code:"D0017",name:"หน้ากากเชื่อมเหล็ก",cat:"D0000",unit:"อัน"},{code:"D0018",name:"เครื่องยิงตะปู",cat:"D0000",unit:"เครื่อง"},{code:"D0019",name:"นั่งร้าน",cat:"D0000",unit:"ชุด"},{code:"D0020",name:"น้ำมันทาไม้",cat:"D0000",unit:"กระป๋อง"},
    {code:"D0021",name:"ทินเนอร์",cat:"D0000",unit:"ขวด/ปี๊บ"},{code:"D0022",name:"สี",cat:"D0000",unit:"กระป๋อง"},{code:"D0023",name:"ปูนซีเมนต์",cat:"D0000",unit:"ถุง"},{code:"D0024",name:"ทราย",cat:"D0000",unit:"คิว"},{code:"D0025",name:"ยางมะตอยสำเร็จรูป",cat:"D0000",unit:"ถุง"},{code:"D0026",name:"อิฐ/ซีเมนต์บล็อก",cat:"D0000",unit:"ก้อน"},{code:"D0027",name:"กระเบื้อง",cat:"D0000",unit:"แผ่น"},{code:"D0028",name:"สังกะสี",cat:"D0000",unit:"แผ่น"},{code:"D0029",name:"ตะปู",cat:"D0000",unit:"กก."},{code:"D0030",name:"เหล็กเส้น",cat:"D0000",unit:"เส้น"},
    {code:"D0031",name:"แปรงทาสี",cat:"D0000",unit:"อัน"},{code:"D0032",name:"ปูนขาว",cat:"D0000",unit:"ถุง"},{code:"D0033",name:"แผ่นดินเหนียวสังเคราะห์",cat:"D0000",unit:"แผ่น"},{code:"D0034",name:"อุปกรณ์ประปา",cat:"D0000",unit:"ชิ้น"},{code:"D0035",name:"ท่อต่างๆ",cat:"D0000",unit:"ท่อน"},{code:"D0036",name:"ท่อน้ำบาดาล",cat:"D0000",unit:"ท่อน"},{code:"D0037",name:"อื่นๆ",cat:"D0000",unit:"ชิ้น"},
    {code:"E0001",name:"ไขควง",cat:"E0000",unit:"อัน"},{code:"E0002",name:"ประแจ",cat:"E0000",unit:"อัน"},{code:"E0003",name:"แม่แรง",cat:"E0000",unit:"ตัว"},{code:"E0004",name:"กุญแจปากตาย",cat:"E0000",unit:"ตัว"},{code:"E0005",name:"กุญแจเลื่อน",cat:"E0000",unit:"ตัว"},{code:"E0006",name:"คีมล็อค",cat:"E0000",unit:"อัน"},{code:"E0007",name:"ล็อคเกียร์",cat:"E0000",unit:"ชุด"},{code:"E0008",name:"ล็อคคลัตช์",cat:"E0000",unit:"ชุด"},{code:"E0009",name:"ล็อคพวงมาลัย",cat:"E0000",unit:"ชุด"},{code:"E0010",name:"ยางรถยนต์",cat:"E0000",unit:"เส้น"},
    {code:"E0011",name:"น้ำมันเบรก",cat:"E0000",unit:"กระป๋อง"},{code:"E0012",name:"น็อตและสกรู",cat:"E0000",unit:"ตัว"},{code:"E0013",name:"สายไมล์",cat:"E0000",unit:"เส้น"},{code:"E0014",name:"เพลา",cat:"E0000",unit:"อัน"},{code:"E0015",name:"ฟิล์มกรองแสง",cat:"E0000",unit:"ม้วน"},{code:"E0016",name:"น้ำกลั่น",cat:"E0000",unit:"ขวด"},{code:"E0017",name:"เบาะรถยนต์",cat:"E0000",unit:"เบาะ"},{code:"E0018",name:"อะไหล่เครื่องยนต์",cat:"E0000",unit:"ชิ้น"},{code:"E0019",name:"ชุดเกียร์",cat:"E0000",unit:"ชุด"},{code:"E0020",name:"เบรก",cat:"E0000",unit:"ชุด"},
    {code:"E0021",name:"ครัช",cat:"E0000",unit:"ชุด"},{code:"E0022",name:"พวงมาลัย",cat:"E0000",unit:"วง"},{code:"E0023",name:"สายพานใบพัด",cat:"E0000",unit:"เส้น"},{code:"E0024",name:"หม้อน้ำ",cat:"E0000",unit:"ใบ"},{code:"E0025",name:"หัวเทียน",cat:"E0000",unit:"หัว"},{code:"E0026",name:"แบตเตอรี่",cat:"E0000",unit:"ลูก"},{code:"E0027",name:"จานจ่าย",cat:"E0000",unit:"อัน"},{code:"E0028",name:"ล้อ",cat:"E0000",unit:"ล้อ"},{code:"E0029",name:"ถังน้ำมัน",cat:"E0000",unit:"ใบ"},{code:"E0030",name:"ไฟหน้า",cat:"E0000",unit:"ดวง"},
    {code:"E0031",name:"ไฟเบรก",cat:"E0000",unit:"ดวง"},{code:"E0032",name:"อานจักรยาน",cat:"E0000",unit:"อัน"},{code:"E0033",name:"ตลับลูกปืน",cat:"E0000",unit:"ตลับ"},{code:"E0034",name:"กระจกมองข้าง",cat:"E0000",unit:"บาน"},{code:"E0035",name:"กันชน",cat:"E0000",unit:"อัน"},{code:"E0036",name:"เข็มขัดนิรภัย",cat:"E0000",unit:"เส้น"},{code:"E0037",name:"สายไฮดรอลิค",cat:"E0000",unit:"เส้น"},{code:"E0038",name:"แก๊สหุงต้ม",cat:"E0000",unit:"ถัง"},{code:"E0039",name:"น้ำมันเชื้อเพลิง",cat:"E0000",unit:"ลิตร"},{code:"E0040",name:"น้ำมันดีเซล",cat:"E0000",unit:"ลิตร"},
    {code:"E0041",name:"น้ำมันก๊าด",cat:"E0000",unit:"ลิตร"},{code:"E0042",name:"น้ำมันเบนซิน",cat:"E0000",unit:"ลิตร"},{code:"E0043",name:"น้ำมันเตา",cat:"E0000",unit:"ลิตร"},{code:"E0044",name:"จารบี",cat:"E0000",unit:"กก."},{code:"E0045",name:"น้ำมันเครื่อง",cat:"E0000",unit:"ลิตร"},{code:"E0046",name:"ถ่าน",cat:"E0000",unit:"กก."},{code:"E0047",name:"ก๊าซ",cat:"E0000",unit:"ถัง"},{code:"E0048",name:"น้ำมันเกียร์",cat:"E0000",unit:"ลิตร"},{code:"E0049",name:"น้ำมันหล่อลื่น",cat:"E0000",unit:"ลิตร"},
    {code:"F0001",name:"อื่นๆ",cat:"F0000",unit:"ชิ้น"},{code:"F0002",name:"ชุดเครื่องมือผ่าตัด",cat:"F0000",unit:"ชุด"},{code:"F0003",name:"ที่วางกรวยแก้ว",cat:"F0000",unit:"อัน"},{code:"F0004",name:"กระบอกตวง",cat:"F0000",unit:"อัน"},{code:"F0005",name:"เบ้าหลอม",cat:"F0000",unit:"อัน"},{code:"F0006",name:"หูฟังแพทย์",cat:"F0000",unit:"อัน"},{code:"F0007",name:"เปลหาม",cat:"F0000",unit:"อัน"},{code:"F0008",name:"คีมถอนฟัน",cat:"F0000",unit:"อัน"},{code:"F0009",name:"เครื่องวัดน้ำฝน",cat:"F0000",unit:"เครื่อง"},{code:"F0010",name:"ถังเก็บเชื้อเพลิง",cat:"F0000",unit:"ถัง"},
    {code:"F0011",name:"เครื่องนึ่ง",cat:"F0000",unit:"เครื่อง"},{code:"F0012",name:"เครื่องมือวิทย์ฯ",cat:"F0000",unit:"เครื่อง"},{code:"F0013",name:"เครื่องวัดอุณหภูมิ",cat:"F0000",unit:"เครื่อง"},{code:"F0014",name:"ปรอทวัดไข้",cat:"F0000",unit:"อัน"},{code:"F0015",name:"สำลี/ผ้าพันแผล",cat:"F0000",unit:"ห่อ/ม้วน"},{code:"F0016",name:"เวชภัณฑ์",cat:"F0000",unit:"ชิ้น"},{code:"F0017",name:"ชุดป้องกันเชื้อโรค",cat:"F0000",unit:"ชุด"},{code:"F0018",name:"แอลกอฮอล์",cat:"F0000",unit:"ขวด"},{code:"F0019",name:"ฟิล์มเอกซเรย์",cat:"F0000",unit:"แผ่น"},{code:"F0020",name:"เคมีภัณฑ์",cat:"F0000",unit:"ขวด"},
    {code:"F0021",name:"ออกซิเจน",cat:"F0000",unit:"ถัง"},{code:"F0022",name:"น้ำยาต่าง ๆ",cat:"F0000",unit:"ขวด"},{code:"F0023",name:"เลือด",cat:"F0000",unit:"ถุง"},{code:"F0024",name:"สายยาง",cat:"F0000",unit:"เส้น"},{code:"F0025",name:"ลูกยาง",cat:"F0000",unit:"ลูก"},{code:"F0026",name:"หลอดแก้ว",cat:"F0000",unit:"หลอด"},{code:"F0027",name:"ลวดเชื่อมเงิน",cat:"F0000",unit:"เส้น"},{code:"F0028",name:"ถุงมือ",cat:"F0000",unit:"คู่"},{code:"F0029",name:"กระดาษกรอง",cat:"F0000",unit:"แผ่น"},{code:"F0030",name:"จุกต่าง ๆ",cat:"F0000",unit:"อัน"},
    {code:"F0031",name:"สัตว์ทดลอง",cat:"F0000",unit:"ตัว"},{code:"F0032",name:"หลอดเอกซเรย์",cat:"F0000",unit:"หลอด"},{code:"F0033",name:"ทรายอะเบท",cat:"F0000",unit:"ถุง"},{code:"F0034",name:"น้ำยากำจัดยุง",cat:"F0000",unit:"ขวด"},{code:"F0035",name:"คลอรีน/สารส้ม",cat:"F0000",unit:"ถุง"},{code:"F0036",name:"หน้ากากอนามัย",cat:"F0000",unit:"ชิ้น"},{code:"F0037",name:"อื่นๆ",cat:"F0000",unit:"ชิ้น"},
    {code:"G0001",name:"เคียว",cat:"G0000",unit:"เล่ม"},{code:"G0002",name:"สปริงเกลอร์",cat:"G0000",unit:"หัว"},{code:"G0003",name:"จอบหมุน",cat:"G0000",unit:"อัน"},{code:"G0004",name:"จอบพรวน",cat:"G0000",unit:"อัน"},{code:"G0005",name:"ผานไถ",cat:"G0000",unit:"อัน"},{code:"G0006",name:"คราด",cat:"G0000",unit:"อัน"},{code:"G0007",name:"เครื่องดักแมลง",cat:"G0000",unit:"เครื่อง"},{code:"G0008",name:"ตะแกรงร่อน",cat:"G0000",unit:"อัน"},{code:"G0009",name:"อวน",cat:"G0000",unit:"ปาก"},{code:"G0010",name:"กระชัง",cat:"G0000",unit:"อัน"},
    {code:"G0011",name:"มีดตัดต้นไม้",cat:"G0000",unit:"เล่ม"},{code:"G0012",name:"ปุ๋ย",cat:"G0000",unit:"กระสอบ"},{code:"G0013",name:"ยากำจัดศัตรูพืช",cat:"G0000",unit:"ขวด"},{code:"G0014",name:"อาหารสัตว์",cat:"G0000",unit:"กระสอบ"},{code:"G0015",name:"พืช/สัตว์",cat:"G0000",unit:"ต้น/ตัว"},{code:"G0016",name:"พันธุ์สัตว์",cat:"G0000",unit:"ตัว"},{code:"G0017",name:"น้ำเชื้อพันธุ์สัตว์",cat:"G0000",unit:"หลอด"},{code:"G0018",name:"วัสดุเพาะชำ",cat:"G0000",unit:"ชิ้น"},{code:"G0019",name:"อุปกรณ์ขยายพันธุ์",cat:"G0000",unit:"ชิ้น"},{code:"G0020",name:"ผ้าใบ/พลาสติก",cat:"G0000",unit:"ผืน"},
    {code:"G0021",name:"หน้ากากกันแก๊ส",cat:"G0000",unit:"อัน"},{code:"G0022",name:"หัวกะโหลกดูดน้ำ",cat:"G0000",unit:"หัว"},{code:"G0023",name:"อื่นๆ",cat:"G0000",unit:"ชิ้น"},
    {code:"H0001",name:"เครื่องแบบ",cat:"H0000",unit:"ชุด"},{code:"H0002",name:"เสื้อ/กางเกง",cat:"H0000",unit:"ตัว"},{code:"H0003",name:"เครื่องหมาย",cat:"H0000",unit:"อัน"},{code:"H0004",name:"ถุงเท้า/ถุงมือ",cat:"H0000",unit:"คู่"},{code:"H0005",name:"รองเท้า",cat:"H0000",unit:"คู่"},{code:"H0006",name:"เข็มขัด",cat:"H0000",unit:"เส้น"},{code:"H0007",name:"หมวก",cat:"H0000",unit:"ใบ"},{code:"H0008",name:"ผ้าพันคอ",cat:"H0000",unit:"ผืน"},{code:"H0009",name:"เสื้อสะท้อนแสง",cat:"H0000",unit:"ตัว"},{code:"H0010",name:"เสื้อชูชีพ",cat:"H0000",unit:"ตัว"},
    {code:"H0011",name:"ชุดดับเพลิง",cat:"H0000",unit:"ชุด"},{code:"H0012",name:"ชุดประดาน้ำ",cat:"H0000",unit:"ชุด"},{code:"H0013",name:"ชุดคนงานกวาดถนน",cat:"H0000",unit:"ชุด"},{code:"H0014",name:"ชุดจนท.สาธารณสุข",cat:"H0000",unit:"ชุด"},{code:"H0015",name:"ชุดนาฎศิลป์",cat:"H0000",unit:"ชุด"},{code:"H0016",name:"ชุดดุริยางค์",cat:"H0000",unit:"ชุด"},{code:"H0017",name:"วุฒิบัตร อปพร.",cat:"H0000",unit:"ใบ"},{code:"H0018",name:"บัตร อปพร.",cat:"H0000",unit:"บัตร"},{code:"H0019",name:"เข็ม อปพร.",cat:"H0000",unit:"อัน"},{code:"H0020",name:"อื่นๆ",cat:"H0000",unit:"ชิ้น"},
    {code:"I0001",name:"ห่วงยาง",cat:"I0000",unit:"ห่วง"},{code:"I0002",name:"ไม้ปิงปอง",cat:"I0000",unit:"อัน"},{code:"I0003",name:"ไม้แบดมินตัน",cat:"I0000",unit:"อัน"},{code:"I0004",name:"ไม้เทนนิส",cat:"I0000",unit:"อัน"},{code:"I0005",name:"เชือกกระโดด",cat:"I0000",unit:"เส้น"},{code:"I0006",name:"ดาบสองมือ",cat:"I0000",unit:"เล่ม"},{code:"I0007",name:"ตะกร้าแชร์บอล",cat:"I0000",unit:"ใบ"},{code:"I0008",name:"นาฬิกาจับเวลา",cat:"I0000",unit:"เรือน"},{code:"I0009",name:"นวม",cat:"I0000",unit:"คู่"},{code:"I0010",name:"ลูกทุ่มน้ำหนัก",cat:"I0000",unit:"ลูก"},
    {code:"I0011",name:"เสาตาข่าย",cat:"I0000",unit:"คู่"},{code:"I0012",name:"ห่วงบาสเก็ตบอล",cat:"I0000",unit:"ห่วง"},{code:"I0013",name:"กระดานคะแนน",cat:"I0000",unit:"แผ่น"},{code:"I0014",name:"ลูกเปตอง",cat:"I0000",unit:"ลูก"},{code:"I0015",name:"เบาะยืดหยุ่น",cat:"I0000",unit:"เบาะ"},{code:"I0016",name:"ตาข่ายกีฬา",cat:"I0000",unit:"ผืน"},{code:"I0017",name:"ลูกปิงปอง",cat:"I0000",unit:"ลูก"},{code:"I0018",name:"ลูกแบดมินตัน",cat:"I0000",unit:"ลูก"},{code:"I0019",name:"ลูกเทนนิส",cat:"I0000",unit:"ลูก"},{code:"I0020",name:"ลูกฟุตบอล",cat:"I0000",unit:"ลูก"},
    {code:"I0021",name:"ลูกแชร์บอล",cat:"I0000",unit:"ลูก"},{code:"I0022",name:"แผ่นโยคะ",cat:"I0000",unit:"แผ่น"},{code:"I0023",name:"ตะกร้อ",cat:"I0000",unit:"ลูก"},{code:"I0024",name:"นกหวีด",cat:"I0000",unit:"อัน"},{code:"I0025",name:"อื่นๆ",cat:"I0000",unit:"ชิ้น"},
    {code:"J0001",name:"แผ่นบันทึกข้อมูล",cat:"J0000",unit:"แผ่น"},{code:"J0002",name:"อุปกรณ์บันทึกข้อมูล",cat:"J0000",unit:"อัน"},{code:"J0003",name:"แฟลชไดร์ฟ/แผ่นดิสก์",cat:"J0000",unit:"อัน"},{code:"J0004",name:"เทปบันทึกข้อมูล",cat:"J0000",unit:"ม้วน"},{code:"J0005",name:"หัวพิมพ์",cat:"J0000",unit:"อัน"},{code:"J0006",name:"ตลับหมึก",cat:"J0000",unit:"ตลับ"},{code:"J0007",name:"กระดาษต่อเนื่อง",cat:"J0000",unit:"กล่อง"},{code:"J0008",name:"สายเคเบิล",cat:"J0000",unit:"เส้น"},{code:"J0009",name:"CPU",cat:"J0000",unit:"อัน"},{code:"J0010",name:"Hard Disk",cat:"J0000",unit:"อัน"},
    {code:"J0011",name:"CD-ROM Drive",cat:"J0000",unit:"อัน"},{code:"J0012",name:"แผ่นกรองแสง",cat:"J0000",unit:"แผ่น"},{code:"J0013",name:"คีย์บอร์ด",cat:"J0000",unit:"อัน"},{code:"J0014",name:"เมนบอร์ด",cat:"J0000",unit:"อัน"},{code:"J0015",name:"RAM",cat:"J0000",unit:"อัน"},{code:"J0016",name:"Cut Sheet Feeder",cat:"J0000",unit:"อัน"},{code:"J0017",name:"เมาส์",cat:"J0000",unit:"อัน"},{code:"J0018",name:"Switching Box",cat:"J0000",unit:"อัน"},{code:"J0019",name:"Hub",cat:"J0000",unit:"เครื่อง"},{code:"J0020",name:"การ์ดต่างๆ (LAN/Sound)",cat:"J0000",unit:"แผ่น"},
    {code:"J0021",name:"เครื่องอ่านข้อมูล",cat:"J0000",unit:"เครื่อง"},{code:"J0022",name:"Optical Disk",cat:"J0000",unit:"อัน"},{code:"J0023",name:"Router",cat:"J0000",unit:"เครื่อง"},{code:"J0024",name:"อื่นๆ",cat:"J0000",unit:"ชิ้น"},
    {code:"K0001",name:"หุ่นจำลอง",cat:"K0000",unit:"ตัว"},{code:"K0002",name:"แบบจำลองภูมิประเทศ",cat:"K0000",unit:"ชุด"},{code:"K0003",name:"สื่อการสอนพลาสติก",cat:"K0000",unit:"ชิ้น"},{code:"K0004",name:"กระดานลื่น",cat:"K0000",unit:"ชุด"},{code:"K0005",name:"เบาะยืดหยุ่น",cat:"K0000",unit:"เบาะ"},{code:"K0006",name:"ชอล์ค",cat:"K0000",unit:"กล่อง"},{code:"K0007",name:"ปากกาไวท์บอร์ด",cat:"K0000",unit:"ด้าม"},{code:"K0008",name:"กระดานไวท์บอร์ด",cat:"K0000",unit:"แผ่น"},{code:"K0009",name:"ขาตั้งกระดาน",cat:"K0000",unit:"อัน"},{code:"K0010",name:"แปรงลบกระดาน",cat:"K0000",unit:"อัน"},{code:"K0011",name:"อื่นๆ",cat:"K0000",unit:"ชิ้น"},
    {code:"L0001",name:"วาล์วดับเพลิง",cat:"L0000",unit:"อัน"},{code:"L0002",name:"ลูกบอลดับเพลิง",cat:"L0000",unit:"ลูก"},{code:"L0003",name:"ท่อส่งน้ำ",cat:"L0000",unit:"ท่อน"},{code:"L0004",name:"สายดับเพลิง",cat:"L0000",unit:"เส้น"},{code:"L0005",name:"อุปกรณ์ดับไฟป่า",cat:"L0000",unit:"ชิ้น"},{code:"L0006",name:"ถังดับเพลิง",cat:"L0000",unit:"ถัง"},{code:"L0007",name:"อื่นๆ",cat:"L0000",unit:"ชิ้น"},
    {code:"M0001",name:"เต็นท์",cat:"M0000",unit:"หลัง"},{code:"M0002",name:"ถุงนอน",cat:"M0000",unit:"ถุง"},{code:"M0003",name:"เข็มทิศ",cat:"M0000",unit:"อัน"},{code:"M0004",name:"เปลสนาม",cat:"M0000",unit:"อัน"},{code:"M0005",name:"ม้าหิน",cat:"M0000",unit:"ตัว"},{code:"M0006",name:"หญ้าเทียม",cat:"M0000",unit:"ตร.ม."},{code:"M0007",name:"โครงลวดรูปสัตว์",cat:"M0000",unit:"ตัว"},{code:"M0008",name:"อื่นๆ",cat:"M0000",unit:"ชิ้น"},
    {code:"N0001",name:"บันไดอลูมิเนียม",cat:"N0000",unit:"อัน"},{code:"N0002",name:"เครื่องมือแกะสลัก",cat:"N0000",unit:"ชุด"},{code:"N0003",name:"เครื่องมือดึงสาย",cat:"N0000",unit:"ชุด"},{code:"N0004",name:"อื่นๆ",cat:"N0000",unit:"ชิ้น"},
    {code:"O0001",name:"ฉิ่ง",cat:"O0000",unit:"คู่"},{code:"O0002",name:"ฉาบ",cat:"O0000",unit:"คู่"},{code:"O0003",name:"กรับ",cat:"O0000",unit:"คู่"},{code:"O0004",name:"อังกะลุง",cat:"O0000",unit:"ตัว"},{code:"O0005",name:"กลอง",cat:"O0000",unit:"ใบ"},{code:"O0006",name:"ลูกชัด",cat:"O0000",unit:"อัน"},{code:"O0007",name:"ปารากัส",cat:"O0000",unit:"คู่"},{code:"O0008",name:"ขลุ่ย",cat:"O0000",unit:"เลา"},{code:"O0009",name:"ขิม",cat:"O0000",unit:"ตัว"},{code:"O0010",name:"ซอ",cat:"O0000",unit:"คัน"},
    {code:"O0011",name:"จะเข้",cat:"O0000",unit:"ตัว"},{code:"O0012",name:"โทน",cat:"O0000",unit:"ใบ"},{code:"O0013",name:"โหม่ง",cat:"O0000",unit:"ใบ"},{code:"O0014",name:"ปี่มอญ",cat:"O0000",unit:"เลา"},{code:"O0015",name:"อูคูเลเล่",cat:"O0000",unit:"ตัว"},{code:"O0016",name:"อื่นๆ",cat:"O0000",unit:"ชิ้น"},
    {code:"P0001",name:"ไฟกระพริบ",cat:"P0000",unit:"ดวง"},{code:"P0002",name:"ไฟฉุกเฉิน",cat:"P0000",unit:"ดวง"},{code:"P0003",name:"กรวยจราจร",cat:"P0000",unit:"อัน"},{code:"P0004",name:"แผงกั้นจราจร",cat:"P0000",unit:"แผง"},{code:"P0005",name:"ป้ายเตือน",cat:"P0000",unit:"แผ่น"},{code:"P0006",name:"แท่นแบริเออร์",cat:"P0000",unit:"แท่น"},{code:"P0007",name:"ป้ายหยุดตรวจ",cat:"P0000",unit:"ป้าย"},{code:"P0008",name:"ป้ายจราจร",cat:"P0000",unit:"แผ่น"},{code:"P0009",name:"กระจกโค้ง",cat:"P0000",unit:"บาน"},{code:"P0010",name:"ไฟวับวาบ",cat:"P0000",unit:"ดวง"},
    {code:"P0011",name:"กระบองไฟ",cat:"P0000",unit:"อัน"},{code:"P0012",name:"ลูกระนาด",cat:"P0000",unit:"เส้น"},{code:"P0013",name:"สติ๊กเกอร์",cat:"P0000",unit:"แผ่น"},{code:"P0014",name:"อื่นๆ",cat:"P0000",unit:"ชิ้น"},
    {code:"Q0001",name:"มิเตอร์น้ำ/ไฟ",cat:"Q0000",unit:"เครื่อง"},{code:"Q0002",name:"อุปกรณ์บังคับสัตว์",cat:"Q0000",unit:"อัน"},{code:"Q0003",name:"สมอเรือ",cat:"Q0000",unit:"ตัว"},{code:"Q0004",name:"ตะแกรงกันสวะ",cat:"Q0000",unit:"แผง"},{code:"Q0005",name:"หัวเชื่อมแก๊ส",cat:"Q0000",unit:"หัว"},{code:"Q0006",name:"วาล์วแก๊ส",cat:"Q0000",unit:"หัว"},{code:"Q0007",name:"อื่นๆ",cat:"Q0000",unit:"ชิ้น"}
];

async function initDB() {
    const client = await pool.connect();
    try {
        console.log('🔧 กำลังสร้างฐานข้อมูล PostgreSQL...');

        // ===== สร้างตาราง =====
        await client.query(`
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS categories (
                code TEXT PRIMARY KEY,
                name TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS items (
                id SERIAL PRIMARY KEY,
                code TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                spec TEXT DEFAULT '-',
                cat_code TEXT NOT NULL REFERENCES categories(code),
                cat_name TEXT NOT NULL,
                unit TEXT NOT NULL,
                min_qty INTEGER DEFAULT 5,
                location TEXT DEFAULT 'กองพัสดุ',
                last_price REAL DEFAULT 0,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id SERIAL PRIMARY KEY,
                date TEXT NOT NULL,
                type TEXT NOT NULL CHECK(type IN ('IN','OUT')),
                doc_no TEXT NOT NULL,
                ref TEXT DEFAULT '',
                note TEXT DEFAULT '',
                user_name TEXT DEFAULT '',
                approver TEXT DEFAULT '',
                checker TEXT DEFAULT '',
                created_at TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS transaction_lines (
                id SERIAL PRIMARY KEY,
                tx_id INTEGER NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
                item_id INTEGER NOT NULL REFERENCES items(id),
                code TEXT NOT NULL,
                name TEXT NOT NULL,
                spec TEXT DEFAULT '-',
                unit TEXT NOT NULL,
                qty REAL NOT NULL,
                price REAL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin','user')),
                created_at TIMESTAMPTZ DEFAULT NOW()
            );

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
            );

            CREATE INDEX IF NOT EXISTS idx_items_code ON items(code);
            CREATE INDEX IF NOT EXISTS idx_items_cat ON items(cat_code);
            CREATE INDEX IF NOT EXISTS idx_tx_date ON transactions(date);
            CREATE INDEX IF NOT EXISTS idx_tx_type ON transactions(type);
            CREATE INDEX IF NOT EXISTS idx_txlines_txid ON transaction_lines(tx_id);
            CREATE INDEX IF NOT EXISTS idx_txlines_itemid ON transaction_lines(item_id);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
            CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
        `);
        console.log('✅ สร้างตารางสำเร็จ');

        // ===== Seed Categories =====
        for (const [code, name] of Object.entries(CATEGORIES)) {
            await client.query(
                `INSERT INTO categories (code, name) VALUES ($1, $2) ON CONFLICT (code) DO NOTHING`,
                [code, name]
            );
        }
        console.log('✅ เพิ่มประเภทวัสดุ 17 ประเภท');

        // ===== Seed Settings =====
        await client.query(
            `INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`,
            ['orgName', 'องค์การบริหารส่วนตำบลตัวอย่าง']
        );

        // ===== Seed Items =====
        let inserted = 0;
        for (const item of INITIAL_ITEMS) {
            const res = await client.query(
                `INSERT INTO items (code, name, spec, cat_code, cat_name, unit, min_qty, location, last_price)
                 VALUES ($1, $2, '-', $3, $4, $5, 5, 'กองพัสดุ', 0)
                 ON CONFLICT (code) DO NOTHING`,
                [item.code, item.name, item.cat, CATEGORIES[item.cat] || 'อื่นๆ', item.unit]
            );
            if (res.rowCount > 0) inserted++;
        }
        console.log(`✅ เพิ่มวัสดุ ${inserted} รายการ (มีอยู่แล้ว ${INITIAL_ITEMS.length - inserted})`);

        const countRes = await client.query('SELECT COUNT(*) as cnt FROM items');
        console.log(`\n📊 สรุป: วัสดุในฐานข้อมูล ${countRes.rows[0].cnt} รายการ`);
        console.log('🚀 พร้อมใช้งาน!');

    } finally {
        client.release();
    }
}

// Export สำหรับเรียกจาก server.js
module.exports = { initDB, CATEGORIES, INITIAL_ITEMS };

// ถ้ารันตรง
if (require.main === module) {
    initDB()
        .then(() => { console.log('\n✅ Init DB สำเร็จ'); process.exit(0); })
        .catch(err => { console.error('❌ Error:', err); process.exit(1); });
}
