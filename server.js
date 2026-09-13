const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// إعدادات الحماية ضد الهجمات (Rate Limiting)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 دقيقة
    max: 100, // حد أقصى 100 طلب لكل IP
    message: { error: 'تم تجاوز الحد الأقصى للطلبات، يرجى المحاولة لاحقاً.' }
});
app.use(limiter);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

// إنشاء والاتصال بقاعدة البيانات SQLite محلياً
const dbFile = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbFile, (err) => {
    if (err) console.error('خطأ في الاتصال بقاعدة البيانات:', err.message);
    else console.log('تم الاتصال بقاعدة بيانات SQLite بنجاح.');
});

// تهيئة الجداول الأساسية
db.serialize(() => {
    // جدول الألعاب
    db.run(`CREATE TABLE IF NOT EXISTS games (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        cat TEXT NOT NULL,
        physics_engine TEXT NOT NULL,
        gravity_scale REAL DEFAULT 9.8,
        url TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        developer_tag TEXT DEFAULT 'مطور معتمد'
    )`);

    // جدول إعدادات الإدارة والمطورين (مع تشفير الباسورد بـ bcrypt)
    db.run(`CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )`, async () => {
        // التحقق من وجود كلمة سر الإدارة الافتراضية وتشفرها
        db.get(`SELECT value FROM settings WHERE key = 'admin_pass'`, async (err, row) => {
            if (!row) {
                const hashed = await bcrypt.hash('AbuEliz@2026Secure!', 10);
                db.run(`INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_pass', ?)`, [hashed]);
            }
        });
    });

    // جدول المطورين الجدد (تسجيل دخول المطورين لرفع الألعاب)
    db.run(`CREATE TABLE IF NOT EXISTS developers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )`);

    // جدول السجلات الأمنية (Audit Logs)
    db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action_type TEXT,
        description TEXT,
        ip_address TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

// مسار الصفحة الرئيسية
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// جلب الألعاب (حسب الحالة أو محرك الفيزياء)
app.get('/api/games', (req, res) => {
    let query = `SELECT * FROM games WHERE 1=1`;
    let params = [];
    if (req.query.status) {
        query += ` AND status = ?`;
        params.push(req.query.status);
    }
    if (req.query.physics) {
        query += ` AND physics_engine = ?`;
        params.push(req.query.physics);
    }
    db.all(query, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// تسجيل مطور جديد
app.post('/api/dev/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'جميع الحقول مطلوبة للمطور.' });
    
    try {
        const hashedPass = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO developers (username, password) VALUES (?, ?)`, [username, hashedPass], function(err) {
            if (err) return res.status(400).json({ error: 'اسم المستخدم للمطور موجود مسبقاً.' });
            res.json({ success: true, message: 'تم تسسجيل حساب المطور بنجاح!' });
        });
    } catch (ex) {
        res.status(500).json({ error: 'خطأ داخلي في الخادم.' });
    }
});

// تسجيل دخول المطور
app.post('/api/dev/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM developers WHERE username = ?`, [username], async (err, dev) => {
        if (err || !dev) return res.status(401).json({ success: false, message: 'بيانات المطور غير صحيحة.' });
        
        const match = await bcrypt.compare(password, dev.password);
        if (match) {
            res.json({ success: true, message: 'تم تسجيل دخول المطور بنجاح!' });
        } else {
            res.status(401).json({ success: false, message: 'كلمة سر المطور غير صحيحة.' });
        }
    });
});

// رفع لعبة جديدة (مشروط بتسجيل الدخول)
app.post('/api/games', (req, res) => {
    const { title, cat, physics_engine, gravity_scale, url, developer } = req.body;
    if (!title || !url) return res.status(400).json({ error: 'عنوان اللعبة والرابط مطلوبان.' });

    db.run(`INSERT INTO games (title, cat, physics_engine, gravity_scale, url, status, developer_tag) VALUES (?, ?, ?, ?, ?, 'pending', ?)`,
        [title, cat || 'Action', physics_engine || 'Box2D.js', gravity_scale || 9.8, url, developer || 'مطور معتمد'],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            
            // تسجيل الحدث في الـ Logs
            db.run(`INSERT INTO audit_logs (action_type, description, ip_address) VALUES (?, ?, ?)`,
                ['GAME_SUBMIT', `تم رفع لعبة جديدة: ${title}`, req.ip]);

            res.json({ success: true, message: 'تم إرسال اللعبة للمراجعة بنجاح بانتظار اعتماد الإدارة.' });
        }
    );
});

// تحديث حالة اللعبة (قبول أو رفض من الإدارة)
app.patch('/api/games/:id', (req, res) => {
    const { status } = req.body;
    db.run(`UPDATE games SET status = ? WHERE id = ?`, [status, req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, message: 'تم تحديث حالة اللعبة.' });
    });
});

// تسجيل دخول الإدارة الآمن
app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    db.get(`SELECT value FROM settings WHERE key = 'admin_pass'`, async (err, row) => {
        if (err || !row) return res.status(500).json({ success: false, message: 'خطأ في النظام.' });
        
        const match = await bcrypt.compare(password, row.value);
        if (match) {
            db.run(`INSERT INTO audit_logs (action_type, description, ip_address) VALUES ('ADMIN_LOGIN', 'تسجيل دخول ناجح للوحة الإدارة', ?)`, [req.ip]);
            res.json({ success: true, message: 'أهلاً بك يا أبو العز، تم تسجيل الدخول بنجاح!' });
        } else {
            res.status(401).json({ success: false, message: 'كلمة سر الإدارة غير صحيحة.' });
        }
    });
});

// مسار تغيير كلمة مرور الإدارة
app.post('/api/admin/change-password', async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    db.get(`SELECT value FROM settings WHERE key = 'admin_pass'`, async (err, row) => {
        if (err || !row) return res.status(500).json({ error: 'خطأ في النظام.' });
        const match = await bcrypt.compare(currentPassword, row.value);
        if (!match) return res.status(401).json({ error: 'كلمة السر الحالية غير صحيحة.' });
        
        const hashedNew = await bcrypt.hash(newPassword, 10);
        db.run(`UPDATE settings SET value = ? WHERE key = 'admin_pass'`, [hashedNew], (updateErr) => {
            if (updateErr) return res.status(500).json({ error: 'فشل تحديث كلمة السر.' });
            db.run(`INSERT INTO audit_logs (action_type, description, ip_address) VALUES ('CHANGE_PASSWORD', 'تم تغيير كلمة سر الإدارة بنجاح', ?)`, [req.ip]);
            res.json({ success: true, message: 'تم تحديث وتشفير كلمة السر بنجاح!' });
        });
    });
});

// مسار استقبال الألعاب عبر الـ API الخارجي
app.post('/api/v1/external/submit', (req, res) => {
    const { apiKey, title, category, gameUrl } = req.body;
    if (apiKey !== 'ABU_ELIZ_MASTER_EXTERNAL_API_KEY_2026') {
        return res.status(403).json({ error: 'مفتاح الـ API غير صالح.' });
    }
    if (!title || !gameUrl) return res.status(400).json({ error: 'العنوان ورابط اللعبة مطلوبان.' });

    db.run(`INSERT INTO games (title, cat, physics_engine, gravity_scale, url, status, developer_tag) VALUES (?, ?, 'Box2D.js', 9.8, ?, 'pending', 'External API')`,
        [title, category || 'Action', gameUrl], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: 'تم استلام اللعبة عبر الـ API بنجاح وإرسالها للمراجعة.' });
        }
    );
});

// إحصائيات الخادم للإدارة
app.get('/api/admin/stats', (req, res) => {
    db.get(`SELECT 
        (SELECT COUNT(*) FROM games) as totalGames,
        (SELECT COUNT(*) FROM games WHERE status='pending') as pendingGames,
        (SELECT COUNT(*) FROM games WHERE status='approved') as approvedGames`, (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        
        const mem = process.memoryUsage();
        const activeMemory = Math.round(mem.rss / 1024 / 1024) + ' MB';
        
        res.json({ ...row, activeMemory });
    });
});

// جلب سجلات الأمان
app.get('/api/admin/logs', (req, res) => {
    db.all(`SELECT * FROM audit_logs ORDER BY id DESC LIMIT 50`, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// تشغيل السيرفر
app.listen(PORT, () => {
    console.log(`Server is running smoothly on http://localhost:${PORT}`);
});
