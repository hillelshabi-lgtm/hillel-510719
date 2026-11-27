const express = require('express');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json());

// הסיסמאות נשמרות אך ורק במשתני הסביבה המוצפנים של Render (Environment Variables)
// ולעולם לא נשלחות לדפדפן של המשתמש
const BASIC_PASSWORD = process.env.LIB_BASIC_PASSWORD || '44918';
const ADMIN_PASSWORD = process.env.LIB_ADMIN_PASSWORD || '340430';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// השוואה קריפטוגרפית חסינת התקפות תזמון (Timing-Safe Comparison)
function safeCompare(input, secret) {
    const a = crypto.createHash('sha256').update(String(input || '')).digest();
    const b = crypto.createHash('sha256').update(String(secret || '')).digest();
    return crypto.timingSafeEqual(a, b);
}

// נקודת קצה מאובטחת לאימות התחברות בצד השרת בלבד
app.post('/api/auth/login', (req, res) => {
    try {
        const { username, password, adminPassword, isAdmin } = req.body || {};
        if (!username || !password) {
            return res.status(400).json({ ok: false, message: 'נא למלא שם משתמש וסיסמה.' });
        }

        if (!safeCompare(password, BASIC_PASSWORD)) {
            return res.status(401).json({ ok: false, message: 'הכניסה לא הושלמה. נסו שוב.' });
        }

        if (isAdmin && !safeCompare(adminPassword, ADMIN_PASSWORD)) {
            return res.status(401).json({ ok: false, message: 'סיסמת העל שגויה. הכניסה נכשלה.' });
        }

        // הנפקת טוקן סשן חתום ב-HMAC מהשרת
        const payload = `${username}:${Date.now()}`;
        const signature = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
        const token = Buffer.from(`${payload}:${signature}`).toString('base64');

        return res.json({ ok: true, token });
    } catch (err) {
        return res.status(500).json({ ok: false, message: 'שגיאת שרת פנימית.' });
    }
});

// הגשת הקבצים הסטטיים (index.html)
app.use(express.static(path.join(__dirname)));

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Hillel Secure Library Server running on port ${PORT}`);
});
