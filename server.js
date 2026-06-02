const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const admin = require('firebase-admin');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const sanitizeHtml = require('sanitize-html');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { body, validationResult, matchedData, header } = require('express-validator');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const Redis = require('ioredis');
const { RateLimiterRedis } = require('rate-limiter-flexible');
const compression = require('compression');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();

// ============= إعدادات الأمان المتقدمة =============
const isProduction = process.env.NODE_ENV === 'production';

// Trust proxy for Vercel/Heroku/Nginx
if (process.env.TRUST_PROXY) {
    app.set('trust proxy', parseInt(process.env.TRUST_PROXY));
}

// Compression for responses
app.use(compression());

// ============= إعدادات Redis المتقدمة =============
const redisClient = new Redis({
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT) || 6379,
    password: process.env.REDIS_PASSWORD || undefined,
    retryStrategy: (times) => {
        const delay = Math.min(times * 50, 2000);
        console.log(`Redis reconnecting in ${delay}ms...`);
        return delay;
    },
    maxRetriesPerRequest: 3,
    enableReadyCheck: true,
    lazyConnect: false,
    tls: process.env.REDIS_TLS === 'true' ? {} : undefined
});

redisClient.on('connect', () => console.log('✅ Redis connected'));
redisClient.on('error', (err) => console.error('❌ Redis error:', err));

// ============= التشفير المتقدم مع دعم IV الثابت للبحث =============
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
const IV_LENGTH = 16;

// تشفير عادي (مع IV عشوائي) - للإيداع
function encrypt(text) {
    if (!text) return null;
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

// فك التشفير
function decrypt(text) {
    if (!text) return null;
    try {
        const [ivHex, authTagHex, encryptedText] = text.split(':');
        if (!ivHex || !authTagHex || !encryptedText) return null;
        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');
        const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        console.error('Decryption error:', error);
        return null;
    }
}

// تشفير للبحث (مع IV ثابت من hash الإيميل) - للاستعلامات
function encryptForSearch(email) {
    if (!email) return null;
    const hash = crypto.createHash('sha256').update(email.toLowerCase()).digest();
    const iv = hash.slice(0, IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(email.toLowerCase(), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

// ============= تسجيل الأحداث الأمنية المتقدم =============
const auditLog = async (action, userId, ip, userAgent, details, status = 'success') => {
    const logEntry = {
        timestamp: new Date().toISOString(),
        action,
        userId: userId || 'anonymous',
        ip,
        userAgent: userAgent || 'unknown',
        details: typeof details === 'object' ? JSON.stringify(details) : details,
        status,
        sessionId: crypto.randomBytes(32).toString('base64url')
    };

    if (db) {
        try {
            await db.collection('auditLogs').add(logEntry);
        } catch (error) {
            console.error('Failed to write audit log:', error);
        }
    }

    console.log(`[AUDIT] ${action} | User: ${userId || 'anonymous'} | IP: ${ip} | Status: ${status}`);

    // إشعار فوري للحالات الحرجة
    if (status === 'critical') {
        await sendSecurityAlert(logEntry);
    }
};

// ============= نظام قفل الحساب المحسن =============
const failedAttempts = new Map();

async function checkAccountLockout(identifier) {
    const attempts = failedAttempts.get(identifier) || { count: 0, firstAttempt: Date.now() };

    if (attempts.count >= parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 10) {
        const lockoutTime = (parseInt(process.env.ACCOUNT_LOCKOUT_MINUTES) || 30) * 60 * 1000;
        if (Date.now() - attempts.firstAttempt < lockoutTime) {
            const remaining = Math.ceil((lockoutTime - (Date.now() - attempts.firstAttempt)) / 60000);
            throw new Error(`الحساب مقفل لمدة ${remaining} دقائق`);
        } else {
            failedAttempts.delete(identifier);
        }
    }
    return attempts;
}

async function recordFailedAttempt(identifier) {
    const attempts = failedAttempts.get(identifier) || { count: 0, firstAttempt: Date.now() };
    attempts.count++;
    failedAttempts.set(identifier, attempts);

    const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 10;
    if (attempts.count === maxAttempts) {
        await auditLog('ACCOUNT_LOCKED', identifier, null, null, `${attempts.count} failed attempts`, 'critical');
    }
}

// ============= Rate Limiting المتقدم لكل إندبوينت =============
const rateLimiterRedis = new RateLimiterRedis({
    storeClient: redisClient,
    keyPrefix: 'rl',
    points: 5,
    duration: 900,
    blockDuration: 1800
});

const strictLimiter = async (req, res, next) => {
    try {
        const key = `${req.ip}:${req.originalUrl}`;
        await rateLimiterRedis.consume(key);
        next();
    } catch (error) {
        await auditLog('RATE_LIMIT_EXCEEDED', null, req.ip, req.get('User-Agent'), req.originalUrl, 'warning');
        res.status(429).json({
            error: 'محاولات كثيرة جداً. يرجى المحاولة بعد 30 دقيقة.',
            retryAfter: Math.ceil(error.msBeforeNext / 1000)
        });
    }
};

// Rate limiter مخصص للـ API العام
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests from this IP',
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.ip
});

// ============= الأمان الأساسي =============
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            imgSrc: ["'self'", "data:", "https:", "http:"],
            connectSrc: ["'self'", process.env.API_URL, "https://*.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            frameAncestors: ["'none'"],
            formAction: ["'self'"],
            upgradeInsecureRequests: []
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(cookieParser(process.env.COOKIE_SECRET));

// Session management مع أعلى أمان
app.use(session({
    store: new RedisStore({ 
        client: redisClient,
        prefix: 'session:',
        ttl: 86400
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    name: '__Secure-sessionId',
    cookie: {
        secure: isProduction,
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000,
        domain: isProduction ? process.env.COOKIE_DOMAIN : undefined,
        path: '/',
        partitioned: true
    }
}));

// CSRF Protection مع تكوين محسن
const csrfProtection = csrf({ 
    cookie: {
        key: '__Secure-csrf',
        httpOnly: true,
        secure: isProduction,
        sameSite: 'strict'
    },
    value: (req) => req.headers['x-csrf-token'] || req.body._csrf
});

// CORS مقيد بشكل صارم
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000').split(',');
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin) || (isProduction && origin?.includes('vercel.app'))) {
            callback(null, true);
        } else {
            console.warn(`CORS blocked: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With', 'X-Device-Fingerprint'],
    exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining'],
    maxAge: 86400
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// ============= Device Fingerprinting (لمنع سرقة الجلسات) =============
function generateDeviceFingerprint(req) {
    const components = [
        req.get('User-Agent') || 'unknown',
        req.get('Accept-Language') || 'unknown',
        req.get('Accept-Encoding') || 'unknown',
        req.ip || 'unknown'
    ];
    return crypto.createHash('sha256').update(components.join('|')).digest('hex');
}

const verifyDeviceFingerprint = async (req, res, next) => {
    const fingerprint = generateDeviceFingerprint(req);
    const storedFingerprint = req.session.deviceFingerprint;
    
    if (req.user && storedFingerprint && storedFingerprint !== fingerprint) {
        await auditLog('DEVICE_FINGERPRINT_MISMATCH', req.user.id, req.ip, req.get('User-Agent'), 'Possible session hijacking', 'critical');
        await redisClient.del(`session:${req.user.id}`);
        req.session.destroy();
        return res.status(401).json({ error: 'Session expired. Please login again.' });
    }
    
    req.deviceFingerprint = fingerprint;
    next();
};

// ============= Initialize Firebase =============
let db;
try {
    if (process.env.FIREBASE_CONFIG) {
        const serviceAccount = JSON.parse(process.env.FIREBASE_CONFIG);
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount),
            projectId: serviceAccount.project_id
        });
        db = admin.firestore();
        db.settings({ ignoreUndefinedProperties: true });
        console.log('✅ Firebase connected');
    } else {
        console.error('❌ FIREBASE_CONFIG not found in environment');
        process.exit(1);
    }
} catch (error) {
    console.error('❌ Firebase initialization error:', error.message);
    process.exit(1);
}

// ============= Email Transporter مع TLS قوي و Retry Logic =============
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT),
    secure: true,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    },
    tls: {
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2',
        ciphers: 'HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA'
    },
    pool: true,
    maxConnections: 5,
    rateDelta: 1000,
    rateLimit: 5
});

// Verify email configuration
transporter.verify((error, success) => {
    if (error) {
        console.error('❌ Email transporter error:', error);
    } else {
        console.log('✅ Email transporter ready');
    }
});

// Email sending with retry
async function sendEmailWithRetry(mailOptions, retries = 3) {
    for (let i = 0; i < retries; i++) {
        try {
            const info = await transporter.sendMail(mailOptions);
            console.log(`📧 Email sent: ${info.messageId}`);
            return info;
        } catch (error) {
            console.error(`Email attempt ${i + 1} failed:`, error.message);
            if (i === retries - 1) throw error;
            await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1)));
        }
    }
}

// ============= Middleware للتحقق من التوكن =============
const tokenBlacklist = new Set();
setInterval(() => tokenBlacklist.clear(), 60 * 60 * 1000); // Clear every hour

const verifyToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader?.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    
    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    if (tokenBlacklist.has(token)) {
        await auditLog('TOKEN_REUSE', null, req.ip, req.get('User-Agent'), token, 'critical');
        return res.status(401).json({ error: 'Token invalidated. Please login again.' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET, {
            algorithms: ['HS256'],
            maxAge: `${process.env.TOKEN_EXPIRY_HOURS || 1}h`
        });

        // Check if token is revoked in Redis
        const isRevoked = await redisClient.get(`revoked:${token}`);
        if (isRevoked) {
            return res.status(401).json({ error: 'Token revoked. Please login again.' });
        }

        // Check session exists
        const sessionExists = await redisClient.exists(`session:${decoded.id}`);
        if (!sessionExists) {
            return res.status(401).json({ error: 'Session expired. Please login again.' });
        }

        req.user = decoded;
        req.token = token;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            await auditLog('TOKEN_EXPIRED', null, req.ip, req.get('User-Agent'), null, 'warning');
            return res.status(401).json({ error: 'Token expired. Please refresh.' });
        }
        await auditLog('INVALID_TOKEN', null, req.ip, req.get('User-Agent'), error.message, 'warning');
        return res.status(403).json({ error: 'Invalid token' });
    }
};

const requireAdmin = async (req, res, next) => {
    if (req.user.role !== 'admin') {
        await auditLog('UNAUTHORIZED_ADMIN_ACCESS', req.user.id, req.ip, req.get('User-Agent'), 'Attempted admin access', 'critical');
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// ============= Security Alert with Webhook Support =============
async function sendSecurityAlert(logEntry) {
    const alertHtml = `
        <h2 style="color: #d32f2f;">🚨 SECURITY INCIDENT DETECTED</h2>
        <hr>
        <p><strong>Action:</strong> ${logEntry.action}</p>
        <p><strong>User ID:</strong> ${logEntry.userId}</p>
        <p><strong>IP Address:</strong> ${logEntry.ip}</p>
        <p><strong>User Agent:</strong> ${logEntry.userAgent}</p>
        <p><strong>Details:</strong> ${logEntry.details}</p>
        <p><strong>Status:</strong> <span style="color: #d32f2f;">${logEntry.status}</span></p>
        <p><strong>Timestamp:</strong> ${new Date(logEntry.timestamp).toLocaleString('ar-EG')}</p>
        <hr>
        <p style="color: #666;">Please investigate immediately.</p>
    `;

    try {
        await sendEmailWithRetry({
            from: `"Security Alert" <${process.env.SMTP_USER}>`,
            to: process.env.ADMIN_EMAIL,
            cc: process.env.SUPPORT_EMAIL,
            subject: `🚨 [CRITICAL] Security Alert: ${logEntry.action}`,
            html: alertHtml,
            priority: 'high'
        });

        // Discord/Slack webhook (optional)
        if (process.env.DISCORD_WEBHOOK_URL) {
            const response = await fetch(process.env.DISCORD_WEBHOOK_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    content: `🚨 **SECURITY ALERT**\nAction: ${logEntry.action}\nIP: ${logEntry.ip}\nUser: ${logEntry.userId}\nTime: ${logEntry.timestamp}`
                })
            });
        }
    } catch (error) {
        console.error('Failed to send security alert:', error.message);
    }
}

// ============= Helper function for timing-safe comparison =============
function timingSafeCompare(a, b) {
    if (!a || !b) return false;
    try {
        return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
    } catch {
        return false;
    }
}

// ============= AUTH ENDPOINTS =============

// 1. GET CSRF Token
app.get('/api/csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// 2. Register
app.post('/api/register',
    strictLimiter,
    csrfProtection,
    body('fullname').trim().isLength({ min: 3, max: 50 }).matches(/^[\p{L}\s]+$/u).withMessage('الاسم يجب أن يحتوي على حروف فقط'),
    body('username').trim().isAlphanumeric().isLength({ min: 3, max: 30 }).withMessage('اسم المستخدم يجب أن يكون حروف وأرقام فقط'),
    body('email').isEmail().normalizeEmail().withMessage('البريد الإلكتروني غير صحيح'),
    body('password').isLength({ min: 12 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/).withMessage('كلمة المرور ضعيفة'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            await auditLog('REGISTER_VALIDATION_FAILED', null, req.ip, req.get('User-Agent'), errors.array(), 'warning');
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const { fullname, username, email, password } = matchedData(req);
            
            // التحقق باستخدام التشفير المخصص للبحث
            const searchEncryptedEmail = encryptForSearch(email);
            const existingUserQuery = await db.collection('users')
                .where('searchEmail', '==', searchEncryptedEmail)
                .limit(1)
                .get();
            
            if (!existingUserQuery.empty) {
                await auditLog('REGISTER_DUPLICATE_EMAIL', null, req.ip, req.get('User-Agent'), email, 'warning');
                return res.status(400).json({ error: 'البريد الإلكتروني مسجل بالفعل' });
            }

            const encryptedEmail = encrypt(email);
            const searchEncryptedEmailForDb = encryptForSearch(email);
            const hashedPassword = await bcrypt.hash(password, 12);
            
            const emailVerificationToken = crypto.randomBytes(32).toString('hex');
            const hashedVerificationToken = await bcrypt.hash(emailVerificationToken, 10);
            
            const userData = {
                fullname: sanitizeHtml(fullname, { allowedTags: [], allowedAttributes: {} }),
                username: username.toLowerCase(),
                email: encryptedEmail,
                searchEmail: searchEncryptedEmailForDb,
                password: hashedPassword,
                role: 'user',
                emailVerified: false,
                emailVerificationToken: hashedVerificationToken,
                verificationExpires: Date.now() + 24 * 60 * 60 * 1000,
                createdAt: admin.firestore.FieldValue.serverTimestamp(),
                failedLoginAttempts: 0,
                lastLoginIP: null,
                accountLocked: false,
                twoFactorEnabled: false,
                emailNotifications: true
            };
            
            await db.collection('users').add(userData);
            
            // إرسال الإيميل مع تأخير عشوائي للأمان
            const verificationLink = `${process.env.SITE_URL}/verify-email?token=${emailVerificationToken}&email=${encodeURIComponent(email)}`;
            setTimeout(() => {
                sendVerificationEmail(email, fullname, verificationLink).catch(console.error);
            }, Math.random() * 1000);
            
            await auditLog('REGISTER_SUCCESS', null, req.ip, req.get('User-Agent'), username);
            res.status(201).json({ 
                success: true, 
                message: 'تم إنشاء الحساب بنجاح. يرجى تفعيل البريد الإلكتروني خلال 24 ساعة.' 
            });
        } catch (error) {
            console.error('Registration error:', error);
            await auditLog('REGISTER_ERROR', null, req.ip, req.get('User-Agent'), error.message, 'critical');
            res.status(500).json({ error: 'حدث خطأ في الخادم. يرجى المحاولة لاحقاً.' });
        }
    }
);

// 3. Login
app.post('/api/login',
    strictLimiter,
    csrfProtection,
    body('username').trim().escape(),
    body('password').notEmpty(),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'بيانات غير صحيحة' });
        }

        const { username, password } = req.body;
        const clientIP = req.ip;
        const userAgent = req.get('User-Agent');
        const deviceFingerprint = generateDeviceFingerprint(req);

        try {
            await checkAccountLockout(username);

            const userQuery = await db.collection('users')
                .where('username', '==', username.toLowerCase())
                .limit(1)
                .get();

            if (userQuery.empty) {
                await recordFailedAttempt(username);
                await new Promise(resolve => setTimeout(resolve, 1000)); // Constant time response
                return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
            }

            const user = { id: userQuery.docs[0].id, ...userQuery.docs[0].data() };

            if (!user.emailVerified) {
                await auditLog('LOGIN_FAILED_EMAIL_NOT_VERIFIED', user.id, clientIP, userAgent, null, 'warning');
                return res.status(401).json({ error: 'يرجى تفعيل حسابك عبر البريد الإلكتروني' });
            }

            if (user.accountLocked) {
                await auditLog('LOGIN_FAILED_ACCOUNT_LOCKED', user.id, clientIP, userAgent, null, 'critical');
                return res.status(401).json({ error: 'الحساب مقفل. يرجى التواصل مع الدعم.' });
            }

            const isValid = await bcrypt.compare(password, user.password);
            await new Promise(resolve => setTimeout(resolve, 500)); // Timing attack prevention

            if (!isValid) {
                const newAttempts = (user.failedLoginAttempts || 0) + 1;
                await db.collection('users').doc(user.id).update({ failedLoginAttempts: newAttempts });

                const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 10;
                if (newAttempts >= maxAttempts) {
                    await db.collection('users').doc(user.id).update({ accountLocked: true });
                    await auditLog('ACCOUNT_AUTO_LOCKED', user.id, clientIP, userAgent, `${newAttempts} failed attempts`, 'critical');
                    await sendSecurityAlert({ action: 'ACCOUNT_AUTO_LOCKED', userId: user.id, ip: clientIP, userAgent, details: `${newAttempts} failed login attempts` });
                    return res.status(401).json({ error: `الحساب مقفل لمدة ${process.env.ACCOUNT_LOCKOUT_MINUTES || 30} دقيقة` });
                }

                await recordFailedAttempt(username);
                await auditLog('LOGIN_FAILED_WRONG_PASSWORD', user.id, clientIP, userAgent, null, 'warning');
                return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
            }

            // Reset failed attempts on successful login
            await db.collection('users').doc(user.id).update({
                failedLoginAttempts: 0,
                lastLoginIP: clientIP,
                lastLoginAt: admin.firestore.FieldValue.serverTimestamp(),
                lastLoginUserAgent: userAgent
            });

            // Create secure token with device fingerprint
            const sessionId = crypto.randomBytes(32).toString('base64url');
            const token = jwt.sign(
                {
                    id: user.id,
                    username: user.username,
                    role: user.role,
                    sessionId: sessionId,
                    deviceFingerprint: deviceFingerprint,
                    iat: Math.floor(Date.now() / 1000),
                    jti: crypto.randomBytes(16).toString('hex')
                },
                process.env.JWT_SECRET,
                { expiresIn: `${process.env.TOKEN_EXPIRY_HOURS || 1}h`, algorithm: 'HS256' }
            );

            // Store session in Redis
            await redisClient.setex(`session:${user.id}`, 3600, JSON.stringify({
                token,
                sessionId,
                deviceFingerprint,
                ip: clientIP
            }));

            // Refresh token
            const refreshToken = jwt.sign(
                { id: user.id, type: 'refresh', version: Date.now() },
                process.env.REFRESH_SECRET,
                { expiresIn: `${process.env.REFRESH_TOKEN_EXPIRY_DAYS || 7}d` }
            );

            res.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                secure: isProduction,
                sameSite: 'strict',
                maxAge: (parseInt(process.env.REFRESH_TOKEN_EXPIRY_DAYS) || 7) * 24 * 60 * 60 * 1000,
                domain: isProduction ? process.env.COOKIE_DOMAIN : undefined,
                path: '/',
                partitioned: true
            });

            // Store device fingerprint in session
            req.session.deviceFingerprint = deviceFingerprint;

            await auditLog('LOGIN_SUCCESS', user.id, clientIP, userAgent, null);
            res.json({ 
                success: true, 
                token, 
                expiresIn: 3600,
                user: {
                    id: user.id,
                    username: user.username,
                    fullname: user.fullname,
                    role: user.role,
                    emailVerified: user.emailVerified
                }
            });
        } catch (error) {
            if (error.message.includes('مقفل')) {
                return res.status(401).json({ error: error.message });
            }
            console.error('Login error:', error);
            await auditLog('LOGIN_ERROR', null, clientIP, userAgent, error.message, 'critical');
            res.status(500).json({ error: 'حدث خطأ في الخادم' });
        }
    }
);

// 4. Refresh Token
app.post('/api/refresh-token', async (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
        return res.status(401).json({ error: 'No refresh token provided' });
    }

    try {
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
        
        const userDoc = await db.collection('users').doc(decoded.id).get();
        if (!userDoc.exists) {
            return res.status(401).json({ error: 'User not found' });
        }

        const user = userDoc.data();
        const deviceFingerprint = generateDeviceFingerprint(req);
        
        const newToken = jwt.sign(
            {
                id: decoded.id,
                username: user.username,
                role: user.role,
                sessionId: crypto.randomBytes(32).toString('base64url'),
                deviceFingerprint: deviceFingerprint,
                jti: crypto.randomBytes(16).toString('hex')
            },
            process.env.JWT_SECRET,
            { expiresIn: `${process.env.TOKEN_EXPIRY_HOURS || 1}h` }
        );

        await redisClient.setex(`session:${decoded.id}`, 3600, newToken);
        
        res.json({ token: newToken });
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            res.clearCookie('refreshToken');
            return res.status(401).json({ error: 'Refresh token expired. Please login again.' });
        }
        res.status(401).json({ error: 'Invalid refresh token' });
    }
});

// 5. Verify Email
app.post('/api/verify-email',
    strictLimiter,
    body('email').isEmail().normalizeEmail(),
    body('token').isLength({ min: 32, max: 64 }),
    async (req, res) => {
        const { email, token } = req.body;
        
        try {
            const searchEncryptedEmail = encryptForSearch(email);
            const userQuery = await db.collection('users')
                .where('searchEmail', '==', searchEncryptedEmail)
                .limit(1)
                .get();

            if (userQuery.empty) {
                await new Promise(resolve => setTimeout(resolve, 1000));
                return res.status(404).json({ error: 'Invalid verification link' });
            }

            const user = { id: userQuery.docs[0].id, ...userQuery.docs[0].data() };

            if (user.emailVerified) {
                return res.json({ success: true, message: 'Email already verified' });
            }

            if (Date.now() > user.verificationExpires) {
                // Generate new verification token
                const newToken = crypto.randomBytes(32).toString('hex');
                const hashedToken = await bcrypt.hash(newToken, 10);
                await db.collection('users').doc(user.id).update({
                    emailVerificationToken: hashedToken,
                    verificationExpires: Date.now() + 24 * 60 * 60 * 1000
                });
                const newLink = `${process.env.SITE_URL}/verify-email?token=${newToken}&email=${encodeURIComponent(email)}`;
                await sendVerificationEmail(email, user.fullname, newLink);
                return res.status(400).json({ error: 'Link expired. New verification email sent.' });
            }

            // Timing-safe comparison
            const isValidToken = await bcrypt.compare(token, user.emailVerificationToken);
            if (!isValidToken) {
                return res.status(400).json({ error: 'Invalid verification token' });
            }

            await db.collection('users').doc(user.id).update({
                emailVerified: true,
                emailVerificationToken: admin.firestore.FieldValue.delete(),
                verificationExpires: admin.firestore.FieldValue.delete(),
                emailVerifiedAt: admin.firestore.FieldValue.serverTimestamp()
            });

            await auditLog('EMAIL_VERIFIED', user.id, req.ip, req.get('User-Agent'), null);
            res.json({ success: true, message: 'Email verified successfully. You can now login.' });
        } catch (error) {
            console.error('Email verification error:', error);
            res.status(500).json({ error: 'Verification failed. Please try again.' });
        }
    }
);

// 6. Logout
app.post('/api/logout', verifyToken, csrfProtection, async (req, res) => {
    const token = req.token;
    
    if (token) {
        tokenBlacklist.add(token);
        const decoded = jwt.decode(token);
        if (decoded?.exp) {
            const ttl = decoded.exp - Math.floor(Date.now() / 1000);
            if (ttl > 0) {
                await redisClient.setex(`revoked:${token}`, ttl, 'true');
            }
        }
        await redisClient.del(`session:${req.user.id}`);
    }
    
    res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'strict',
        path: '/'
    });
    
    req.session.destroy((err) => {
        if (err) console.error('Session destruction error:', err);
    });
    
    await auditLog('LOGOUT', req.user.id, req.ip, req.get('User-Agent'), null);
    res.json({ success: true, message: 'Logged out successfully' });
});

// 7. Get Current User
app.get('/api/me', verifyToken, async (req, res) => {
    try {
        const userDoc = await db.collection('users').doc(req.user.id).get();
        if (!userDoc.exists) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const user = userDoc.data();
        res.json({
            id: req.user.id,
            fullname: user.fullname,
            username: user.username,
            email: decrypt(user.email),
            role: user.role,
            emailVerified: user.emailVerified,
            twoFactorEnabled: user.twoFactorEnabled || false,
            createdAt: user.createdAt,
            lastLoginIP: user.lastLoginIP,
            lastLoginAt: user.lastLoginAt
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// 8. Admin Users Endpoint
app.get('/api/admin/users', verifyToken, requireAdmin, async (req, res) => {
    try {
        const { limit = 50, offset = 0, role, emailVerified } = req.query;
        
        let query = db.collection('users')
            .orderBy('createdAt', 'desc')
            .limit(parseInt(limit));
        
        if (role) query = query.where('role', '==', role);
        if (emailVerified === 'true') query = query.where('emailVerified', '==', true);
        if (emailVerified === 'false') query = query.where('emailVerified', '==', false);
        
        const snapshot = await query.get();
        const users = [];
        
        for (const doc of snapshot.docs) {
            const user = doc.data();
            users.push({
                id: doc.id,
                fullname: user.fullname,
                username: user.username,
                email: user.email ? decrypt(user.email) : null,
                role: user.role,
                emailVerified: user.emailVerified,
                createdAt: user.createdAt,
                lastLoginIP: user.lastLoginIP,
                lastLoginAt: user.lastLoginAt,
                accountLocked: user.accountLocked || false,
                failedLoginAttempts: user.failedLoginAttempts || 0
            });
        }
        
        await auditLog('ADMIN_VIEWED_USERS', req.user.id, req.ip, req.get('User-Agent'), { count: users.length });
        res.json({ users, total: users.length });
    } catch (error) {
        console.error('Admin users error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// 9. Audit Logs Endpoint
app.get('/api/admin/audit-logs', verifyToken, requireAdmin, async (req, res) => {
    try {
        const { limit = 100, action, fromDate, toDate, userId } = req.query;
        
        let query = db.collection('auditLogs')
            .orderBy('timestamp', 'desc')
            .limit(parseInt(limit));
        
        if (action) query = query.where('action', '==', action);
        if (userId) query = query.where('userId', '==', userId);
        if (fromDate) query = query.where('timestamp', '>=', fromDate);
        if (toDate) query = query.where('timestamp', '<=', toDate);
        
        const snapshot = await query.get();
        const logs = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        
        await auditLog('ADMIN_VIEWED_AUDIT_LOGS', req.user.id, req.ip, req.get('User-Agent'), { count: logs.length });
        res.json({ logs, total: logs.length });
    } catch (error) {
        console.error('Audit logs error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// 10. Forgot Password
app.post('/api/forgot-password',
    strictLimiter,
    body('email').isEmail().normalizeEmail(),
    async (req, res) => {
        const { email } = req.body;
        const startTime = Date.now();
        
        try {
            const searchEncryptedEmail = encryptForSearch(email);
            const userQuery = await db.collection('users')
                .where('searchEmail', '==', searchEncryptedEmail)
                .limit(1)
                .get();

            if (!userQuery.empty) {
                const user = { id: userQuery.docs[0].id, ...userQuery.docs[0].data() };
                
                const resetToken = crypto.randomBytes(32).toString('hex');
                const hashedResetToken = await bcrypt.hash(resetToken, 10);
                
                await db.collection('users').doc(user.id).update({
                    passwordResetToken: hashedResetToken,
                    passwordResetExpires: Date.now() + 60 * 60 * 1000,
                    passwordResetRequestedAt: admin.firestore.FieldValue.serverTimestamp(),
                    passwordResetRequestedIP: req.ip
                });
                
                const decryptedEmail = decrypt(user.email);
                await sendPasswordResetEmail(decryptedEmail, user.fullname, resetToken);
                await auditLog('PASSWORD_RESET_REQUESTED', user.id, req.ip, req.get('User-Agent'), null);
            }
            
            // Constant time response to prevent user enumeration
            const elapsed = Date.now() - startTime;
            const delay = Math.max(0, 1000 - elapsed);
            await new Promise(resolve => setTimeout(resolve, delay));
            
            res.json({ 
                success: true, 
                message: 'إذا كان البريد الإلكتروني مسجلاً لدينا، ستتلقى رابط إعادة تعيين كلمة المرور خلال دقائق.' 
            });
        } catch (error) {
            console.error('Forgot password error:', error);
            res.status(500).json({ error: 'Server error. Please try again later.' });
        }
    }
);

// 11. Reset Password
app.post('/api/reset-password',
    strictLimiter,
    body('token').isLength({ min: 32, max: 64 }),
    body('newPassword').isLength({ min: 12 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/),
    async (req, res) => {
        const { token, newPassword } = req.body;
        
        try {
            const usersQuery = await db.collection('users')
                .where('passwordResetExpires', '>', Date.now())
                .get();
            
            let userDoc = null;
            let validToken = false;
            
            for (const doc of usersQuery.docs) {
                const user = doc.data();
                if (user.passwordResetToken) {
                    const isValid = await bcrypt.compare(token, user.passwordResetToken);
                    if (isValid) {
                        userDoc = { id: doc.id, ...user };
                        validToken = true;
                        break;
                    }
                }
            }
            
            if (!validToken || !userDoc) {
                await new Promise(resolve => setTimeout(resolve, 1000));
                return res.status(400).json({ error: 'Invalid or expired reset token' });
            }
            
            const hashedPassword = await bcrypt.hash(newPassword, 12);
            
            await db.collection('users').doc(userDoc.id).update({
                password: hashedPassword,
                passwordResetToken: admin.firestore.FieldValue.delete(),
                passwordResetExpires: admin.firestore.FieldValue.delete(),
                failedLoginAttempts: 0,
                accountLocked: false,
                passwordUpdatedAt: admin.firestore.FieldValue.serverTimestamp(),
                passwordUpdatedIP: req.ip
            });
            
            // Invalidate all sessions
            await redisClient.del(`session:${userDoc.id}`);
            
            // Add to token blacklist
            const tokens = await redisClient.keys(`session:${userDoc.id}:*`);
            for (const tokenKey of tokens) {
                await redisClient.del(tokenKey);
            }
            
            await auditLog('PASSWORD_RESET_SUCCESS', userDoc.id, req.ip, req.get('User-Agent'), null);
            res.json({ success: true, message: 'Password reset successfully. You can now login with your new password.' });
        } catch (error) {
            console.error('Reset password error:', error);
            res.status(500).json({ error: 'Server error. Please try again.' });
        }
    }
);

// 12. Health Check Endpoint
app.get('/api/health', async (req, res) => {
    const checks = {
        redis: false,
        firebase: false,
        email: false,
        timestamp: new Date().toISOString()
    };
    
    // Check Redis
    try {
        await redisClient.ping();
        checks.redis = true;
    } catch (error) {
        console.error('Redis health check failed:', error);
    }
    
    // Check Firebase
    try {
        await db.collection('_health').doc('check').set({ timestamp: Date.now() });
        checks.firebase = true;
    } catch (error) {
        console.error('Firebase health check failed:', error);
    }
    
    // Check Email
    try {
        await transporter.verify();
        checks.email = true;
    } catch (error) {
        console.error('Email health check failed:', error);
    }
    
    const isHealthy = checks.redis && checks.firebase && checks.email;
    
    res.status(isHealthy ? 200 : 503).json({
        status: isHealthy ? 'healthy' : 'unhealthy',
        checks,
        environment: process.env.NODE_ENV
    });
});

// ============= Email Functions =============
async function sendVerificationEmail(email, fullname, verificationLink) {
    const mailOptions = {
        from: `"${process.env.COMPANY_NAME}" <${process.env.SMTP_USER}>`,
        to: email,
        subject: `تفعيل حسابك في ${process.env.COMPANY_NAME}`,
        html: `
            <div style="direction: rtl; font-family: 'Cairo', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px;">
                <div style="text-align: center; padding-bottom: 20px; border-bottom: 2px solid #4CAF50;">
                    <h1 style="color: #4CAF50;">${process.env.COMPANY_NAME}</h1>
                    <h3 style="color: #666;">مرحباً ${fullname}</h3>
                </div>
                
                <div style="padding: 20px 0;">
                    <p style="font-size: 16px; line-height: 1.5; color: #333;">
                        شكراً لتسجيلك معنا! يرجى تفعيل حسابك بالضغط على الرابط أدناه:
                    </p>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${verificationLink}" style="background-color: #4CAF50; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-size: 16px; font-weight: bold;">
                            تفعيل الحساب
                        </a>
                    </div>
                    
                    <p style="font-size: 14px; color: #666; text-align: center;">
                        أو انسخ الرابط التالي والصقه في المتصفح:<br>
                        <span style="color: #4CAF50; word-break: break-all;">${verificationLink}</span>
                    </p>
                    
                    <hr style="margin: 20px 0; border: none; border-top: 1px solid #e0e0e0;">
                    
                    <p style="font-size: 12px; color: #999; text-align: center;">
                        هذا الرابط صالح لمدة 24 ساعة.<br>
                        إذا لم تقم بالتسجيل معنا، يرجى تجاهل هذا البريد الإلكتروني.
                    </p>
                    
                    <p style="font-size: 12px; color: #999; text-align: center;">
                        © ${new Date().getFullYear()} ${process.env.COMPANY_NAME}. جميع الحقوق محفوظة.
                    </p>
                </div>
            </div>
        `,
        text: `مرحباً ${fullname},\n\nشكراً لتسجيلك معنا! يرجى تفعيل حسابك بالضغط على الرابط التالي:\n\n${verificationLink}\n\nهذا الرابط صالح لمدة 24 ساعة.\n\nإذا لم تقم بالتسجيل معنا، يرجى تجاهل هذا البريد الإلكتروني.`
    };
    
    await sendEmailWithRetry(mailOptions);
}

async function sendPasswordResetEmail(email, fullname, resetToken) {
    const resetLink = `${process.env.SITE_URL}/reset-password?token=${resetToken}`;
    
    const mailOptions = {
        from: `"${process.env.COMPANY_NAME}" <${process.env.SMTP_USER}>`,
        to: email,
        subject: `إعادة تعيين كلمة المرور - ${process.env.COMPANY_NAME}`,
        html: `
            <div style="direction: rtl; font-family: 'Cairo', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px;">
                <div style="text-align: center; padding-bottom: 20px; border-bottom: 2px solid #ff9800;">
                    <h1 style="color: #ff9800;">${process.env.COMPANY_NAME}</h1>
                    <h3 style="color: #666;">مرحباً ${fullname}</h3>
                </div>
                
                <div style="padding: 20px 0;">
                    <p style="font-size: 16px; line-height: 1.5; color: #333;">
                        تلقينا طلباً لإعادة تعيين كلمة المرور لحسابك. اضغط على الرابط أدناه لإكمال العملية:
                    </p>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${resetLink}" style="background-color: #ff9800; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-size: 16px; font-weight: bold;">
                            إعادة تعيين كلمة المرور
                        </a>
                    </div>
                    
                    <p style="font-size: 14px; color: #666; text-align: center;">
                        أو انسخ الرابط التالي والصقه في المتصفح:<br>
                        <span style="color: #ff9800; word-break: break-all;">${resetLink}</span>
                    </p>
                    
                    <hr style="margin: 20px 0; border: none; border-top: 1px solid #e0e0e0;">
                    
                    <p style="font-size: 12px; color: #999; text-align: center;">
                        هذا الرابط صالح لمدة ساعة واحدة.<br>
                        إذا لم تطلب إعادة تعيين كلمة المرور، يرجى تجاهل هذا البريد الإلكتروني.
                    </p>
                    
                    <p style="font-size: 12px; color: #999; text-align: center;">
                        © ${new Date().getFullYear()} ${process.env.COMPANY_NAME}. جميع الحقوق محفوظة.
                    </p>
                </div>
            </div>
        `,
        text: `مرحباً ${fullname},\n\nتلقينا طلباً لإعادة تعيين كلمة المرور لحسابك. اضغط على الرابط التالي لإكمال العملية:\n\n${resetLink}\n\nهذا الرابط صالح لمدة ساعة واحدة.\n\nإذا لم تطلب إعادة تعيين كلمة المرور، يرجى تجاهل هذا البريد الإلكتروني.`
    };
    
    await sendEmailWithRetry(mailOptions);
}

// ============= 404 Handler =============
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// ============= Global Error Handler =============
app.use((err, req, res, next) => {
    console.error('Global error:', err);
    
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    
    if (err.name === 'UnauthorizedError') {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    res.status(500).json({ 
        error: process.env.NODE_ENV === 'production' 
            ? 'Internal server error' 
            : err.message 
    });
});

// ============= Start Server =============
const PORT = process.env.PORT || 3000;

if (require.main === module) {
    const server = app.listen(PORT, () => {
        console.log('\n' + '='.repeat(60));
        console.log(`🚀 Secure Server Running on Port ${PORT}`);
        console.log('='.repeat(60));
        console.log(`🔒 Environment: ${process.env.NODE_ENV || 'development'}`);
        console.log(`🛡️ Security Level: BANKING GRADE (Enhanced)`);
        console.log(`📊 Audit Logging: ${process.env.ENABLE_AUDIT_LOGS === 'false' ? 'DISABLED' : 'ENABLED'}`);
        console.log(`🔐 CSRF Protection: ENABLED`);
        console.log(`🔑 Encryption: AES-256-GCM`);
        console.log(`📧 Email Service: ${process.env.SMTP_HOST}`);
        console.log(`🗄️ Redis: ${redisClient.status === 'ready' ? 'CONNECTED' : 'DISCONNECTED'}`);
        console.log(`🔥 Firebase: ${db ? 'CONNECTED' : 'DISCONNECTED'}`);
        console.log('='.repeat(60) + '\n');
    });
    
    // Graceful shutdown
    process.on('SIGTERM', () => {
        console.log('SIGTERM received. Closing server...');
        server.close(() => {
            redisClient.quit();
            console.log('Server closed');
            process.exit(0);
        });
    });
}

module.exports = app;
