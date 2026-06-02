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
const { Redis } = require('@upstash/redis');
const { RateLimiterRedis } = require('rate-limiter-flexible');
const compression = require('compression');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();

// ============= إعدادات الأمان المتقدمة =============
const isProduction = process.env.NODE_ENV === 'production';

if (process.env.TRUST_PROXY) {
    app.set('trust proxy', parseInt(process.env.TRUST_PROXY));
}

app.use(compression());

// ============= إعدادات Redis (Upstash) - تعريف مبكر =============
let redisClient;
try {
    if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
        redisClient = new Redis({
            url: process.env.UPSTASH_REDIS_REST_URL,
            token: process.env.UPSTASH_REDIS_REST_TOKEN,
        });
        console.log('✅ Redis (Upstash) connected');
    } else {
        // للاستخدام المحلي فقط
        const RedisLocal = require('ioredis');
        redisClient = new RedisLocal({
            host: process.env.REDIS_HOST || 'localhost',
            port: parseInt(process.env.REDIS_PORT) || 6379,
            password: process.env.REDIS_PASSWORD || undefined,
            tls: process.env.REDIS_TLS === 'true' ? {} : undefined
        });
        console.log('✅ Redis (ioredis) connected');
    }
} catch (error) {
    console.error('❌ Redis initialization error:', error.message);
}

// ============= التشفير =============
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
const IV_LENGTH = 16;

function encrypt(text) {
    if (!text) return null;
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

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

// ============= Audit Log =============
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

    if (status === 'critical') {
        await sendSecurityAlert(logEntry);
    }
};

// ============= Account Lockout =============
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

// ============= Rate Limiting =============
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

// ============= Helmet & Security =============
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

const csrfProtection = csrf({ 
    cookie: {
        key: '__Secure-csrf',
        httpOnly: true,
        secure: isProduction,
        sameSite: 'strict'
    },
    value: (req) => req.headers['x-csrf-token'] || req.body._csrf
});

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

// ============= Device Fingerprinting =============
function generateDeviceFingerprint(req) {
    const components = [
        req.get('User-Agent') || 'unknown',
        req.get('Accept-Language') || 'unknown',
        req.get('Accept-Encoding') || 'unknown',
        req.ip || 'unknown'
    ];
    return crypto.createHash('sha256').update(components.join('|')).digest('hex');
}

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

// ============= Initialize Supabase =============
let supabase;
try {
    if (process.env.SUPABASE_URL && process.env.SUPABASE_ANON_KEY) {
        supabase = createClient(
            process.env.SUPABASE_URL,
            process.env.SUPABASE_ANON_KEY
        );
        console.log('✅ Supabase connected');
    } else {
        console.log('⚠️ Supabase not configured, skipping...');
    }
} catch (error) {
    console.error('❌ Supabase initialization error:', error.message);
}

// ============= Email Transporter =============
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

transporter.verify((error, success) => {
    if (error) {
        console.error('❌ Email transporter error:', error);
    } else {
        console.log('✅ Email transporter ready');
    }
});

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

// ============= Verify Token Middleware =============
const tokenBlacklist = new Set();
setInterval(() => tokenBlacklist.clear(), 60 * 60 * 1000);

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

        const isRevoked = await redisClient.get(`revoked:${token}`);
        if (isRevoked) {
            return res.status(401).json({ error: 'Token revoked. Please login again.' });
        }

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

// ============= Security Alert =============
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
    } catch (error) {
        console.error('Failed to send security alert:', error.message);
    }
}

// ============= TOURS ENDPOINTS =============

// 1. GET /api/tours - جلب قائمة الجولات السياحية
app.get('/api/tours', async (req, res) => {
    try {
        // بيانات وهمية للتجربة - استبدلها ببيانات من Firebase عند وجودها
        const mockTours = [
            { 
                id: '1', 
                name: 'أهرامات الجيزة', 
                price: 500, 
                duration: '4 ساعات',
                location: 'القاهرة',
                description: 'جولة رائعة لزيارة أهرامات الجيزة وأبو الهول'
            },
            { 
                id: '2', 
                name: 'مدينة الأقصر', 
                price: 700, 
                duration: '6 ساعات',
                location: 'الأقصر',
                description: 'استكشاف معابد الأقصر والكرنك'
            },
            { 
                id: '3', 
                name: 'رحلة نيلية', 
                price: 300, 
                duration: '2 ساعات',
                location: 'القاهرة',
                description: 'رحلة ممتعة على نهر النيل مع العشاء'
            }
        ];

        // مثال لجلب البيانات من Firebase (قم بإلغاء التعليق عند إنشاء Collection باسم "tours")
        /*
        const toursSnapshot = await db.collection('tours').get();
        const tours = toursSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        return res.status(200).json({ success: true, count: tours.length, data: tours });
        */

        res.status(200).json({ 
            success: true, 
            count: mockTours.length, 
            data: mockTours 
        });
    } catch (error) {
        console.error('Error fetching tours:', error);
        res.status(500).json({ success: false, error: 'فشل في جلب بيانات الجولات' });
    }
});

// 2. GET /api/tours/:id - جلب جولة محددة بالمعرف
app.get('/api/tours/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        // بيانات وهمية - استبدلها بجلب من Firebase
        const mockTours = {
            '1': { id: '1', name: 'أهرامات الجيزة', price: 500, duration: '4 ساعات', location: 'القاهرة', description: 'جولة رائعة لزيارة أهرامات الجيزة وأبو الهول' },
            '2': { id: '2', name: 'مدينة الأقصر', price: 700, duration: '6 ساعات', location: 'الأقصر', description: 'استكشاف معابد الأقصر والكرنك' },
            '3': { id: '3', name: 'رحلة نيلية', price: 300, duration: '2 ساعات', location: 'القاهرة', description: 'رحلة ممتعة على نهر النيل مع العشاء' }
        };

        const tour = mockTours[id];
        if (!tour) {
            return res.status(404).json({ success: false, error: 'الجولة غير موجودة' });
        }

        res.status(200).json({ success: true, data: tour });
    } catch (error) {
        console.error('Error fetching tour:', error);
        res.status(500).json({ success: false, error: 'فشل في جلب بيانات الجولة' });
    }
});

// 3. POST /api/tours (محمي - للمشرفين فقط) - إضافة جولة جديدة
app.post('/api/tours', verifyToken, requireAdmin, async (req, res) => {
    try {
        const { name, price, duration, location, description } = req.body;

        // التحقق من صحة البيانات
        if (!name || !price || !duration) {
            return res.status(400).json({ success: false, error: 'الاسم والسعر والمدة مطلوبة' });
        }

        // مثال للإضافة إلى Firebase (قم بإلغاء التعليق عند وجود Collection "tours")
        /*
        const newTour = {
            name: sanitizeHtml(name, { allowedTags: [], allowedAttributes: {} }),
            price: parseInt(price),
            duration,
            location: location || '',
            description: description ? sanitizeHtml(description, { allowedTags: [], allowedAttributes: {} }) : '',
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            createdBy: req.user.id
        };
        
        const docRef = await db.collection('tours').add(newTour);
        
        await auditLog('TOUR_CREATED', req.user.id, req.ip, req.get('User-Agent'), { tourId: docRef.id, name });
        
        res.status(201).json({ success: true, message: 'تمت إضافة الجولة بنجاح', data: { id: docRef.id, ...newTour } });
        */

        // رد وهمي للتجربة
        await auditLog('TOUR_CREATED', req.user.id, req.ip, req.get('User-Agent'), { name });
        res.status(201).json({ success: true, message: 'تمت إضافة الجولة بنجاح', data: { id: Date.now().toString(), name, price, duration, location, description } });
    } catch (error) {
        console.error('Error adding tour:', error);
        res.status(500).json({ success: false, error: 'فشل في إضافة الجولة' });
    }
});

// ============= AUTH ENDPOINTS =============

// 1. GET CSRF Token
app.get('/api/csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// 2. Register
app.post('/api/register',
    strictLimiter,
    csrfProtection,
    body('fullname').trim().isLength({ min: 3, max: 50 }).matches(/^[\p{L}\s]+$/u),
    body('username').trim().isAlphanumeric().isLength({ min: 3, max: 30 }),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 12 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            await auditLog('REGISTER_VALIDATION_FAILED', null, req.ip, req.get('User-Agent'), errors.array(), 'warning');
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const { fullname, username, email, password } = matchedData(req);
            
            const searchEncryptedEmail = encryptForSearch(email);
            const existingUserQuery = await db.collection('users')
                .where('searchEmail', '==', searchEncryptedEmail)
                .limit(1)
                .get();
            
            if (!existingUserQuery.empty) {
                return res.status(400).json({ error: 'البريد الإلكتروني مسجل بالفعل' });
            }

            const encryptedEmail = encrypt(email);
            const searchEncryptedEmailForDb = encryptForSearch(email);
            const hashedPassword = await bcrypt.hash(password, 12);
            const emailVerificationToken = crypto.randomBytes(32).toString('hex');
            const hashedVerificationToken = await bcrypt.hash(emailVerificationToken, 10);
            
            await db.collection('users').add({
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
            });
            
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
                await new Promise(resolve => setTimeout(resolve, 1000));
                return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
            }

            const user = { id: userQuery.docs[0].id, ...userQuery.docs[0].data() };

            if (!user.emailVerified) {
                return res.status(401).json({ error: 'يرجى تفعيل حسابك عبر البريد الإلكتروني' });
            }

            if (user.accountLocked) {
                return res.status(401).json({ error: 'الحساب مقفل. يرجى التواصل مع الدعم.' });
            }

            const isValid = await bcrypt.compare(password, user.password);
            await new Promise(resolve => setTimeout(resolve, 500));

            if (!isValid) {
                const newAttempts = (user.failedLoginAttempts || 0) + 1;
                await db.collection('users').doc(user.id).update({ failedLoginAttempts: newAttempts });

                const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 10;
                if (newAttempts >= maxAttempts) {
                    await db.collection('users').doc(user.id).update({ accountLocked: true });
                    await auditLog('ACCOUNT_AUTO_LOCKED', user.id, clientIP, userAgent, `${newAttempts} failed attempts`, 'critical');
                    return res.status(401).json({ error: `الحساب مقفل لمدة ${process.env.ACCOUNT_LOCKOUT_MINUTES || 30} دقيقة` });
                }

                await recordFailedAttempt(username);
                await auditLog('LOGIN_FAILED_WRONG_PASSWORD', user.id, clientIP, userAgent, null, 'warning');
                return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
            }

            await db.collection('users').doc(user.id).update({
                failedLoginAttempts: 0,
                lastLoginIP: clientIP,
                lastLoginAt: admin.firestore.FieldValue.serverTimestamp(),
                lastLoginUserAgent: userAgent
            });

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

            await redisClient.setex(`session:${user.id}`, 3600, JSON.stringify({
                token,
                sessionId,
                deviceFingerprint,
                ip: clientIP
            }));

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
        const { limit = 50, role, emailVerified } = req.query;
        
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
            
            await redisClient.del(`session:${userDoc.id}`);
            
            await auditLog('PASSWORD_RESET_SUCCESS', userDoc.id, req.ip, req.get('User-Agent'), null);
            res.json({ success: true, message: 'Password reset successfully. You can now login with your new password.' });
        } catch (error) {
            console.error('Reset password error:', error);
            res.status(500).json({ error: 'Server error. Please try again.' });
        }
    }
);

// 12. Health Check
app.get('/api/health', async (req, res) => {
    const checks = {
        redis: false,
        firebase: false,
        email: false,
        timestamp: new Date().toISOString()
    };
    
    try {
        await redisClient.ping();
        checks.redis = true;
    } catch (error) {
        console.error('Redis health check failed:', error);
    }
    
    try {
        await db.collection('_health').doc('check').set({ timestamp: Date.now() });
        checks.firebase = true;
    } catch (error) {
        console.error('Firebase health check failed:', error);
    }
    
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
        html: `<div style="direction:rtl;font-family:Arial;text-align:center;padding:20px"><h1>مرحباً ${fullname}</h1><p>شكراً لتسجيلك! اضغط على الرابط لتفعيل حسابك:</p><a href="${verificationLink}" style="background:#4CAF50;color:white;padding:10px 20px;text-decoration:none;border-radius:5px">تفعيل الحساب</a><p>الرابط صالح لمدة 24 ساعة</p></div>`,
        text: `مرحباً ${fullname}\n\nشكراً لتسجيلك! فعّل حسابك عبر الرابط: ${verificationLink}\nهذا الرابط صالح لمدة 24 ساعة.`
    };
    await sendEmailWithRetry(mailOptions);
}

async function sendPasswordResetEmail(email, fullname, resetToken) {
    const resetLink = `${process.env.SITE_URL}/reset-password?token=${resetToken}`;
    const mailOptions = {
        from: `"${process.env.COMPANY_NAME}" <${process.env.SMTP_USER}>`,
        to: email,
        subject: `إعادة تعيين كلمة المرور - ${process.env.COMPANY_NAME}`,
        html: `<div style="direction:rtl;font-family:Arial;text-align:center;padding:20px"><h1>مرحباً ${fullname}</h1><p>لقد طلبت إعادة تعيين كلمة المرور. اضغط على الرابط:</p><a href="${resetLink}" style="background:#ff9800;color:white;padding:10px 20px;text-decoration:none;border-radius:5px">إعادة تعيين كلمة المرور</a><p>الرابط صالح لمدة ساعة واحدة</p></div>`,
        text: `مرحباً ${fullname}\n\nلقد طلبت إعادة تعيين كلمة المرور. استخدم الرابط: ${resetLink}\nهذا الرابط صالح لمدة ساعة واحدة.`
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
        console.log(`📊 Audit Logging: ENABLED`);
        console.log(`🔐 CSRF Protection: ENABLED`);
        console.log(`🔑 Encryption: AES-256-GCM`);
        console.log(`📧 Email Service: ${process.env.SMTP_HOST}`);
        console.log(`🗄️ Redis: ${redisClient ? 'CONNECTED' : 'DISCONNECTED'}`);
        console.log(`🔥 Firebase: ${db ? 'CONNECTED' : 'DISCONNECTED'}`);
        console.log('='.repeat(60) + '\n');
    });
    
    process.on('SIGTERM', () => {
        console.log('SIGTERM received. Closing server...');
        server.close(() => {
            if (redisClient && redisClient.quit) redisClient.quit();
            console.log('Server closed');
            process.exit(0);
        });
    });
}

module.exports = app;
