const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const admin = require('firebase-admin');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const sanitizeHtml = require('sanitize-html');
require('dotenv').config();

const app = express();

// ============= الحماية الأمنية =============
app.use(helmet({
  contentSecurityPolicy: false, // للسماح بالـ inline styles في الإيميلات
}));

// CORS مقيد
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000', 'https://simoon-issac.vercel.app'],
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// Rate limiting لل endpoints الحساسة
const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقيقة
  max: 5, // 5 محاولات
  message: { error: 'محاولات كثيرة، حاول بعد 15 دقيقة' },
  skipSuccessfulRequests: true // لا تحسب المحاولات الناجحة
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: '太多 الطلبات، حاول لاحقاً' }
});

app.use('/api/login', strictLimiter);
app.use('/api/register', strictLimiter);
app.use('/api/forgot-password', strictLimiter);
app.use('/api/contact', generalLimiter);

// Blacklist للتوكنات المسحوبة
const tokenBlacklist = new Set();

// Initialize Firebase Admin
let db;
try {
  if (process.env.FIREBASE_CONFIG) {
    const serviceAccount = JSON.parse(process.env.FIREBASE_CONFIG);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    db = admin.firestore();
    console.log('✅ Firebase connected successfully');
  } else {
    console.warn('⚠️ No FIREBASE_CONFIG found, using memory storage');
    db = null;
  }
} catch (error) {
  console.error('❌ Firebase initialization error:', error.message);
  db = null;
}

// In-memory storage fallback
const memoryStorage = {
  tours: [],
  packages: [],
  bookings: [],
  contacts: [],
  rankings: []
};

const memoryUsers = [];

// Email transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// ============= UNIFIED EMAIL TEMPLATE FUNCTION =============
function generateUnifiedEmailHTML(title, greeting, content, buttonText = null, buttonLink = null) {
  return `
    <!DOCTYPE html>
    <html dir="rtl" lang="ar">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${title}</title>
      <style>
        body {
          font-family: 'Cairo', 'Tahoma', 'Arial', sans-serif;
          background-color: #f0f2f5;
          margin: 0;
          padding: 20px;
          direction: rtl;
        }
        .container {
          max-width: 600px;
          margin: 0 auto;
          background-color: #ffffff;
          border-radius: 20px;
          overflow: hidden;
          box-shadow: 0 8px 30px rgba(0,0,0,0.12);
        }
        .header {
          background: linear-gradient(135deg, #D4AF37 0%, #B8860B 100%);
          padding: 30px 20px;
          text-align: center;
          color: #2c1810;
        }
        .header h1 {
          margin: 0;
          font-size: 26px;
          letter-spacing: 1px;
        }
        .header p {
          margin: 10px 0 0;
          font-size: 14px;
          opacity: 0.9;
        }
        .content {
          padding: 30px;
          background: #ffffff;
        }
        .greeting {
          font-size: 20px;
          font-weight: bold;
          color: #2c1810;
          margin-bottom: 20px;
          border-right: 4px solid #D4AF37;
          padding-right: 15px;
        }
        .message-box {
          background-color: #f8f9fa;
          border-radius: 16px;
          padding: 20px;
          margin: 20px 0;
          line-height: 1.7;
          color: #333;
        }
        .button {
          display: inline-block;
          background: linear-gradient(135deg, #D4AF37, #FF8C00);
          color: #2c1810;
          text-decoration: none;
          padding: 12px 30px;
          border-radius: 30px;
          font-weight: bold;
          margin: 20px 0;
          text-align: center;
          transition: transform 0.2s;
        }
        .button:hover {
          transform: scale(1.02);
        }
        .footer {
          background-color: #f8f9fa;
          padding: 20px;
          text-align: center;
          font-size: 12px;
          color: #888;
          border-top: 1px solid #eee;
        }
        .footer p {
          margin: 5px 0;
        }
        .social-links {
          margin-top: 10px;
        }
        hr {
          border: none;
          border-top: 1px solid #eee;
          margin: 20px 0;
        }
        @media (max-width: 480px) {
          .content {
            padding: 20px;
          }
          .header h1 {
            font-size: 22px;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🇪🇬 رحلة في مصر مع سيمون</h1>
          <p>اكتشف جمال مصر الأصيل</p>
        </div>
        <div class="content">
          <div class="greeting">${greeting}</div>
          <div class="message-box">
            ${content}
          </div>
          ${buttonText && buttonLink ? `<div style="text-align: center;"><a href="${buttonLink}" class="button">${buttonText}</a></div>` : ''}
        </div>
        <div class="footer">
          <p>© ${new Date().getFullYear()} رحلة في مصر مع سيمون - جميع الحقوق محفوظة</p>
          <p>📍 مصر - القاهرة | 📞 للاستفسارات: ${process.env.SUPPORT_PHONE || '01026517329'}</p>
          <div class="social-links">
            🌐 ${process.env.SITE_URL || 'https://simoon-issac.vercel.app'}
          </div>
        </div>
      </div>
    </html>
  `;
}

async function sendUnifiedEmail(to, subject, title, greeting, content, buttonText = null, buttonLink = null) {
  try {
    const emailHtml = generateUnifiedEmailHTML(title, greeting, content, buttonText, buttonLink);
    await transporter.sendMail({
      from: `"رحلة في مصر مع سيمون" <${process.env.SMTP_USER}>`,
      to: to,
      subject: subject,
      html: emailHtml
    });
    console.log(`📧 Unified email sent to ${to} - Subject: ${subject}`);
    return true;
  } catch (error) {
    console.error('❌ Unified email error:', error.message);
    return false;
  }
}

async function sendAdminNotification(visitorName, visitorEmail, visitorPhone, message) {
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@egyptwithsimon.com';
  const safeMessage = sanitizeHtml(message, { allowedTags: ['br', 'p'], allowedAttributes: {} });
  const content = `
    <p><strong>📩 لديك رسالة جديدة من موقع رحلة في مصر</strong></p>
    <hr>
    <p><strong>👤 الاسم:</strong> ${sanitizeHtml(visitorName)}</p>
    <p><strong>📧 البريد الإلكتروني:</strong> <a href="mailto:${visitorEmail}">${visitorEmail}</a></p>
    <p><strong>📞 رقم الهاتف:</strong> ${visitorPhone || 'غير مدخل'}</p>
    <p><strong>💬 نص الرسالة:</strong></p>
    <p style="background: #f0f0f0; padding: 15px; border-radius: 10px;">${safeMessage.replace(/\n/g, '<br>')}</p>
    <hr>
    <p>يمكنك الرد على هذا البريد للتواصل مع العميل مباشرة.</p>
  `;
  
  return await sendUnifiedEmail(
    adminEmail,
    '📬 رسالة جديدة من الموقع - رحلة في مصر',
    'رسالة جديدة من العميل',
    `صباح/مساء الخير مدير الموقع،`,
    content,
    'الرد على العميل',
    `mailto:${visitorEmail}`
  );
}

// ⚠️ تم تعديل هذه الدالة - لا ترسل كلمة المرور بعد الآن
async function sendAccountCreatedEmail(email, fullname, username) {
  const content = `
    <p>أهلاً بك في منصة <strong>رحلة في مصر مع سيمون</strong>.</p>
    <p>تم إنشاء حسابك بنجاح، ويمكنك الآن الوصول إلى لوحة التحكم وإدارة المحتوى بكل سهولة.</p>
    <div style="background: #e8f5e9; padding: 15px; border-radius: 12px; margin: 15px 0;">
      <p><strong>📝 بيانات حسابك:</strong></p>
      <p>👤 <strong>الاسم الكامل:</strong> ${sanitizeHtml(fullname)}</p>
      <p>🔑 <strong>اسم المستخدم:</strong> <span style="color: #D4AF37; font-weight: bold;">${sanitizeHtml(username)}</span></p>
      <p>📧 <strong>البريد الإلكتروني:</strong> ${email}</p>
    </div>
    <p>🔐 تم تعيين كلمة المرور التي أدخلتها أثناء التسجيل. يمكنك استخدامها لتسجيل الدخول.</p>
    <p style="color: #f44336; font-size: 13px;">⚠️ يرجى الحفاظ على كلمة المرور في مكان آمن.</p>
  `;
  
  return await sendUnifiedEmail(
    email,
    '🎉 ترحيباً بك - تم إنشاء حسابك بنجاح',
    'مرحباً بك في عائلتنا',
    `أهلاً بك ${fullname}،`,
    content,
    'تسجيل الدخول الآن',
    `${process.env.SITE_URL || 'https://simoon-issac.vercel.app'}/login`
  );
}

async function sendForgotPasswordEmail(email, fullname, resetLink) {
  const content = `
    <p>عزيزي/عزيزتي <strong>${sanitizeHtml(fullname)}</strong>،</p>
    <p>لقد تلقينا طلباً لإعادة تعيين كلمة المرور الخاصة بحسابك.</p>
    <p>لإعادة تعيين كلمة المرور، يرجى النقر على الزر أدناه:</p>
    <div style="text-align: center; margin: 25px 0;">
      <a href="${resetLink}" style="background: linear-gradient(135deg, #D4AF37, #FF8C00); color: #2c1810; text-decoration: none; padding: 12px 30px; border-radius: 30px; font-weight: bold; display: inline-block;">إعادة تعيين كلمة المرور</a>
    </div>
    <p>هذا الرابط صالح لمدة ساعة واحدة فقط.</p>
    <p>إذا لم تكن أنت من طلب إعادة التعيين، يمكنك تجاهل هذا البريد.</p>
  `;
  
  return await sendUnifiedEmail(
    email,
    '🔐 إعادة تعيين كلمة المرور - رحلة في مصر',
    'طلب إعادة تعيين كلمة المرور',
    `السلام عليكم ${fullname}،`,
    content,
    'إعادة تعيين كلمة المرور',
    resetLink
  );
}

async function sendBookingConfirmationEmail(booking) {
  const { name, email, tourName, persons, date, totalAmount, currency, transferNumber } = booking;
  
  const content = `
    <p>شكراً لثقتكم بنا وحجز رحلتكم مع <strong>رحلة في مصر مع سيمون</strong>.</p>
    <p>تم استلام طلب حجزكم بنجاح، وسنقوم بالتواصل معكم خلال 24 ساعة لتأكيد التفاصيل النهائية.</p>
    <div style="background: #f8f9fa; padding: 15px; border-radius: 12px; margin: 15px 0;">
      <p><strong>🏝️ تفاصيل الحجز:</strong></p>
      <p><strong>اسم الرحلة:</strong> ${sanitizeHtml(tourName)}</p>
      <p><strong>👥 عدد الأشخاص:</strong> ${persons}</p>
      <p><strong>📅 التاريخ:</strong> ${date}</p>
      <p><strong>💰 السعر الإجمالي:</strong> ${totalAmount} ${currency === 'EGP' ? 'جنيه مصري' : 'دولار أمريكي'}</p>
      <p><strong>🔢 رقم الحجز المرجعي:</strong> ${transferNumber}</p>
    </div>
    <p>في حالة وجود أي استفسار، يمكنك الاتصال بنا.</p>
  `;
  
  return await sendUnifiedEmail(
    email,
    '🎉 تأكيد حجز رحلتك - رحلة في مصر مع سيمون',
    'تم تأكيد حجزك بنجاح',
    `عزيزي/عزيزتي ${sanitizeHtml(name)}،`,
    content,
    'زيارة موقعنا',
    process.env.SITE_URL || 'https://simoon-issac.vercel.app'
  );
}

async function sendPaymentConfirmationEmail(email, name, tour, persons, date, totalAmount, currency, transferNumber) {
  const content = `
    <div style="text-align: center; margin-bottom: 20px;">
      <span style="font-size: 50px;">✅</span>
    </div>
    <p>تم تأكيد عملية الدفع الخاصة برحلتك بنجاح!</p>
    <div style="background: #e8f5e9; padding: 15px; border-radius: 12px; margin: 15px 0;">
      <p><strong>🏝️ الرحلة:</strong> ${sanitizeHtml(tour)}</p>
      <p><strong>👥 عدد الأشخاص:</strong> ${persons}</p>
      <p><strong>📅 التاريخ:</strong> ${date}</p>
      <p><strong>💰 المبلغ المدفوع:</strong> ${totalAmount} ${currency === 'EGP' ? 'جنيه مصري' : 'دولار أمريكي'}</p>
      <p><strong>🔢 رقم التحويل:</strong> ${transferNumber}</p>
    </div>
    <p>نشكركم على ثقتكم، وسنقوم بتجهيز كل ما يلزم لرحلتكم.</p>
  `;
  
  return await sendUnifiedEmail(
    email,
    '✅ تأكيد الدفع - رحلة في مصر مع سيمون',
    'تم تأكيد دفعك بنجاح',
    `عزيزي/عزيزتي ${sanitizeHtml(name)}،`,
    content,
    'زيارة موقعنا',
    process.env.SITE_URL || 'https://simoon-issac.vercel.app'
  );
}

async function sendContactThankYouEmail(name, email, message) {
  const content = `
    <p>شكراً لتواصلك معنا عبر موقع <strong>رحلة في مصر مع سيمون</strong>.</p>
    <p>لقد استلمنا رسالتك التالية:</p>
    <div style="background: #f0f0f0; padding: 15px; border-radius: 10px; margin: 15px 0;">
      <p><em>"${sanitizeHtml(message.substring(0, 200))}${message.length > 200 ? '...' : ''}"</em></p>
    </div>
    <p>سنقوم بالرد عليك في أقرب وقت ممكن (خلال 24 ساعة كحد أقصى).</p>
    <p>مع جزيل الشكر،<br>فريق رحلة في مصر مع سيمون</p>
  `;
  
  return await sendUnifiedEmail(
    email,
    '📧 شكراً لتواصلك مع رحلة في مصر',
    'تم استلام رسالتك',
    `مرحباً ${sanitizeHtml(name)}،`,
    content,
    'تصفح رحلاتنا',
    `${process.env.SITE_URL || 'https://simoon-issac.vercel.app'}/#tours`
  );
}

// Middleware للتحقق من التوكن مع Blacklist
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  
  // التحقق من وجود التوكن في القائمة السوداء
  if (tokenBlacklist.has(token)) {
    return res.status(401).json({ error: 'Token invalidated, please login again' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

async function initDefaultAdmin() {
  const bcrypt = require('bcryptjs');
  const defaultUsername = process.env.ADMIN_USERNAME || 'admin';
  const defaultPassword = process.env.ADMIN_PASSWORD || 'admin123';
  const defaultEmail = process.env.ADMIN_EMAIL || 'admin@egyptwithsimon.com';
  
  if (db) {
    const adminQuery = await db.collection('users').where('username', '==', defaultUsername).get();
    if (adminQuery.empty) {
      const hashedPassword = await bcrypt.hash(defaultPassword, 10);
      await db.collection('users').add({
        fullname: 'المدير العام',
        username: defaultUsername,
        email: defaultEmail,
        password: hashedPassword,
        role: 'admin',
        createdAt: new Date().toISOString(),
        emailVerified: true
      });
      console.log('✅ Default admin user created in Firebase');
    }
  } else {
    const existingAdmin = memoryUsers.find(u => u.username === defaultUsername);
    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash(defaultPassword, 10);
      memoryUsers.push({
        id: 'admin',
        fullname: 'المدير العام',
        username: defaultUsername,
        email: defaultEmail,
        password: hashedPassword,
        role: 'admin',
        createdAt: new Date().toISOString(),
        emailVerified: true
      });
      console.log('✅ Default admin user created in memory');
    }
  }
}

// ============= AUTH ENDPOINTS (معدلة أمنياً) =============

// تسجيل الخروج - إبطال التوكن
app.post('/api/logout', verifyToken, (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (token) {
    tokenBlacklist.add(token);
    // تنظيف القائمة السوداء كل ساعة
    setTimeout(() => tokenBlacklist.delete(token), 60 * 60 * 1000);
  }
  res.json({ success: true, message: 'Logged out successfully' });
});

app.post('/api/register', async (req, res) => {
  try {
    let { fullname, username, email, password } = req.body;
    const bcrypt = require('bcryptjs');
    
    // تنظيف المدخلات
    fullname = sanitizeHtml(fullname, { allowedTags: [], allowedAttributes: {} });
    username = sanitizeHtml(username, { allowedTags: [], allowedAttributes: {} });
    email = email.toLowerCase().trim();
    
    if (!fullname || !username || !email || !password) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }
    
    // التحقق من صحة البريد الإلكتروني
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'البريد الإلكتروني غير صحيح' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });
    }
    
    if (db) {
      const existingUser = await db.collection('users').where('username', '==', username).get();
      if (!existingUser.empty) return res.status(400).json({ error: 'اسم المستخدم موجود بالفعل' });
      
      const existingEmail = await db.collection('users').where('email', '==', email).get();
      if (!existingEmail.empty) return res.status(400).json({ error: 'البريد الإلكتروني موجود بالفعل' });
      
      const hashedPassword = await bcrypt.hash(password, 10);
      await db.collection('users').add({
        fullname, username, email, password: hashedPassword, role: 'admin', 
        createdAt: new Date().toISOString(),
        emailVerified: false
      });
      
      // ✅ لا ترسل كلمة المرور
      await sendAccountCreatedEmail(email, fullname, username);
      res.json({ success: true, message: 'تم إنشاء الحساب بنجاح' });
    } else {
      const existingUser = memoryUsers.find(u => u.username === username);
      if (existingUser) return res.status(400).json({ error: 'اسم المستخدم موجود بالفعل' });
      
      const existingEmail = memoryUsers.find(u => u.email === email);
      if (existingEmail) return res.status(400).json({ error: 'البريد الإلكتروني موجود بالفعل' });
      
      const hashedPassword = await bcrypt.hash(password, 10);
      memoryUsers.push({
        id: Date.now().toString(), fullname, username, email, password: hashedPassword, 
        role: 'admin', createdAt: new Date().toISOString(),
        emailVerified: false
      });
      
      // ✅ لا ترسل كلمة المرور
      await sendAccountCreatedEmail(email, fullname, username);
      res.json({ success: true, message: 'تم إنشاء الحساب بنجاح' });
    }
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'حدث خطأ في الخادم' }); // لا تعرض تفاصيل الخطأ
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const bcrypt = require('bcryptjs');
  
  try {
    let user = null;
    
    if (db) {
      const userQuery = await db.collection('users').where('username', '==', username).get();
      if (!userQuery.empty) user = { id: userQuery.docs[0].id, ...userQuery.docs[0].data() };
    } else {
      user = memoryUsers.find(u => u.username === username);
    }
    
    if (user) {
      const isValid = await bcrypt.compare(password, user.password);
      if (isValid) {
        const token = jwt.sign(
          { id: user.id, username: user.username, role: user.role || 'admin' },
          process.env.JWT_SECRET,
          { expiresIn: '24h' }
        );
        return res.json({ success: true, token });
      }
    }
    
    // Fallback للمشرف الافتراضي
    if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
      const token = jwt.sign({ username, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '24h' });
      return res.json({ success: true, token });
    }
    
    // رسالة عامة لا تحدد إذا كان المستخدم موجود أو كلمة المرور خطأ
    res.status(401).json({ success: false, error: 'بيانات الدخول غير صحيحة' });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

// Forgot password endpoint - sends reset link
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) return res.status(400).json({ error: 'البريد الإلكتروني مطلوب' });
    
    let user = null;
    
    if (db) {
      const userQuery = await db.collection('users').where('email', '==', email).get();
      if (!userQuery.empty) user = { id: userQuery.docs[0].id, ...userQuery.docs[0].data() };
    } else {
      user = memoryUsers.find(u => u.email === email);
    }
    
    // لا تخبر المستخدم إذا البريد غير موجود (أمان)
    if (!user) {
      return res.json({ success: true, message: 'إذا كان البريد مسجلاً، ستتلقى رابط إعادة التعيين' });
    }
    
    const resetToken = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    const resetLink = `${process.env.SITE_URL || 'https://simoon-issac.vercel.app'}/reset-password?token=${resetToken}`;
    
    await sendForgotPasswordEmail(email, user.fullname, resetLink);
    
    res.json({ success: true, message: 'تم إرسال رابط إعادة تعيين كلمة المرور إلى بريدك الإلكتروني' });
    
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

// Reset password endpoint
app.post('/api/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    const bcrypt = require('bcryptjs');
    
    if (!token || !newPassword) {
      return res.status(400).json({ error: 'الرمز وكلمة المرور الجديدة مطلوبة' });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });
    }
    
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      return res.status(400).json({ error: 'الرمز غير صالح أو منتهي الصلاحية' });
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    if (db) {
      await db.collection('users').doc(decoded.id).update({
        password: hashedPassword,
        updatedAt: new Date().toISOString()
      });
    } else {
      const userIndex = memoryUsers.findIndex(u => u.id === decoded.id);
      if (userIndex !== -1) {
        memoryUsers[userIndex].password = hashedPassword;
      } else {
        return res.status(404).json({ error: 'المستخدم غير موجود' });
      }
    }
    
    res.json({ success: true, message: 'تم تغيير كلمة المرور بنجاح' });
    
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

app.post('/api/verify-token', verifyToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

app.get('/api/users', verifyToken, async (req, res) => {
  try {
    if (db) {
      const snapshot = await db.collection('users').orderBy('createdAt', 'desc').get();
      const users = snapshot.docs.map(doc => { const user = doc.data(); delete user.password; return { id: doc.id, ...user }; });
      res.json(users);
    } else {
      const users = memoryUsers.map(({ password, ...user }) => user);
      res.json(users);
    }
  } catch (error) {
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

app.delete('/api/users/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (db) {
      await db.collection('users').doc(id).delete();
      res.json({ success: true });
    } else {
      const index = memoryUsers.findIndex(u => u.id === id);
      if (index === -1) return res.status(404).json({ error: 'User not found' });
      memoryUsers.splice(index, 1);
      res.json({ success: true });
    }
  } catch (error) {
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

// ============= TOURS MANAGEMENT ENDPOINTS =============
app.get('/api/tours', async (req, res) => {
  try {
    if (db) {
      const snapshot = await db.collection('tours').get();
      const tours = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
      res.json(tours);
    } else {
      res.json(memoryStorage.tours);
    }
  } catch (error) {
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

app.get('/api/tours/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (db) {
      const doc = await db.collection('tours').doc(id).get();
      if (!doc.exists) return res.status(404).json({ error: 'Tour not found' });
      res.json({ id: doc.id, ...doc.data() });
    } else {
      const tour = memoryStorage.tours.find(t => t.id === id);
      if (!tour) return res.status(404).json({ error: 'Tour not found' });
      res.json(tour);
    }
  } catch (error) {
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

app.post('/api/tours', verifyToken, async (req, res) => {
  try {
    const { name, description, days, priceEgyptian, priceForeign, image, itinerary, includes, excludes, faq, gallery } = req.body;
    
    if (!name || !description || !days || !priceEgyptian || !priceForeign) {
      return res.status(400).json({ error: 'جميع الحقول المطلوبة' });
    }
    
    let imageValue = (image && image.trim() !== '' && image !== 'null' && image !== 'undefined') ? image : '';
    
    const newTour = {
      name: sanitizeHtml(name), 
      description: sanitizeHtml(description), 
      days: parseInt(days), 
      priceEgyptian: parseFloat(priceEgyptian),
      priceForeign: parseFloat(priceForeign), 
      image: imageValue,
      itinerary: itinerary || [], 
      includes: includes || [], 
      excludes: excludes || [],
      faq: faq || [], 
      gallery: gallery || [], 
      createdAt: new Date().toISOString()
    };
    
    if (db) {
      const docRef = await db.collection('tours').add(newTour);
      res.json({ id: docRef.id, ...newTour });
    } else {
      newTour.id = Date.now().toString();
      memoryStorage.tours.push(newTour);
      res.json(newTour);
    }
  } catch (error) {
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

app.put('/api/tours/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    if (updates.image === '' || updates.image === null || updates.image === undefined) updates.image = '';
    if (updates.name) updates.name = sanitizeHtml(updates.name);
    if (updates.description) updates.description = sanitizeHtml(updates.description);
    
    if (db) {
      await db.collection('tours').doc(id).update(updates);
      res.json({ success: true, id, ...updates });
    } else {
      const index = memoryStorage.tours.findIndex(t => t.id === id);
      if (index === -1) return res.status(404).json({ error: 'Tour not found' });
      memoryStorage.tours[index] = { ...memoryStorage.tours[index], ...updates };
      res.json({ success: true, id, ...updates });
    }
  } catch (error) {
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

app.delete('/api/tours/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (db) {
      await db.collection('tours').doc(id).delete();
      res.json({ success: true });
    } else {
      memoryStorage.tours = memoryStorage.tours.filter(t => t.id !== id);
      res.json({ success: true });
    }
  } catch (error) {
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

// ============= BOOKINGS ENDPOINTS =============
app.post('/api/bookings', async (req, res) => {
  try {
    let { tourId, tourName, name, email, phone, persons, date, nationality, totalPrice, currency } = req.body;
    
    // تنظيف المدخلات
    name = sanitizeHtml(name);
    tourName = sanitizeHtml(tourName || 'رحلة سياحية');
    phone = sanitizeHtml(phone || '');
    nationality = sanitizeHtml(nationality || '');
    
    const booking = { 
      tourId, tourName, name, email, phone,
      persons: parseInt(persons) || 1, date, nationality, totalAmount: totalPrice,
      currency, transferNumber: 'TR-' + Date.now(), createdAt: new Date().toISOString() 
    };
    
    if (db) {
      const docRef = await db.collection('bookings').add(booking);
      booking.id = docRef.id;
    } else {
      booking.id = Date.now().toString();
      memoryStorage.bookings.push(booking);
    }
    
    await sendBookingConfirmationEmail(booking);
    
    res.json({ success: true, booking });
  } catch (error) {
    console.error('Booking error:', error);
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

app.get('/api/bookings', verifyToken, async (req, res) => {
  try {
    if (db) {
      const snapshot = await db.collection('bookings').orderBy('createdAt', 'desc').get();
      const bookings = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
      res.json(bookings);
    } else {
      res.json(memoryStorage.bookings);
    }
  } catch (error) {
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

app.delete('/api/bookings/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (db) {
      await db.collection('bookings').doc(id).delete();
      res.json({ success: true });
    } else {
      memoryStorage.bookings = memoryStorage.bookings.filter(b => b.id !== id);
      res.json({ success: true });
    }
  } catch (error) {
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

// ============= CONTACT ENDPOINTS (معدلة) =============
app.post('/api/contact', async (req, res) => {
  try {
    let { name, email, phone, message } = req.body;
    
    if (!name || !email || !message) {
      return res.status(400).json({ error: 'الاسم والبريد الإلكتروني والرسالة مطلوبة' });
    }
    
    // تنظيف المدخلات من XSS
    name = sanitizeHtml(name, { allowedTags: [], allowedAttributes: {} });
    message = sanitizeHtml(message, { allowedTags: ['br', 'p'], allowedAttributes: {} });
    phone = sanitizeHtml(phone || '', { allowedTags: [], allowedAttributes: {} });
    
    const contact = { 
      name, email, phone, message, 
      createdAt: new Date().toISOString(), status: 'unread' 
    };
    
    if (db) {
      await db.collection('contacts').add(contact);
    } else {
      contact.id = Date.now().toString();
      if (!memoryStorage.contacts) memoryStorage.contacts = [];
      memoryStorage.contacts.push(contact);
    }
    
    await sendContactThankYouEmail(name, email, message);
    await sendAdminNotification(name, email, phone, message);
    
    res.json({ success: true, message: 'تم إرسال رسالتك بنجاح' });
  } catch (error) {
    console.error('Contact error:', error);
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

app.get('/api/contacts', verifyToken, async (req, res) => {
  try {
    if (db) {
      const snapshot = await db.collection('contacts').orderBy('createdAt', 'desc').get();
      const contacts = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
      res.json(contacts);
    } else {
      res.json(memoryStorage.contacts || []);
    }
  } catch (error) {
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

app.delete('/api/contacts/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (db) {
      await db.collection('contacts').doc(id).delete();
    } else {
      memoryStorage.contacts = memoryStorage.contacts.filter(c => c.id !== id);
    }
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

// ============= RANKINGS ENDPOINTS =============
app.post('/api/rankings', async (req, res) => {
  try {
    const ranking = { ...req.body, createdAt: new Date().toISOString() };
    if (db) {
      await db.collection('rankings').add(ranking);
    } else {
      ranking.id = Date.now().toString();
      if (!memoryStorage.rankings) memoryStorage.rankings = [];
      memoryStorage.rankings.push(ranking);
    }
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

app.get('/api/rankings', async (req, res) => {
  try {
    if (db) {
      const snapshot = await db.collection('rankings').orderBy('createdAt', 'desc').get();
      const rankings = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
      res.json(rankings);
    } else {
      res.json(memoryStorage.rankings || []);
    }
  } catch (error) {
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

app.delete('/api/rankings/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (db) {
      await db.collection('rankings').doc(id).delete();
    } else {
      memoryStorage.rankings = memoryStorage.rankings.filter(r => r.id !== id);
    }
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

// ============= ADMIN SEND EMAIL ENDPOINT =============
app.post('/api/send-email', verifyToken, async (req, res) => {
  try {
    const { to, subject, message } = req.body;
    
    if (!to || !subject || !message) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }
    
    const success = await sendUnifiedEmail(
      to,
      subject,
      'رسالة من إدارة الموقع',
      `مرحباً،`,
      `<p>${sanitizeHtml(message).replace(/\n/g, '<br>')}</p>`,
      'زيارة موقعنا',
      process.env.SITE_URL || 'https://simoon-issac.vercel.app'
    );
    
    if (success) {
      res.json({ success: true, message: 'تم إرسال البريد بنجاح' });
    } else {
      res.status(500).json({ error: 'فشل إرسال البريد' });
    }
  } catch (error) {
    res.status(500).json({ error: 'فشل إرسال البريد: ' + error.message });
  }
});

// ============= CONFIRM PAYMENT ENDPOINT =============
app.post('/api/confirm-payment', async (req, res) => {
  try {
    const { bookingId, email, name, tour, persons, date, totalAmount, currency, transferNumber } = req.body;
    
    console.log('📝 Payment confirmation received:', { bookingId, email, name, tour, totalAmount, currency });
    
    await sendPaymentConfirmationEmail(email, name, tour, persons, date, totalAmount, currency, transferNumber);
    
    res.json({ success: true, message: 'تم تأكيد الدفع بنجاح' });
  } catch (error) {
    console.error('Confirm payment error:', error);
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

// ============= FULL TOUR DETAILS ENDPOINTS =============
app.put('/api/tours/:id/full', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, days, priceEgyptian, priceForeign, image, itinerary, includes, excludes, faq, gallery } = req.body;
    
    const updates = {
      name: sanitizeHtml(name), 
      description: sanitizeHtml(description), 
      days: parseInt(days), 
      priceEgyptian: parseFloat(priceEgyptian),
      priceForeign: parseFloat(priceForeign), 
      image: image || '',
      itinerary: itinerary || [], 
      includes: includes || [], 
      excludes: excludes || [],
      faq: faq || [], 
      gallery: gallery || [], 
      updatedAt: new Date().toISOString()
    };
    
    if (db) {
      await db.collection('tours').doc(id).update(updates);
      res.json({ success: true, id, ...updates });
    } else {
      const index = memoryStorage.tours.findIndex(t => t.id === id);
      if (index === -1) return res.status(404).json({ error: 'Tour not found' });
      memoryStorage.tours[index] = { ...memoryStorage.tours[index], ...updates };
      res.json({ success: true, id, ...updates });
    }
  } catch (error) {
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

app.get('/api/tours/:id/full', async (req, res) => {
  try {
    const { id } = req.params;
    if (db) {
      const doc = await db.collection('tours').doc(id).get();
      if (!doc.exists) return res.status(404).json({ error: 'Tour not found' });
      res.json({ id: doc.id, ...doc.data() });
    } else {
      const tour = memoryStorage.tours.find(t => t.id === id);
      if (!tour) return res.status(404).json({ error: 'Tour not found' });
      res.json(tour);
    }
  } catch (error) {
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

initDefaultAdmin().catch(console.error);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📱 Main site: http://localhost:${PORT}/`);
  console.log(`🔐 Login: http://localhost:${PORT}/login`);
  console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard`);
});
