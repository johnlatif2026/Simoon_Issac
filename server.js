const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const admin = require('firebase-admin');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

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
// دالة موحدة لإنشاء قالب البريد الإلكتروني (شكل واحد لكل الرسائل)
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
            🌐 ${process.env.SITE_URL || 'http://simoon-issac.vercel.app'}
          </div>
        </div>
      </div>
    </body>
    </html>
  `;
}

// دالة موحدة لإرسال أي بريد باستخدام القالب الموحد
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

// دالة خاصة لإشعارات الأدمن (عندما يرسل زائر رسالة جديدة)
async function sendAdminNotification(visitorName, visitorEmail, visitorPhone, message) {
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@egyptwithsimon.com';
  const content = `
    <p><strong>📩 لديك رسالة جديدة من موقع رحلة في مصر</strong></p>
    <hr>
    <p><strong>👤 الاسم:</strong> ${visitorName}</p>
    <p><strong>📧 البريد الإلكتروني:</strong> <a href="mailto:${visitorEmail}">${visitorEmail}</a></p>
    <p><strong>📞 رقم الهاتف:</strong> ${visitorPhone || 'غير مدخل'}</p>
    <p><strong>💬 نص الرسالة:</strong></p>
    <p style="background: #f0f0f0; padding: 15px; border-radius: 10px;">${message.replace(/\n/g, '<br>')}</p>
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

// ============= EMAIL FUNCTIONS FOR DIFFERENT TYPES (ALL USING UNIFIED TEMPLATE) =============

// دالة لإرسال بريد إنشاء الحساب
async function sendAccountCreatedEmail(email, fullname, username, password) {
  const content = `
    <p>أهلاً بك في منصة <strong>رحلة في مصر مع سيمون</strong>.</p>
    <p>تم إنشاء حسابك بنجاح، ويمكنك الآن الوصول إلى لوحة التحكم وإدارة المحتوى بكل سهولة.</p>
    <div style="background: #e8f5e9; padding: 15px; border-radius: 12px; margin: 15px 0;">
      <p><strong>📝 بيانات حسابك:</strong></p>
      <p>👤 <strong>الاسم الكامل:</strong> ${fullname}</p>
      <p>🔑 <strong>اسم المستخدم:</strong> <span style="color: #D4AF37; font-weight: bold;">${username}</span></p>
      <p>🔐 <strong>كلمة المرور:</strong> <span style="color: #D4AF37; font-weight: bold;">${password}</span></p>
      <p>📧 <strong>البريد الإلكتروني:</strong> ${email}</p>
    </div>
    <p style="color: #f44336; font-size: 13px;">⚠️ يرجى حفظ هذه البيانات في مكان آمن. نوصي بتغيير كلمة المرور بعد تسجيل الدخول الأول.</p>
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

// دالة لإرسال بريد استعادة كلمة المرور
async function sendForgotPasswordEmail(email, fullname, username, newPassword) {
  const content = `
    <p>عزيزي/عزيزتي <strong>${fullname}</strong>،</p>
    <p>تم إنشاء كلمة مرور جديدة لحسابك بناءً على طلبك.</p>
    <div style="background: #fff3e0; padding: 15px; border-radius: 12px; margin: 15px 0;">
      <p><strong>📝 بيانات حسابك الجديدة:</strong></p>
      <p>👤 <strong>الاسم الكامل:</strong> ${fullname}</p>
      <p>🔑 <strong>اسم المستخدم:</strong> <span style="color: #D4AF37; font-weight: bold;">${username}</span></p>
      <p>🔐 <strong>كلمة المرور الجديدة:</strong></p>
      <p style="text-align: center;"><span style="font-size: 24px; font-weight: bold; color: #D4AF37; background: #f0f0f0; padding: 10px 20px; border-radius: 10px; display: inline-block;">${newPassword}</span></p>
    </div>
    <div style="background: #ffebee; padding: 12px; border-radius: 10px; margin-top: 15px;">
      <p><strong>⚠️ تنبيه هام:</strong> إذا لم تكن أنت من طلب استعادة كلمة المرور، يرجى تغيير كلمة المرور فوراً من خلال لوحة التحكم.</p>
    </div>
  `;
  
  return await sendUnifiedEmail(
    email,
    '🔐 إعادة تعيين كلمة المرور - رحلة في مصر',
    'تم إعادة تعيين كلمة المرور',
    `السلام عليكم ${fullname}،`,
    content,
    'تسجيل الدخول الآن',
    `${process.env.SITE_URL || 'https://simoon-issac.vercel.app'}/login`
  );
}

// دالة إرسال تأكيد الحجز (موحدة)
async function sendBookingConfirmationEmail(booking) {
  const { name, email, tourName, persons, date, totalAmount, currency, transferNumber } = booking;
  
  const content = `
    <p>شكراً لثقتكم بنا وحجز رحلتكم مع <strong>رحلة في مصر مع سيمون</strong>.</p>
    <p>تم استلام طلب حجزكم بنجاح، وسنقوم بالتواصل معكم خلال 24 ساعة لتأكيد التفاصيل النهائية.</p>
    <div style="background: #f8f9fa; padding: 15px; border-radius: 12px; margin: 15px 0;">
      <p><strong>🏝️ تفاصيل الحجز:</strong></p>
      <p><strong>اسم الرحلة:</strong> ${tourName}</p>
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
    `عزيزي/عزيزتي ${name}،`,
    content,
    'زيارة موقعنا',
    process.env.SITE_URL || 'https://simoon-issac.vercel.app'
  );
}

// دالة إرسال تأكيد الدفع (موحدة)
async function sendPaymentConfirmationEmail(email, name, tour, persons, date, totalAmount, currency, transferNumber) {
  const content = `
    <div style="text-align: center; margin-bottom: 20px;">
      <span style="font-size: 50px;">✅</span>
    </div>
    <p>تم تأكيد عملية الدفع الخاصة برحلتك بنجاح!</p>
    <div style="background: #e8f5e9; padding: 15px; border-radius: 12px; margin: 15px 0;">
      <p><strong>🏝️ الرحلة:</strong> ${tour}</p>
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
    `عزيزي/عزيزتي ${name}،`,
    content,
    'زيارة موقعنا',
    process.env.SITE_URL || 'https://simoon-issac.vercel.app'
  );
}

// دالة الرد على رسالة التواصل (شكراً لتواصلك)
async function sendContactThankYouEmail(name, email, message) {
  const content = `
    <p>شكراً لتواصلك معنا عبر موقع <strong>رحلة في مصر مع سيمون</strong>.</p>
    <p>لقد استلمنا رسالتك التالية:</p>
    <div style="background: #f0f0f0; padding: 15px; border-radius: 10px; margin: 15px 0;">
      <p><em>"${message.substring(0, 200)}${message.length > 200 ? '...' : ''}"</em></p>
    </div>
    <p>سنقوم بالرد عليك في أقرب وقت ممكن (خلال 24 ساعة كحد أقصى).</p>
    <p>مع جزيل الشكر،<br>فريق رحلة في مصر مع سيمون</p>
  `;
  
  return await sendUnifiedEmail(
    email,
    '📧 شكراً لتواصلك مع رحلة في مصر',
    'تم استلام رسالتك',
    `السلام عليكم ${name}،`,
    content,
    'تصفح رحلاتنا',
    `${process.env.SITE_URL || 'https://simoon-issac.vercel.app'}/tours`
  );
}

// Middleware: Verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Initialize default admin user
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
        createdAt: new Date().toISOString()
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
        createdAt: new Date().toISOString()
      });
      console.log('✅ Default admin user created in memory');
    }
  }
}

// ============= AUTH ENDPOINTS =============

// Register new user
app.post('/api/register', async (req, res) => {
  try {
    const { fullname, username, email, password } = req.body;
    const bcrypt = require('bcryptjs');
    
    if (!fullname || !username || !email || !password) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }
    
    if (password.length < 3) {
      return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 3 أحرف على الأقل' });
    }
    
    if (db) {
      const existingUser = await db.collection('users').where('username', '==', username).get();
      if (!existingUser.empty) return res.status(400).json({ error: 'اسم المستخدم موجود بالفعل' });
      
      const existingEmail = await db.collection('users').where('email', '==', email).get();
      if (!existingEmail.empty) return res.status(400).json({ error: 'البريد الإلكتروني موجود بالفعل' });
      
      const hashedPassword = await bcrypt.hash(password, 10);
      await db.collection('users').add({
        fullname, username, email, password: hashedPassword, role: 'admin', createdAt: new Date().toISOString()
      });
      
      await sendAccountCreatedEmail(email, fullname, username, password);
      res.json({ success: true, message: 'تم إنشاء الحساب بنجاح' });
    } else {
      const existingUser = memoryUsers.find(u => u.username === username);
      if (existingUser) return res.status(400).json({ error: 'اسم المستخدم موجود بالفعل' });
      
      const existingEmail = memoryUsers.find(u => u.email === email);
      if (existingEmail) return res.status(400).json({ error: 'البريد الإلكتروني موجود بالفعل' });
      
      const hashedPassword = await bcrypt.hash(password, 10);
      memoryUsers.push({
        id: Date.now().toString(), fullname, username, email, password: hashedPassword, role: 'admin', createdAt: new Date().toISOString()
      });
      
      await sendAccountCreatedEmail(email, fullname, username, password);
      res.json({ success: true, message: 'تم إنشاء الحساب بنجاح' });
    }
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: error.message });
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
    
    if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
      const token = jwt.sign({ username, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '24h' });
      return res.json({ success: true, token });
    }
    
    res.status(401).json({ success: false, error: 'Invalid credentials' });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const bcrypt = require('bcryptjs');
    
    if (!email) return res.status(400).json({ error: 'البريد الإلكتروني مطلوب' });
    
    let user = null;
    if (db) {
      const userQuery = await db.collection('users').where('email', '==', email).get();
      if (!userQuery.empty) user = { id: userQuery.docs[0].id, ...userQuery.docs[0].data() };
    } else {
      user = memoryUsers.find(u => u.email === email);
    }
    
    if (!user) return res.status(404).json({ error: 'هذا البريد الإلكتروني غير مسجل في النظام' });
    
    const newPassword = Math.random().toString(36).slice(-8);
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    
    if (db) {
      await db.collection('users').doc(user.id).update({ password: hashedNewPassword, updatedAt: new Date().toISOString() });
    } else {
      const userIndex = memoryUsers.findIndex(u => u.id === user.id);
      if (userIndex !== -1) memoryUsers[userIndex].password = hashedNewPassword;
    }
    
    await sendForgotPasswordEmail(email, user.fullname, user.username, newPassword);
    res.json({ success: true, message: 'تم إرسال كلمة المرور الجديدة إلى بريدك الإلكتروني' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: error.message });
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
    res.status(500).json({ error: error.message });
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
    res.status(500).json({ error: error.message });
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
    res.status(500).json({ error: error.message });
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
    res.status(500).json({ error: error.message });
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
      name, description, days: parseInt(days), priceEgyptian: parseFloat(priceEgyptian),
      priceForeign: parseFloat(priceForeign), image: imageValue,
      itinerary: itinerary || [], includes: includes || [], excludes: excludes || [],
      faq: faq || [], gallery: gallery || [], createdAt: new Date().toISOString()
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
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/tours/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    if (updates.image === '' || updates.image === null || updates.image === undefined) updates.image = '';
    
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
    res.status(500).json({ error: error.message });
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
    res.status(500).json({ error: error.message });
  }
});

// ============= BOOKINGS ENDPOINTS =============
app.post('/api/bookings', async (req, res) => {
  try {
    const { tourId, tourName, name, email, phone, persons, date, nationality, totalPrice, currency } = req.body;
    
    const booking = { 
      tourId, tourName: tourName || 'رحلة سياحية', name, email, phone,
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
    
    // إرسال بريد تأكيد الحجز باستخدام القالب الموحد
    await sendBookingConfirmationEmail(booking);
    
    res.json({ success: true, booking });
  } catch (error) {
    console.error('Booking error:', error);
    res.status(500).json({ error: error.message });
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
    res.status(500).json({ error: error.message });
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
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/contact', async (req, res) => {
  try {
    const contact = { ...req.body, createdAt: new Date().toISOString(), status: 'unread' };
    
    if (db) {
      await db.collection('contacts').add(contact);
    } else {
      contact.id = Date.now().toString();
      if (!memoryStorage.contacts) memoryStorage.contacts = [];
      memoryStorage.contacts.push(contact);
    }
    
    try {
      await transporter.sendMail({
        from: `"رحلة في مصر" <${process.env.SMTP_USER}>`,
        to: contact.email,
        subject: `📧 شكراً لتواصلك مع رحلة في مصر`,
        html: `<h3>شكراً لتواصلك ${contact.name}</h3><p>سنقوم بالرد عليك في أقرب وقت ممكن.</p>`
      });
    } catch (e) { console.log('Email error:', e.message); }
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all contacts (admin only - requires JWT)
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
    res.status(500).json({ error: error.message });
  }
});

// Delete contact (admin only - requires JWT)
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
    res.status(500).json({ error: error.message });
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
    res.status(500).json({ error: error.message });
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
    res.status(500).json({ error: error.message });
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
    res.status(500).json({ error: error.message });
  }
});

// ============= ADMIN SEND EMAIL ENDPOINT (باستخدام القالب الموحد) =============
app.post('/api/send-email', verifyToken, async (req, res) => {
  try {
    const { to, subject, message } = req.body;
    
    if (!to || !subject || !message) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }
    
    // استخدام القالب الموحد لإرسال البريد من الأدمن
    const success = await sendUnifiedEmail(
      to,
      subject,
      'رسالة من إدارة الموقع',
      `مرحباً،`,
      `<p>${message.replace(/\n/g, '<br>')}</p>`,
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
    
    // إرسال بريد تأكيد الدفع باستخدام القالب الموحد
    await sendPaymentConfirmationEmail(email, name, tour, persons, date, totalAmount, currency, transferNumber);
    
    res.json({ success: true, message: 'تم تأكيد الدفع بنجاح' });
  } catch (error) {
    console.error('Confirm payment error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============= FULL TOUR DETAILS ENDPOINTS =============
app.put('/api/tours/:id/full', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, days, priceEgyptian, priceForeign, image, itinerary, includes, excludes, faq, gallery } = req.body;
    
    const updates = {
      name, description, days: parseInt(days), priceEgyptian: parseFloat(priceEgyptian),
      priceForeign: parseFloat(priceForeign), image: image || '',
      itinerary: itinerary || [], includes: includes || [], excludes: excludes || [],
      faq: faq || [], gallery: gallery || [], updatedAt: new Date().toISOString()
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
    res.status(500).json({ error: error.message });
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
    res.status(500).json({ error: error.message });
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
