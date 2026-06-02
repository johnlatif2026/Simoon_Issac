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

// ============= EMAIL FUNCTIONS =============

// دالة لإرسال بريد إنشاء الحساب
async function sendAccountCreatedEmail(email, fullname, username, password) {
  const emailHtml = `
    <!DOCTYPE html>
    <html dir="rtl" lang="ar">
    <head>
      <meta charset="UTF-8">
      <title>تم إنشاء حسابك بنجاح</title>
      <style>
        body { font-family: 'Cairo', Tahoma, Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 20px; direction: rtl; }
        .container { max-width: 500px; margin: 0 auto; background-color: #ffffff; border-radius: 20px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #D4AF37, #B8860B); color: #2c1810; padding: 25px; text-align: center; }
        .content { padding: 25px; }
        .info-box { background-color: #f8f9fa; border-radius: 12px; padding: 15px; margin: 20px 0; border-right: 4px solid #D4AF37; }
        .footer { background-color: #f8f9fa; padding: 15px; text-align: center; font-size: 11px; color: #999; }
        .highlight { color: #D4AF37; font-weight: bold; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h2>🇪🇬 رحلة في مصر مع سيمون</h2>
          <p>مرحباً بك في عائلتنا!</p>
        </div>
        <div class="content">
          <h3>🎉 تم إنشاء حسابك بنجاح!</h3>
          <p>أهلاً بك <strong>${fullname}</strong>،</p>
          <p>نحن سعداء بانضمامك إلى منصة <strong>رحلة في مصر مع سيمون</strong>. يمكنك الآن الوصول إلى لوحة التحكم وإدارة المحتوى.</p>
          <div class="info-box">
            <p><strong>📝 بيانات حسابك:</strong></p>
            <p>👤 <strong>الاسم الكامل:</strong> ${fullname}</p>
            <p>🔑 <strong>اسم المستخدم:</strong> <span class="highlight">${username}</span></p>
            <p>🔐 <strong>كلمة المرور:</strong> <span class="highlight">${password}</span></p>
            <p>📧 <strong>البريد الإلكتروني:</strong> ${email}</p>
          </div>
          <p style="color: #f44336; font-size: 12px;">⚠️ يرجى حفظ هذه البيانات في مكان آمن. نوصي بتغيير كلمة المرور بعد تسجيل الدخول الأول.</p>
          <p>للدخول إلى لوحة التحكم، اضغط على الرابط أدناه:</p>
          <p style="text-align: center;">
            <a href="${process.env.SITE_URL || 'http://localhost:3000'}/login" style="background: linear-gradient(135deg, #D4AF37, #FF8C00); color: #2c1810; padding: 10px 25px; text-decoration: none; border-radius: 25px; display: inline-block; font-weight: bold;">🚀 تسجيل الدخول الآن</a>
          </p>
        </div>
        <div class="footer">
          <p>© 2026 رحلة في مصر مع سيمون - جميع الحقوق محفوظة</p>
          <p>📍 مصر - القاهرة</p>
        </div>
      </div>
    </body>
    </html>
  `;
  
  try {
    await transporter.sendMail({
      from: `"رحلة في مصر" <${process.env.SMTP_USER}>`,
      to: email,
      subject: '🎉 ترحيباً بك - تم إنشاء حسابك بنجاح | رحلة في مصر مع سيمون',
      html: emailHtml
    });
    console.log(`📧 Account creation email sent to ${email}`);
    return true;
  } catch (error) {
    console.log('Account email error:', error.message);
    return false;
  }
}

// دالة لإرسال بريد استعادة كلمة المرور
async function sendForgotPasswordEmail(email, fullname, username, newPassword) {
  const emailHtml = `
    <!DOCTYPE html>
    <html dir="rtl" lang="ar">
    <head>
      <meta charset="UTF-8">
      <title>استعادة كلمة المرور</title>
      <style>
        body { font-family: 'Cairo', Tahoma, Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 20px; direction: rtl; }
        .container { max-width: 500px; margin: 0 auto; background-color: #ffffff; border-radius: 20px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #D4AF37, #B8860B); color: #2c1810; padding: 25px; text-align: center; }
        .content { padding: 25px; }
        .info-box { background-color: #e8f5e9; border-radius: 12px; padding: 15px; margin: 20px 0; border-right: 4px solid #4caf50; }
        .warning-box { background-color: #fff3e0; border-radius: 12px; padding: 15px; margin: 20px 0; border-right: 4px solid #ff9800; }
        .footer { background-color: #f8f9fa; padding: 15px; text-align: center; font-size: 11px; color: #999; }
        .highlight { color: #D4AF37; font-weight: bold; }
        .new-password { font-size: 24px; font-weight: bold; color: #D4AF37; font-family: monospace; background: #f0f0f0; padding: 10px; border-radius: 10px; display: inline-block; letter-spacing: 2px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h2>🇪🇬 رحلة في مصر مع سيمون</h2>
          <p>استعادة بيانات حسابك</p>
        </div>
        <div class="content">
          <h3>🔐 تم إعادة تعيين كلمة المرور</h3>
          <p>عزيزي/عزيزتي <strong>${fullname}</strong>،</p>
          <p>تم إنشاء كلمة مرور جديدة لحسابك بناءً على طلبك.</p>
          <div class="info-box">
            <p><strong>📝 بيانات حسابك الجديدة:</strong></p>
            <p>👤 <strong>الاسم الكامل:</strong> ${fullname}</p>
            <p>🔑 <strong>اسم المستخدم:</strong> <span class="highlight">${username}</span></p>
            <p>🔐 <strong>كلمة المرور الجديدة:</strong></p>
            <p style="text-align: center;"><span class="new-password">${newPassword}</span></p>
            <p>📧 <strong>البريد الإلكتروني:</strong> ${email}</p>
          </div>
          <div class="warning-box">
            <p><strong>⚠️ تنبيه هام:</strong></p>
            <p>إذا لم تكن أنت من طلب استعادة كلمة المرور، يرجى تغيير كلمة المرور فوراً من خلال لوحة التحكم.</p>
            <p>نوصي بتغيير كلمة المرور بعد أول تسجيل دخول.</p>
          </div>
          <p>للدخول إلى لوحة التحكم، اضغط على الرابط أدناه:</p>
          <p style="text-align: center;">
            <a href="${process.env.SITE_URL || 'http://localhost:3000'}/login" style="background: linear-gradient(135deg, #D4AF37, #FF8C00); color: #2c1810; padding: 10px 25px; text-decoration: none; border-radius: 25px; display: inline-block; font-weight: bold;">🚀 تسجيل الدخول الآن</a>
          </p>
          <p style="color: #999; font-size: 12px;">إذا واجهتك أي مشكلة، يرجى التواصل مع الدعم الفني.</p>
        </div>
        <div class="footer">
          <p>© 2026 رحلة في مصر مع سيمون - جميع الحقوق محفوظة</p>
        </div>
      </div>
    </body>
    </html>
  `;
  
  try {
    await transporter.sendMail({
      from: `"رحلة في مصر" <${process.env.SMTP_USER}>`,
      to: email,
      subject: '🔐 إعادة تعيين كلمة المرور - رحلة في مصر مع سيمون',
      html: emailHtml
    });
    console.log(`📧 Password recovery email sent to ${email}`);
    return true;
  } catch (error) {
    console.log('Recovery email error:', error.message);
    return false;
  }
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
  
  // Check if admin exists in Firebase
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
    // Memory storage
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
    
    // Validation
    if (!fullname || !username || !email || !password) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }
    
    if (password.length < 3) {
      return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 3 أحرف على الأقل' });
    }
    
    // Check if user exists in Firebase
    if (db) {
      const existingUser = await db.collection('users')
        .where('username', '==', username)
        .get();
      
      if (!existingUser.empty) {
        return res.status(400).json({ error: 'اسم المستخدم موجود بالفعل' });
      }
      
      const existingEmail = await db.collection('users')
        .where('email', '==', email)
        .get();
      
      if (!existingEmail.empty) {
        return res.status(400).json({ error: 'البريد الإلكتروني موجود بالفعل' });
      }
      
      const hashedPassword = await bcrypt.hash(password, 10);
      await db.collection('users').add({
        fullname,
        username,
        email,
        password: hashedPassword,
        role: 'admin',
        createdAt: new Date().toISOString()
      });
      
      // إرسال بريد تأكيد إنشاء الحساب
      await sendAccountCreatedEmail(email, fullname, username, password);
      
      res.json({ success: true, message: 'تم إنشاء الحساب بنجاح' });
    } else {
      // Memory storage
      const existingUser = memoryUsers.find(u => u.username === username);
      if (existingUser) {
        return res.status(400).json({ error: 'اسم المستخدم موجود بالفعل' });
      }
      
      const existingEmail = memoryUsers.find(u => u.email === email);
      if (existingEmail) {
        return res.status(400).json({ error: 'البريد الإلكتروني موجود بالفعل' });
      }
      
      const hashedPassword = await bcrypt.hash(password, 10);
      memoryUsers.push({
        id: Date.now().toString(),
        fullname,
        username,
        email,
        password: hashedPassword,
        role: 'admin',
        createdAt: new Date().toISOString()
      });
      
      // إرسال بريد تأكيد إنشاء الحساب
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
    
    // Search in Firebase
    if (db) {
      const userQuery = await db.collection('users')
        .where('username', '==', username)
        .get();
      
      if (!userQuery.empty) {
        user = { id: userQuery.docs[0].id, ...userQuery.docs[0].data() };
      }
    } else {
      // Search in memory
      user = memoryUsers.find(u => u.username === username);
    }
    
    // Check password if user exists
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
    
    // Fallback to .env admin credentials for backward compatibility
    if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
      const token = jwt.sign(
        { username, role: 'admin' },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );
      return res.json({ success: true, token });
    }
    
    res.status(401).json({ success: false, error: 'Invalid credentials' });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Forgot password endpoint
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const bcrypt = require('bcryptjs');
    
    if (!email) {
      return res.status(400).json({ error: 'البريد الإلكتروني مطلوب' });
    }
    
    let user = null;
    
    // Search in Firebase
    if (db) {
      const userQuery = await db.collection('users')
        .where('email', '==', email)
        .get();
      
      if (!userQuery.empty) {
        user = { id: userQuery.docs[0].id, ...userQuery.docs[0].data() };
      }
    } else {
      // Search in memory
      user = memoryUsers.find(u => u.email === email);
    }
    
    if (!user) {
      return res.status(404).json({ error: 'هذا البريد الإلكتروني غير مسجل في النظام' });
    }
    
    // إنشاء كلمة مرور عشوائية جديدة
    const newPassword = Math.random().toString(36).slice(-8);
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    
    // تحديث كلمة المرور في قاعدة البيانات
    if (db) {
      await db.collection('users').doc(user.id).update({
        password: hashedNewPassword,
        updatedAt: new Date().toISOString()
      });
    } else {
      const userIndex = memoryUsers.findIndex(u => u.id === user.id);
      if (userIndex !== -1) {
        memoryUsers[userIndex].password = hashedNewPassword;
      }
    }
    
    // إرسال البريد مع كلمة المرور الجديدة
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

// Get all users (admin only)
app.get('/api/users', verifyToken, async (req, res) => {
  try {
    if (db) {
      const snapshot = await db.collection('users').orderBy('createdAt', 'desc').get();
      const users = snapshot.docs.map(doc => {
        const user = doc.data();
        delete user.password;
        return { id: doc.id, ...user };
      });
      res.json(users);
    } else {
      const users = memoryUsers.map(({ password, ...user }) => user);
      res.json(users);
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete user (admin only)
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

// ============= TOURS MANAGEMENT ENDPOINTS (CRUD) =============
// Get all tours (public - no auth needed for viewing)
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

// Get single tour (public - no auth needed)
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

// Create tour (admin only - requires JWT)
app.post('/api/tours', verifyToken, async (req, res) => {
  try {
    const { 
      name, description, days, priceEgyptian, priceForeign, image,
      itinerary, includes, excludes, faq, gallery 
    } = req.body;
    
    if (!name || !description || !days || !priceEgyptian || !priceForeign) {
      return res.status(400).json({ error: 'جميع الحقول المطلوبة' });
    }
    
    let imageValue = '';
    if (image && image.trim() !== '' && image !== 'null' && image !== 'undefined') {
      imageValue = image;
    }
    
    const newTour = {
      name,
      description,
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
    res.status(500).json({ error: error.message });
  }
});

// Update tour (admin only - requires JWT)
app.put('/api/tours/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    
    // لو الصورة جاية فاضية، نخليها فاضية
    if (updates.image === '' || updates.image === null || updates.image === undefined) {
      updates.image = '';
    }
    
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

// Delete tour (admin only - requires JWT)
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
      tourId,
      tourName: tourName || 'رحلة سياحية',
      name, 
      email, 
      phone, 
      persons: parseInt(persons) || 1, 
      date,
      nationality,
      totalAmount: totalPrice,
      currency,
      transferNumber: 'TR-' + Date.now(),
      createdAt: new Date().toISOString() 
    };
    
    if (db) {
      const docRef = await db.collection('bookings').add(booking);
      booking.id = docRef.id;
    } else {
      booking.id = Date.now().toString();
      memoryStorage.bookings.push(booking);
    }
    
    // Send email notification...
    try {
      const emailHtml = `
        <!DOCTYPE html>
        <html dir="rtl" lang="ar">
        <head>
          <meta charset="UTF-8">
          <title>تأكيد الحجز</title>
          <style>
            body { font-family: 'Cairo', Tahoma, Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 20px; direction: rtl; }
            .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 20px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
            .header { background: linear-gradient(135deg, #D4AF37, #B8860B); color: #2c1810; padding: 30px; text-align: center; }
            .content { padding: 30px; }
            .tour-details { background-color: #f8f9fa; border-radius: 12px; padding: 20px; margin: 20px 0; border-right: 4px solid #D4AF37; }
            .footer { background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #999; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header"><h1>🇪🇬 رحلة في مصر مع سيمون</h1></div>
            <div class="content">
              <h3>🎉 تم تأكيد حجزك بنجاح!</h3>
              <div class="tour-details">
                <p><strong>🏝️ الرحلة:</strong> ${booking.tourName}</p>
                <p><strong>👤 الاسم:</strong> ${name}</p>
                <p><strong>📧 البريد:</strong> ${email}</p>
                <p><strong>📞 الهاتف:</strong> ${phone}</p>
                <p><strong>👥 عدد الأشخاص:</strong> ${persons}</p>
                <p><strong>📅 التاريخ:</strong> ${date}</p>
                <p><strong>💰 السعر الإجمالي:</strong> ${totalPrice} ${currency === 'EGP' ? 'جنيه' : '$'}</p>
                <p><strong>🔢 رقم الحجز:</strong> ${booking.transferNumber}</p>
              </div>
              <p>سنقوم بالتواصل معكم خلال 24 ساعة لتأكيد التفاصيل النهائية.</p>
              <p>مع تحيات فريق <strong>رحلة في مصر مع سيمون</strong></p>
            </div>
            <div class="footer"><p>© 2026 رحلة في مصر مع سيمون - جميع الحقوق محفوظة</p></div>
          </div>
        </body>
        </html>
      `;
      
      await transporter.sendMail({
        from: `"رحلة في مصر" <${process.env.SMTP_USER}>`,
        to: email,
        subject: '🎉 تأكيد حجز رحلتك - رحلة في مصر مع سيمون',
        html: emailHtml
      });
      console.log(`📧 Booking email sent to ${email}`);
    } catch (emailError) {
      console.log('Email error:', emailError.message);
    }
    
    res.json({ success: true, booking });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all bookings (admin only - requires JWT)
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

// Delete booking (admin only - requires JWT)
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

// ============= CONTACT ENDPOINTS =============
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

// Get all rankings (public)
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

// Delete ranking (admin only - requires JWT)
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

// ============= ADMIN SEND EMAIL ENDPOINT =============
app.post('/api/send-email', verifyToken, async (req, res) => {
  try {
    const { to, subject, message } = req.body;
    
    if (!to || !subject || !message) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }
    
    await transporter.sendMail({
      from: `"رحلة في مصر" <${process.env.SMTP_USER}>`,
      to: to,
      subject: subject,
      html: `<div style="font-family: 'Cairo', sans-serif; direction: rtl;"><h3>${subject}</h3><p>${message.replace(/\n/g, '<br>')}</p><br><p>مع تحيات فريق <strong>رحلة في مصر مع سيمون</strong></p></div>`
    });
    
    res.json({ success: true, message: 'تم إرسال البريد بنجاح' });
  } catch (error) {
    res.status(500).json({ error: 'فشل إرسال البريد: ' + error.message });
  }
});

// ============= CONFIRM PAYMENT ENDPOINT =============
app.post('/api/confirm-payment', async (req, res) => {
  try {
    const { bookingId, email, name, tour, persons, date, totalAmount, currency, transferNumber } = req.body;
    
    console.log('📝 Payment confirmation received:', { bookingId, email, name, tour, totalAmount, currency });
    
    // Here you can update the booking status in your database if needed
    // For now, we'll just send a confirmation email
    
    const confirmationHtml = `
      <!DOCTYPE html>
      <html dir="rtl" lang="ar">
      <head>
        <meta charset="UTF-8">
        <title>تأكيد الدفع - رحلة في مصر</title>
        <style>
          body { font-family: 'Cairo', sans-serif; background-color: #f5f5f5; padding: 20px; direction: rtl; }
          .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 20px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
          .header { background: linear-gradient(135deg, #D4AF37, #B8860B); padding: 30px; text-align: center; color: #2c1810; }
          .content { padding: 30px; }
          .details { background: #f8f9fa; border-radius: 12px; padding: 20px; margin: 20px 0; border-right: 4px solid #D4AF37; }
          .success-icon { font-size: 60px; color: #4caf50; text-align: center; margin-bottom: 20px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🇪🇬 رحلة في مصر مع سيمون</h1>
          </div>
          <div class="content">
            <div class="success-icon">✅</div>
            <h2 style="text-align: center; color: #2c1810;">تم تأكيد دفعك بنجاح!</h2>
            <div class="details">
              <p><strong>🏝️ الرحلة:</strong> ${tour}</p>
              <p><strong>👤 الاسم:</strong> ${name}</p>
              <p><strong>📧 البريد:</strong> ${email}</p>
              <p><strong>👥 عدد الأشخاص:</strong> ${persons}</p>
              <p><strong>📅 التاريخ:</strong> ${date}</p>
              <p><strong>💰 المبلغ المدفوع:</strong> ${totalAmount} ${currency === 'EGP' ? 'جنيه' : '$'}</p>
              <p><strong>🔢 رقم التحويل:</strong> ${transferNumber}</p>
            </div>
            <p style="text-align: center;">شكراً لحجزكم معنا! سنقوم بالتواصل معكم قريباً لتأكيد التفاصيل النهائية.</p>
          </div>
        </div>
      </body>
      </html>
    `;
    
    // Send confirmation email
    try {
      await transporter.sendMail({
        from: `"رحلة في مصر" <${process.env.SMTP_USER}>`,
        to: email,
        subject: '✅ تأكيد الدفع - رحلة في مصر مع سيمون',
        html: confirmationHtml
      });
      console.log(`📧 Payment confirmation email sent to ${email}`);
    } catch (emailError) {
      console.log('Email error:', emailError.message);
      // Don't fail the request if email fails
    }
    
    res.json({ success: true, message: 'تم تأكيد الدفع بنجاح' });
  } catch (error) {
    console.error('Confirm payment error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============= ADD THIS AFTER THE CONFIRM PAYMENT ENDPOINT =============
// Update tour with full details (itinerary, includes, excludes, faq, gallery)
app.put('/api/tours/:id/full', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { 
      name, description, days, priceEgyptian, priceForeign, image,
      itinerary, includes, excludes, faq, gallery 
    } = req.body;
    
    const updates = {
      name,
      description,
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
    res.status(500).json({ error: error.message });
  }
});

// Get full tour details
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
