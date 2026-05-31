const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const admin = require('firebase-admin');
const fs = require('fs').promises;
const path = require('path');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ============= CREDENTIALS MANAGEMENT =============
const CREDENTIALS_FILE = path.join(__dirname, 'credentials.json');

// Initialize credentials.json from .env if it doesn't exist
async function initCredentials() {
    try {
        // Check if credentials.json exists
        await fs.access(CREDENTIALS_FILE);
        console.log('✅ credentials.json found');
    } catch (error) {
        // File doesn't exist, create it from .env
        console.log('📝 Creating credentials.json from .env...');
        const initialCredentials = {
            username: process.env.ADMIN_USERNAME,
            password: process.env.ADMIN_PASSWORD
        };
        await fs.writeFile(CREDENTIALS_FILE, JSON.stringify(initialCredentials, null, 2));
        console.log('✅ credentials.json created successfully');
    }
}

// Read credentials from file
async function getCredentials() {
    try {
        const data = await fs.readFile(CREDENTIALS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading credentials:', error);
        throw new Error('Failed to read credentials');
    }
}

// Update credentials in file
async function updateCredentials(newUsername, newPassword) {
    try {
        const credentials = await getCredentials();
        if (newUsername !== undefined) credentials.username = newUsername;
        if (newPassword !== undefined) credentials.password = newPassword;
        await fs.writeFile(CREDENTIALS_FILE, JSON.stringify(credentials, null, 2));
        return true;
    } catch (error) {
        console.error('Error updating credentials:', error);
        throw new Error('Failed to update credentials');
    }
}

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

// ============= AUTH ENDPOINTS =============
// Login endpoint - uses credentials.json
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const credentials = await getCredentials();
    
    if (username === credentials.username && password === credentials.password) {
      const token = jwt.sign(
        { username, role: 'admin' },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );
      res.json({ success: true, token });
    } else {
      res.status(401).json({ success: false, error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: 'خطأ في الخادم' });
  }
});

app.post('/api/verify-token', verifyToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// Change Username endpoint
app.post('/api/change-username', verifyToken, async (req, res) => {
  const { currentUsername, currentPassword, newUsername } = req.body;
  
  // Validation
  if (!currentUsername || !currentPassword || !newUsername) {
    return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
  }
  
  if (newUsername.length < 4) {
    return res.status(400).json({ error: 'اسم المستخدم الجديد يجب أن لا يقل عن 4 أحرف' });
  }
  
  try {
    const credentials = await getCredentials();
    
    // Verify current credentials
    if (currentUsername !== credentials.username || currentPassword !== credentials.password) {
      return res.status(401).json({ error: 'اسم المستخدم الحالي أو كلمة المرور غير صحيحة' });
    }
    
    // Update username
    await updateCredentials(newUsername, null);
    
    // Generate new token with updated username
    const newToken = jwt.sign(
      { username: newUsername, role: 'admin' },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({ 
      success: true, 
      message: 'تم تغيير اسم المستخدم بنجاح',
      token: newToken
    });
  } catch (error) {
    res.status(500).json({ error: 'حدث خطأ أثناء تغيير اسم المستخدم' });
  }
});

// Change Password endpoint
app.post('/api/change-password', verifyToken, async (req, res) => {
  const { currentUsername, currentPassword, newPassword } = req.body;
  
  // Validation
  if (!currentUsername || !currentPassword || !newPassword) {
    return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
  }
  
  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'كلمة المرور الجديدة يجب أن لا تقل عن 8 أحرف' });
  }
  
  try {
    const credentials = await getCredentials();
    
    // Verify current credentials
    if (currentUsername !== credentials.username || currentPassword !== credentials.password) {
      return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور الحالية غير صحيحة' });
    }
    
    // Update password
    await updateCredentials(null, newPassword);
    
    res.json({ 
      success: true, 
      message: 'تم تغيير كلمة المرور بنجاح'
    });
  } catch (error) {
    res.status(500).json({ error: 'حدث خطأ أثناء تغيير كلمة المرور' });
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
    const { name, description, days, priceEgyptian, priceForeign, image } = req.body;
    
    if (!name || !description || !days || !priceEgyptian || !priceForeign) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
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
    }
    
    res.json({ success: true, message: 'تم تأكيد الدفع بنجاح' });
  } catch (error) {
    console.error('Confirm payment error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Initialize credentials and start server
async function startServer() {
  await initCredentials();
  
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📱 Main site: http://localhost:${PORT}/`);
    console.log(`🔐 Login: http://localhost:${PORT}/login`);
    console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard`);
  });
}

startServer();
