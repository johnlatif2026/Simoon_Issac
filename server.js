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

// In-memory storage fallback with demo tours
const memoryStorage = {
  tours: [
    {
      id: "1",
      titleAr: "جولة المتحف المصري الكبير",
      titleEn: "Grand Egyptian Museum Tour",
      descriptionAr: "استكشف عجائب الحضارة المصرية القديمة في المتحف المصري الكبير",
      descriptionEn: "Explore the wonders of ancient Egyptian civilization at the Grand Egyptian Museum",
      duration: "4 ساعات",
      groupSize: "2-10 أشخاص",
      priceUSD: 50,
      priceEGP: 2500,
      image: "https://i.postimg.cc/4dWVP5tg/GEM.jpg"
    },
    {
      id: "2",
      titleAr: "رحلة النيل",
      titleEn: "Nile Cruise",
      descriptionAr: "عشاء رومانسي على ظهر مركب تقليدي في نهر النيل",
      descriptionEn: "Romantic dinner on a traditional boat on the Nile River",
      duration: "3 ساعات",
      groupSize: "2-15 أشخاص",
      priceUSD: 75,
      priceEGP: 3750,
      image: "https://i.postimg.cc/hjS7TCDB/nhr-alnyl.jpg"
    }
  ],
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
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
    const token = jwt.sign(
      { username, role: 'admin' },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    res.json({ success: true, token });
  } else {
    res.status(401).json({ success: false, error: 'Invalid credentials' });
  }
});

app.post('/api/verify-token', verifyToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// ============= TOURS ENDPOINTS =============
app.get('/api/tours', async (req, res) => {
  try {
    if (db) {
      const snapshot = await db.collection('tours').get();
      const tours = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
      if (tours.length === 0) {
        res.json(memoryStorage.tours);
      } else {
        res.json(tours);
      }
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
      if (!doc.exists) {
        const tour = memoryStorage.tours.find(t => t.id === id);
        if (tour) return res.json(tour);
        return res.status(404).json({ error: 'Tour not found' });
      }
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
    const tour = req.body;
    if (db) {
      const docRef = await db.collection('tours').add(tour);
      res.json({ id: docRef.id, ...tour });
    } else {
      const newTour = { id: Date.now().toString(), ...tour };
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
    if (db) {
      await db.collection('tours').doc(id).update(updates);
      res.json({ id, ...updates });
    } else {
      const index = memoryStorage.tours.findIndex(t => t.id === id);
      if (index === -1) return res.status(404).json({ error: 'Tour not found' });
      memoryStorage.tours[index] = { ...memoryStorage.tours[index], ...updates };
      res.json({ id, ...updates });
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
    const booking = req.body;
    booking.createdAt = new Date().toISOString();
    
    let savedBooking;
    if (db) {
      const docRef = await db.collection('bookings').add(booking);
      savedBooking = { id: docRef.id, ...booking };
    } else {
      savedBooking = { id: Date.now().toString(), ...booking };
      memoryStorage.bookings.push(savedBooking);
    }
    
    // Send email notification to customer
    try {
      const tourName = booking.tour || 'رحلة سياحية';
      const emailHtml = `
        <!DOCTYPE html>
        <html dir="rtl" lang="ar">
        <head><meta charset="UTF-8"><title>تأكيد الحجز</title>
        <style>
          body { font-family: 'Cairo', Tahoma, Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 20px; direction: rtl; }
          .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 20px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
          .header { background: linear-gradient(135deg, #0B3B5A 0%, #1a5a7a 100%); color: white; padding: 30px; text-align: center; }
          .header h1 { margin: 0; font-size: 28px; }
          .content { padding: 30px; }
          .tour-details { background-color: #f8f9fa; border-radius: 12px; padding: 20px; margin: 20px 0; border-right: 4px solid #F4A261; }
          .detail-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #e0e0e0; }
          .footer { background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #999; }
        </style>
        </head>
        <body>
          <div class="container">
            <div class="header"><h1>🇪🇬 جولات استكشافية في مصر</h1><p>استكشف مصر</p></div>
            <div class="content">
              <p>السادة العملاء الكرام،</p>
              <p>يسعدنا تأكيد حجزكم معنا، ونشكركم لثقتكم بنا.</p>
              <div class="tour-details">
                <div class="detail-row"><span>🏝️ اسم الرحلة:</span><span>${tourName}</span></div>
                <div class="detail-row"><span>👤 الاسم:</span><span>${booking.name || '-'}</span></div>
                <div class="detail-row"><span>📧 البريد الإلكتروني:</span><span>${booking.email || '-'}</span></div>
                <div class="detail-row"><span>📞 رقم الهاتف:</span><span>${booking.phone || '-'}</span></div>
                <div class="detail-row"><span>👥 عدد الأشخاص:</span><span>${booking.persons || '1'} شخص</span></div>
                <div class="detail-row"><span>📅 تاريخ الرحلة:</span><span>${booking.date || '-'}</span></div>
                <div class="detail-row"><span>💰 المبلغ:</span><span>${booking.totalAmount || 0} ${booking.currency === 'EGP' ? 'جنيه' : '$'}</span></div>
                <div class="detail-row"><span>🔢 رقم التحويل:</span><span>${booking.transferNumber || '-'}</span></div>
              </div>
              <p style="text-align: center;"><strong>مع تحيات فريق جولات استكشافية في مصر</strong></p>
            </div>
            <div class="footer"><p>© 2026 جولات استكشافية في مصر - جميع الحقوق محفوظة</p></div>
          </div>
        </body>
        </html>
      `;
      
      await transporter.sendMail({
        from: `"جولات استكشافية في مصر" <${process.env.SMTP_USER}>`,
        to: booking.email,
        subject: '🎉 تأكيد حجز رحلتك - جولات استكشافية في مصر',
        html: emailHtml
      });
      console.log(`📧 Booking email sent to ${booking.email}`);
    } catch (emailError) {
      console.log('Email error:', emailError.message);
    }
    
    res.json({ success: true, booking: savedBooking });
  } catch (error) {
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

// ============= RANKINGS ENDPOINTS =============
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

app.post('/api/rankings', async (req, res) => {
  try {
    const ranking = req.body;
    ranking.createdAt = new Date().toISOString();
    
    if (db) {
      const docRef = await db.collection('rankings').add(ranking);
      res.json({ id: docRef.id, ...ranking });
    } else {
      const newRanking = { id: Date.now().toString(), ...ranking };
      if (!memoryStorage.rankings) memoryStorage.rankings = [];
      memoryStorage.rankings.push(newRanking);
      res.json(newRanking);
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
      res.json({ success: true });
    } else {
      if (memoryStorage.rankings) {
        memoryStorage.rankings = memoryStorage.rankings.filter(r => r.id !== id);
      }
      res.json({ success: true });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============= CONTACT ENDPOINTS =============
app.post('/api/contacts', async (req, res) => {
  try {
    const contact = { ...req.body, createdAt: new Date().toISOString(), status: 'unread' };
    
    if (db) {
      await db.collection('contacts').add(contact);
    } else {
      if (!memoryStorage.contacts) memoryStorage.contacts = [];
      contact.id = Date.now().toString();
      memoryStorage.contacts.push(contact);
    }
    
    // Send confirmation email to user
    try {
      await transporter.sendMail({
        from: `"جولات استكشافية في مصر" <${process.env.SMTP_USER}>`,
        to: contact.email,
        subject: `📧 شكراً لتواصلك مع جولات استكشافية في مصر`,
        html: `
          <!DOCTYPE html>
          <html dir="rtl" lang="ar">
          <head><meta charset="UTF-8"><title>شكراً لتواصلك</title>
          <style>
            body { font-family: 'Cairo', Tahoma, Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 20px; direction: rtl; }
            .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 20px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
            .header { background: linear-gradient(135deg, #0B3B5A 0%, #1a5a7a 100%); color: white; padding: 30px; text-align: center; }
            .content { padding: 30px; }
            .footer { background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #999; }
          </style>
          </head>
          <body>
            <div class="container">
              <div class="header"><h1>🇪🇬 جولات استكشافية في مصر</h1></div>
              <div class="content">
                <p>عزيزي/عزيزتي ${contact.name}،</p>
                <p>شكراً لتواصلك مع فريق جولات استكشافية في مصر. هذا تأكيد باستلام رسالتك، وسنقوم بالرد عليك في أقرب وقت ممكن.</p>
                <p style="text-align: center;"><strong>مع تحيات فريق جولات استكشافية في مصر</strong></p>
              </div>
              <div class="footer"><p>© 2026 جولات استكشافية في مصر - جميع الحقوق محفوظة</p></div>
            </div>
          </body>
          </html>
        `
      });
      console.log(`📧 Contact confirmation email sent to ${contact.email}`);
    } catch (emailError) {
      console.log('Email error:', emailError.message);
    }
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
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
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/contacts/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (db) {
      await db.collection('contacts').doc(id).delete();
      res.json({ success: true });
    } else {
      if (memoryStorage.contacts) {
        memoryStorage.contacts = memoryStorage.contacts.filter(c => c.id !== id);
      }
      res.json({ success: true });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============= ADMIN SEND EMAIL ENDPOINT =============
app.post('/api/admin/send-email', verifyToken, async (req, res) => {
  try {
    const { email, subject, message } = req.body;
    
    if (!email || !subject || !message) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }
    
    const emailHtml = `
      <!DOCTYPE html>
      <html dir="rtl" lang="ar">
      <head><meta charset="UTF-8"><title>${subject}</title>
      <style>
        body { font-family: 'Cairo', Tahoma, Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 20px; direction: rtl; }
        .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 20px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #0B3B5A 0%, #1a5a7a 100%); color: white; padding: 30px; text-align: center; }
        .content { padding: 30px; }
        .message-box { background-color: #f8f9fa; border-radius: 12px; padding: 20px; margin: 20px 0; border-right: 4px solid #F4A261; line-height: 1.8; white-space: pre-wrap; }
        .footer { background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #999; }
      </style>
      </head>
      <body>
        <div class="container">
          <div class="header"><h1>🇪🇬 جولات استكشافية في مصر</h1><p>استكشف مصر</p></div>
          <div class="content">
            <div class="message-box">${message.replace(/\n/g, '<br>')}</div>
            <p style="text-align: center;"><strong>مع تحيات فريق جولات استكشافية في مصر</strong></p>
          </div>
          <div class="footer"><p>© 2026 جولات استكشافية في مصر - جميع الحقوق محفوظة</p></div>
        </div>
      </body>
      </html>
    `;
    
    await transporter.sendMail({
      from: `"جولات استكشافية في مصر" <${process.env.SMTP_USER}>`,
      to: email,
      subject: subject,
      html: emailHtml
    });
    
    console.log(`📧 Admin email sent to: ${email} - Subject: ${subject}`);
    res.json({ success: true, message: 'تم إرسال البريد بنجاح' });
  } catch (error) {
    console.error('Email error:', error);
    res.status(500).json({ error: 'فشل إرسال البريد: ' + error.message });
  }
});

// ============= CONFIRM PAYMENT ENDPOINT =============
app.post('/api/confirm-payment', async (req, res) => {
  try {
    const { email, name, tour, totalAmount, currency, transferNumber } = req.body;
    
    const emailHtml = `
      <!DOCTYPE html>
      <html dir="rtl" lang="ar">
      <head><meta charset="UTF-8"><title>تأكيد الدفع - جولات استكشافية في مصر</title>
      <style>
        body { font-family: 'Cairo', Tahoma, Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 20px; direction: rtl; }
        .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 20px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #0B3B5A 0%, #1a5a7a 100%); color: white; padding: 30px; text-align: center; }
        .content { padding: 30px; }
        .success-box { background-color: #d4edda; border-radius: 12px; padding: 20px; margin: 20px 0; text-align: center; color: #155724; }
        .footer { background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #999; }
      </style>
      </head>
      <body>
        <div class="container">
          <div class="header"><h1>🇪🇬 جولات استكشافية في مصر</h1><p>استكشف مصر</p></div>
          <div class="content">
            <div class="success-box">
              <h2>✅ تم تأكيد حجزك بنجاح!</h2>
              <p>شكراً لحجزك معنا. سيتم التواصل معك قريباً لتأكيد التفاصيل النهائية.</p>
              <p><strong>رقم التحويل المرجعي:</strong> ${transferNumber}</p>
              <p><strong>المبلغ:</strong> ${totalAmount} ${currency === 'EGP' ? 'جنيه' : 'دولار'}</p>
            </div>
            <p style="text-align: center;"><strong>مع تحيات فريق جولات استكشافية في مصر</strong></p>
          </div>
          <div class="footer"><p>© 2026 جولات استكشافية في مصر - جميع الحقوق محفوظة</p></div>
        </div>
      </body>
      </html>
    `;
    
    await transporter.sendMail({
      from: `"جولات استكشافية في مصر" <${process.env.SMTP_USER}>`,
      to: email,
      subject: '✅ تأكيد الدفع - جولات استكشافية في مصر',
      html: emailHtml
    });
    
    console.log(`📧 Payment confirmation email sent to ${email}`);
    res.json({ success: true });
  } catch (error) {
    console.error('Confirm payment email error:', error);
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📱 Main site: http://localhost:${PORT}/`);
  console.log(`🔐 Login: http://localhost:${PORT}/login`);
  console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard`);
  console.log(`✨ Demo tours loaded - 2 tours available`);
});
