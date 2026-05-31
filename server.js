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

// In-memory storage with demo tours
const memoryStorage = {
  tours: [
    {
      id: "1",
      name: "جولة الأهرامات وأبو الهول",
      description: "استكشف عجائب الدنيا السبع القديمة الأهرامات العظيمة وأبو الهول، مع جولة في المتحف المصري القديم.",
      days: 3,
      priceEgyptian: 2500,
      priceForeign: 75,
      image: "https://images.unsplash.com/photo-1503177119275-0aa32b3a9368?ixlib=rb-1.2.1&auto=format&fit=crop&w=1950&q=80",
      createdAt: new Date().toISOString()
    },
    {
      id: "2",
      name: "رحلة الأقصر وأسوان",
      description: "جولة 5 أيام في مدن الجنوب الأقصر وأسوان، زيارة معابد الكرنك، الأقصر، وادي الملوك، معبد أبو سمبل.",
      days: 5,
      priceEgyptian: 4500,
      priceForeign: 150,
      image: "https://images.unsplash.com/photo-1566740933436-9121a7c2dadd?ixlib=rb-1.2.1&auto=format&fit=crop&w=1950&q=80",
      createdAt: new Date().toISOString()
    },
    {
      id: "3",
      name: "رحلة الغردقة والبحر الأحمر",
      description: "استمتع بأجمل الشواطئ والغطس في البحر الأحمر، رحلة سفاري وبحيرة الأملاح.",
      days: 4,
      priceEgyptian: 3500,
      priceForeign: 120,
      image: "https://images.unsplash.com/photo-1535739020868-a1106c8fb78a?ixlib=rb-1.2.1&auto=format&fit=crop&w=1950&q=80",
      createdAt: new Date().toISOString()
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

// ============= TOURS MANAGEMENT ENDPOINTS =============
app.get('/api/tours', async (req, res) => {
  try {
    if (db) {
      const snapshot = await db.collection('tours').get();
      let tours = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
      if (tours.length === 0) {
        tours = memoryStorage.tours;
      }
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
    const { name, description, days, priceEgyptian, priceForeign, image } = req.body;
    
    if (!name || !description || !days || !priceEgyptian || !priceForeign) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }
    
    const newTour = {
      name,
      description,
      days: parseInt(days),
      priceEgyptian: parseFloat(priceEgyptian),
      priceForeign: parseFloat(priceForeign),
      image: image || 'https://images.unsplash.com/photo-1503177119275-0aa32b3a9368?ixlib=rb-1.2.1&auto=format&fit=crop&w=1950&q=80',
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

app.put('/api/tours/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    
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
    const { tourId, tourName, name, email, phone, persons, date, nationality, totalPrice, currency, message } = req.body;
    
    const booking = { 
      tourId: tourId || '',
      tourName: tourName || 'رحلة سياحية',
      name, 
      email, 
      phone, 
      persons: parseInt(persons) || 1, 
      date,
      nationality: nationality || 'foreign',
      totalAmount: totalPrice || 0,
      currency: currency || 'USD',
      message: message || '',
      transferNumber: 'TR-' + Date.now(),
      createdAt: new Date().toISOString(),
      paymentStatus: 'pending'
    };
    
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
      const emailHtml = `
        <!DOCTYPE html>
        <html dir="rtl" lang="ar">
        <head><meta charset="UTF-8"><title>تأكيد الحجز - رحلة في مصر</title>
        <style>
          body { font-family: 'Cairo', Tahoma, Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 20px; direction: rtl; }
          .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 20px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
          .header { background: linear-gradient(135deg, #D4AF37, #B8860B); color: #2c1810; padding: 30px; text-align: center; }
          .header h1 { margin: 0; font-size: 28px; }
          .content { padding: 30px; }
          .tour-details { background-color: #f8f9fa; border-radius: 12px; padding: 20px; margin: 20px 0; border-right: 4px solid #D4AF37; }
          .detail-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #e0e0e0; }
          .footer { background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #999; }
        </style>
        </head>
        <body>
          <div class="container">
            <div class="header"><h1>🇪🇬 رحلة في مصر مع سيمون</h1><p>اكتشف جمال مصر</p></div>
            <div class="content">
              <p>السادة العملاء الكرام،</p>
              <p>يسعدنا تأكيد حجزكم معنا، ونشكركم لثقتكم بنا.</p>
              <div class="tour-details">
                <div class="detail-row"><span>🏝️ اسم الرحلة:</span><span>${booking.tourName}</span></div>
                <div class="detail-row"><span>👤 الاسم:</span><span>${booking.name || '-'}</span></div>
                <div class="detail-row"><span>📧 البريد الإلكتروني:</span><span>${booking.email || '-'}</span></div>
                <div class="detail-row"><span>📞 رقم الهاتف:</span><span>${booking.phone || '-'}</span></div>
                <div class="detail-row"><span>👥 عدد الأشخاص:</span><span>${booking.persons} شخص</span></div>
                <div class="detail-row"><span>📅 تاريخ الرحلة:</span><span>${booking.date || '-'}</span></div>
                <div class="detail-row"><span>💰 المبلغ الإجمالي:</span><span>${booking.totalAmount} ${booking.currency === 'EGP' ? 'جنيه' : '$'}</span></div>
                <div class="detail-row"><span>🔢 رقم الحجز:</span><span>${booking.transferNumber}</span></div>
              </div>
              <p>سنقوم بالتواصل معكم خلال 24 ساعة لتأكيد التفاصيل النهائية.</p>
              <p style="text-align: center;"><strong>مع تحيات فريق رحلة في مصر مع سيمون</strong></p>
            </div>
            <div class="footer"><p>© 2026 رحلة في مصر مع سيمون - جميع الحقوق محفوظة</p></div>
          </div>
        </body>
        </html>
      `;
      
      await transporter.sendMail({
        from: `"رحلة في مصر مع سيمون" <${process.env.SMTP_USER}>`,
        to: booking.email,
        subject: '🎉 تأكيد حجز رحلتك - رحلة في مصر مع سيمون',
        html: emailHtml
      });
      console.log(`📧 Booking email sent to ${booking.email}`);
    } catch (emailError) {
      console.log('Email error:', emailError.message);
    }
    
    res.json({ success: true, booking: savedBooking });
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
        from: `"رحلة في مصر مع سيمون" <${process.env.SMTP_USER}>`,
        to: contact.email,
        subject: `📧 شكراً لتواصلك مع رحلة في مصر`,
        html: `<div style="font-family: 'Cairo', sans-serif; direction: rtl;"><h3>شكراً لتواصلك ${contact.name}</h3><p>سنقوم بالرد عليك في أقرب وقت ممكن.</p><br><p>مع تحيات فريق رحلة في مصر مع سيمون</p></div>`
      });
    } catch (e) { console.log('Email error:', e.message); }
    
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

// ============= ADMIN SEND EMAIL ENDPOINT =============
app.post('/api/admin/send-email', verifyToken, async (req, res) => {
  try {
    const { email, subject, message } = req.body;
    
    if (!email || !subject || !message) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }
    
    await transporter.sendMail({
      from: `"رحلة في مصر مع سيمون" <${process.env.SMTP_USER}>`,
      to: email,
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
    const { email, name, tour, totalAmount, currency, transferNumber } = req.body;
    
    const emailHtml = `
      <!DOCTYPE html>
      <html dir="rtl" lang="ar">
      <head><meta charset="UTF-8"><title>تأكيد الدفع - رحلة في مصر</title>
      <style>
        body { font-family: 'Cairo', Tahoma, Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 20px; direction: rtl; }
        .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 20px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #D4AF37, #B8860B); color: #2c1810; padding: 30px; text-align: center; }
        .content { padding: 30px; }
        .success-box { background-color: #d4edda; border-radius: 12px; padding: 20px; margin: 20px 0; text-align: center; color: #155724; }
        .footer { background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #999; }
      </style>
      </head>
      <body>
        <div class="container">
          <div class="header"><h1>🇪🇬 رحلة في مصر مع سيمون</h1></div>
          <div class="content">
            <div class="success-box">
              <h2>✅ تم تأكيد حجزك بنجاح!</h2>
              <p>شكراً لحجزك معنا. سيتم التواصل معك قريباً لتأكيد التفاصيل النهائية.</p>
              <p><strong>رقم الحجز المرجعي:</strong> ${transferNumber}</p>
              <p><strong>المبلغ:</strong> ${totalAmount} ${currency === 'EGP' ? 'جنيه' : 'دولار'}</p>
            </div>
            <p style="text-align: center;"><strong>مع تحيات فريق رحلة في مصر مع سيمون</strong></p>
          </div>
          <div class="footer"><p>© 2026 رحلة في مصر مع سيمون - جميع الحقوق محفوظة</p></div>
        </div>
      </body>
      </html>
    `;
    
    await transporter.sendMail({
      from: `"رحلة في مصر مع سيمون" <${process.env.SMTP_USER}>`,
      to: email,
      subject: '✅ تأكيد الدفع - رحلة في مصر مع سيمون',
      html: emailHtml
    });
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📱 Main site: http://localhost:${PORT}/`);
  console.log(`🔐 Login: http://localhost:${PORT}/login`);
  console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard`);
  console.log(`✨ 3 demo tours loaded successfully!`);
});
