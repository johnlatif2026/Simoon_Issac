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

// ============= TOURS MANAGEMENT ENDPOINTS (CRUD) =============
// Get all tours (public - for website)
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

// Get single tour
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

// Create tour (admin only)
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

// Update tour (admin only)
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

// Delete tour (admin only)
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
    
    console.log('📥 Received payment confirmation:', { bookingId, email, name, tour, persons, date, totalAmount, currency, transferNumber });
    
    // Validate required fields
    if (!email || !name || !tour) {
      console.log('❌ Missing required fields');
      return res.status(400).json({ error: 'بيانات ناقصة، يرجى المحاولة مرة أخرى' });
    }
    
    // Update or create booking record
    let savedBooking = null;
    
    if (db) {
      // Firebase mode
      try {
        if (bookingId) {
          const bookingRef = db.collection('bookings').doc(bookingId);
          const bookingDoc = await bookingRef.get();
          
          if (bookingDoc.exists) {
            await bookingRef.update({
              paymentStatus: 'completed',
              paymentConfirmedAt: new Date().toISOString(),
              transferNumber: transferNumber || null
            });
            savedBooking = { id: bookingId, ...bookingDoc.data() };
            console.log(`✅ Updated booking ${bookingId} with payment status`);
          } else {
            // Create new if not found
            const newBooking = {
              name, email, phone: req.body.phone || '',
              tourName: tour, persons: parseInt(persons) || 1,
              date: date || new Date().toISOString().split('T')[0],
              totalAmount: totalAmount || 0, currency: currency || 'USD',
              transferNumber: transferNumber || null,
              paymentStatus: 'completed',
              paymentConfirmedAt: new Date().toISOString(),
              createdAt: new Date().toISOString()
            };
            const docRef = await db.collection('bookings').add(newBooking);
            savedBooking = { id: docRef.id, ...newBooking };
            console.log(`✅ Created new booking ${docRef.id} with payment`);
          }
        } else {
          // Create new booking
          const newBooking = {
            name, email, phone: req.body.phone || '',
            tourName: tour, persons: parseInt(persons) || 1,
            date: date || new Date().toISOString().split('T')[0],
            totalAmount: totalAmount || 0, currency: currency || 'USD',
            transferNumber: transferNumber || null,
            paymentStatus: 'completed',
            paymentConfirmedAt: new Date().toISOString(),
            createdAt: new Date().toISOString()
          };
          const docRef = await db.collection('bookings').add(newBooking);
          savedBooking = { id: docRef.id, ...newBooking };
          console.log(`✅ Created new booking ${docRef.id} (no ID provided)`);
        }
      } catch (firebaseError) {
        console.error('Firebase error:', firebaseError.message);
        // Fall back to memory storage
        db = null;
      }
    }
    
    // Memory storage mode (or fallback)
    if (!db) {
      const newMemoryBooking = {
        id: bookingId || Date.now().toString(),
        name, email, phone: req.body.phone || '',
        tourName: tour, persons: parseInt(persons) || 1,
        date: date || new Date().toISOString().split('T')[0],
        totalAmount: totalAmount || 0, currency: currency || 'USD',
        transferNumber: transferNumber || null,
        paymentStatus: 'completed',
        paymentConfirmedAt: new Date().toISOString(),
        createdAt: new Date().toISOString()
      };
      
      const existingIndex = memoryStorage.bookings.findIndex(b => b.id === newMemoryBooking.id);
      if (existingIndex !== -1) {
        memoryStorage.bookings[existingIndex] = { ...memoryStorage.bookings[existingIndex], ...newMemoryBooking };
        console.log(`✅ Updated memory booking ${newMemoryBooking.id}`);
      } else {
        memoryStorage.bookings.push(newMemoryBooking);
        console.log(`✅ Created new memory booking ${newMemoryBooking.id}`);
      }
      savedBooking = newMemoryBooking;
    }
    
    // Send confirmation email (don't let email failure break the payment)
    try {
      if (transporter && process.env.SMTP_USER) {
        const customerEmailHtml = `
          <!DOCTYPE html>
          <html dir="rtl" lang="ar">
          <head><meta charset="UTF-8"><title>تأكيد الدفع - رحلة في مصر</title></head>
          <body style="font-family: 'Cairo', Tahoma, sans-serif; direction: rtl; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background: #fff; border-radius: 20px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1);">
              <div style="background: linear-gradient(135deg, #D4AF37, #B8860B); color: #2c1810; padding: 30px; text-align: center;">
                <h1>🇪🇬 رحلة في مصر مع سيمون</h1>
              </div>
              <div style="padding: 30px;">
                <h3>✅ تم تأكيد دفعك بنجاح!</h3>
                <div style="background: #f8f9fa; border-radius: 12px; padding: 20px; margin: 20px 0; border-right: 4px solid #D4AF37;">
                  <p><strong>🏝️ الرحلة:</strong> ${escapeHtml(tour)}</p>
                  <p><strong>👤 الاسم:</strong> ${escapeHtml(name)}</p>
                  <p><strong>📧 البريد:</strong> ${escapeHtml(email)}</p>
                  <p><strong>👥 عدد الأفراد:</strong> ${persons || 1}</p>
                  <p><strong>📅 التاريخ:</strong> ${date || '-'}</p>
                  <p><strong>💰 المبلغ المدفوع:</strong> ${totalAmount || 0} ${currency === 'EGP' ? 'جنيه' : '$'}</p>
                  <p><strong>🔢 رقم التحويل:</strong> ${transferNumber || 'غير محدد'}</p>
                </div>
                <p>شكراً لثقتكم بنا. سيتم إرسال تفاصيل الرحلة النهائية خلال 24 ساعة.</p>
                <p>مع تحيات فريق <strong>رحلة في مصر مع سيمون</strong></p>
              </div>
            </div>
          </body>
          </html>
        `;
        
        await transporter.sendMail({
          from: `"رحلة في مصر" <${process.env.SMTP_USER}>`,
          to: email,
          subject: '✅ تم تأكيد دفعة رحلتك - رحلة في مصر مع سيمون',
          html: customerEmailHtml
        });
        console.log(`📧 Payment email sent to ${email}`);
      } else {
        console.log('⚠️ Email not configured, skipping email send');
      }
    } catch (emailError) {
      // Don't fail the payment if email fails
      console.error('Email error (non-critical):', emailError.message);
    }
    
    // Send success response
    res.json({ success: true, message: 'تم تأكيد الدفع بنجاح', booking: savedBooking });
    
  } catch (error) {
    console.error('❌ Confirm payment error:', error);
    // Send detailed error for debugging (remove in production)
    res.status(500).json({ 
      error: 'حدث خطأ داخلي في الخادم', 
      details: process.env.NODE_ENV === 'development' ? error.message : undefined 
    });
  }
});

// Helper function for escaping HTML (add this at the top of your file with other helpers)
function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>]/g, function(m) {
    if (m === '&') return '&amp;';
    if (m === '<') return '&lt;';
    if (m === '>') return '&gt;';
    return m;
  });
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📱 Main site: http://localhost:${PORT}/`);
  console.log(`🔐 Login: http://localhost:${PORT}/login`);
  console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard`);
});
