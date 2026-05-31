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

// ============ FIREBASE INITIALIZATION ============
let db;
try {
  if (process.env.FIREBASE_CONFIG) {
    const serviceAccount = JSON.parse(process.env.FIREBASE_CONFIG);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    db = admin.firestore();
    console.log('✅ Firebase connected');
  } else {
    console.warn('⚠️ No FIREBASE_CONFIG, using memory storage');
    db = null;
  }
} catch (error) {
  console.error('❌ Firebase error:', error.message);
  db = null;
}

// ============ MEMORY STORAGE ============
const memoryStorage = {
  tours: [],
  bookings: [],
  ratings: [],
  contacts: []
};

// ============ EMAIL TRANSPORTER ============
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT),
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});

// ============ HELPERS ============
function generateSlug(title) {
  return title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>]/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[m]));
}

// ============ MIDDLEWARE ============
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

// ============ DATABASE ABSTRACTION LAYER ============
const toursDAL = {
  async getAll() {
    if (db) {
      const snapshot = await db.collection('tours').get();
      return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    }
    return memoryStorage.tours;
  },
  async getById(id) {
    if (db) {
      const doc = await db.collection('tours').doc(id).get();
      return doc.exists ? { id: doc.id, ...doc.data() } : null;
    }
    return memoryStorage.tours.find(t => t.id === id) || null;
  },
  async getBySlug(slug) {
    if (db) {
      const snapshot = await db.collection('tours').where('slug', '==', slug).get();
      if (snapshot.empty) return null;
      const doc = snapshot.docs[0];
      return { id: doc.id, ...doc.data() };
    }
    return memoryStorage.tours.find(t => t.slug === slug) || null;
  },
  async create(data) {
    const tour = { ...data, createdAt: new Date().toISOString() };
    if (db) {
      const docRef = await db.collection('tours').add(tour);
      return { id: docRef.id, ...tour };
    }
    const newTour = { id: Date.now().toString(), ...tour };
    memoryStorage.tours.push(newTour);
    return newTour;
  },
  async update(id, data) {
    if (db) {
      await db.collection('tours').doc(id).update(data);
      return { id, ...data };
    }
    const index = memoryStorage.tours.findIndex(t => t.id === id);
    if (index === -1) return null;
    memoryStorage.tours[index] = { ...memoryStorage.tours[index], ...data };
    return memoryStorage.tours[index];
  },
  async delete(id) {
    if (db) {
      await db.collection('tours').doc(id).delete();
      return true;
    }
    memoryStorage.tours = memoryStorage.tours.filter(t => t.id !== id);
    return true;
  }
};

const bookingsDAL = {
  async getAll() {
    if (db) {
      const snapshot = await db.collection('bookings').orderBy('createdAt', 'desc').get();
      return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    }
    return memoryStorage.bookings;
  },
  async getById(id) {
    if (db) {
      const doc = await db.collection('bookings').doc(id).get();
      return doc.exists ? { id: doc.id, ...doc.data() } : null;
    }
    return memoryStorage.bookings.find(b => b.id === id) || null;
  },
  async create(data) {
    const booking = { ...data, createdAt: new Date().toISOString(), paymentStatus: 'pending' };
    if (db) {
      const docRef = await db.collection('bookings').add(booking);
      return { id: docRef.id, ...booking };
    }
    const newBooking = { id: Date.now().toString(), ...booking };
    memoryStorage.bookings.push(newBooking);
    return newBooking;
  },
  async update(id, data) {
    if (db) {
      await db.collection('bookings').doc(id).update(data);
      return { id, ...data };
    }
    const index = memoryStorage.bookings.findIndex(b => b.id === id);
    if (index === -1) return null;
    memoryStorage.bookings[index] = { ...memoryStorage.bookings[index], ...data };
    return memoryStorage.bookings[index];
  },
  async delete(id) {
    if (db) {
      await db.collection('bookings').doc(id).delete();
      return true;
    }
    memoryStorage.bookings = memoryStorage.bookings.filter(b => b.id !== id);
    return true;
  }
};

const ratingsDAL = {
  async getAll() {
    if (db) {
      const snapshot = await db.collection('rankings').get();
      return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    }
    return memoryStorage.ratings;
  },
  async getByTourId(tourId) {
    if (db) {
      const snapshot = await db.collection('rankings').where('tourId', '==', tourId).get();
      return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    }
    return memoryStorage.ratings.filter(r => r.tourId === tourId);
  },
  async create(data) {
    const rating = { ...data, createdAt: new Date().toISOString() };
    if (db) {
      const docRef = await db.collection('rankings').add(rating);
      return { id: docRef.id, ...rating };
    }
    const newRating = { id: Date.now().toString(), ...rating };
    memoryStorage.ratings.push(newRating);
    return newRating;
  },
  async delete(id) {
    if (db) {
      await db.collection('rankings').doc(id).delete();
      return true;
    }
    memoryStorage.ratings = memoryStorage.ratings.filter(r => r.id !== id);
    return true;
  }
};

const contactsDAL = {
  async getAll() {
    if (db) {
      const snapshot = await db.collection('contacts').orderBy('createdAt', 'desc').get();
      return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    }
    return memoryStorage.contacts;
  },
  async create(data) {
    const contact = { ...data, createdAt: new Date().toISOString() };
    if (db) {
      const docRef = await db.collection('contacts').add(contact);
      return { id: docRef.id, ...contact };
    }
    const newContact = { id: Date.now().toString(), ...contact };
    memoryStorage.contacts.push(newContact);
    return newContact;
  },
  async delete(id) {
    if (db) {
      await db.collection('contacts').doc(id).delete();
      return true;
    }
    memoryStorage.contacts = memoryStorage.contacts.filter(c => c.id !== id);
    return true;
  }
};

// ============ AUTH ROUTES ============
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
    const token = jwt.sign({ username, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token });
  } else {
    res.status(401).json({ success: false, error: 'Invalid credentials' });
  }
});

app.post('/api/verify-token', verifyToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// ============ TOURS ROUTES ============
app.get('/api/tours', async (req, res) => {
  try {
    const tours = await toursDAL.getAll();
    const toursWithStats = await Promise.all(tours.map(async (tour) => {
      const ratings = await ratingsDAL.getByTourId(tour.id);
      const avgRating = ratings.length ? ratings.reduce((s, r) => s + r.rating, 0) / ratings.length : 0;
      return { ...tour, avgRating: avgRating.toFixed(1), reviewsCount: ratings.length };
    }));
    res.json(toursWithStats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/tours/:id', async (req, res) => {
  try {
    const tour = await toursDAL.getById(req.params.id);
    if (!tour) return res.status(404).json({ error: 'Tour not found' });
    res.json(tour);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/tours/slug/:slug', async (req, res) => {
  try {
    const tour = await toursDAL.getBySlug(req.params.slug);
    if (!tour) return res.status(404).json({ error: 'Tour not found' });
    res.json(tour);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/tours', verifyToken, async (req, res) => {
  try {
    let tour = req.body;
    if (!tour.slug && tour.title) tour.slug = generateSlug(tour.title);
    const newTour = await toursDAL.create(tour);
    res.json(newTour);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/tours/:id', verifyToken, async (req, res) => {
  try {
    const updated = await toursDAL.update(req.params.id, req.body);
    if (!updated) return res.status(404).json({ error: 'Tour not found' });
    res.json(updated);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/tours/:id', verifyToken, async (req, res) => {
  try {
    await toursDAL.delete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ BOOKINGS ROUTES ============
app.post('/api/bookings', async (req, res) => {
  try {
    const { tourId, name, email, phone, nationality, persons, date, notes } = req.body;
    const tour = await toursDAL.getById(tourId);
    if (!tour) return res.status(404).json({ error: 'Tour not found' });
    
    const pricePerPerson = nationality === 'egyptian' ? tour.priceEgyptian : tour.priceForeigner;
    const totalPrice = pricePerPerson * (persons || 1);
    const currency = nationality === 'egyptian' ? 'EGP' : 'USD';
    
    const booking = await bookingsDAL.create({
      tourId, tourName: tour.title, name, email, phone, nationality, persons, date, notes,
      totalPrice, currency
    });
    
    // Send email
    try {
      await transporter.sendMail({
        from: `"رحلة في مصر" <${process.env.SMTP_USER}>`,
        to: email,
        subject: 'تأكيد حجز رحلتك',
        html: `<h2>تم استلام حجزك</h2><p>شكراً لحجزك معنا. سيتم التواصل معك قريباً لتأكيد الحجز.</p><p>رقم الحجز: ${booking.id}</p>`
      });
    } catch (emailError) { console.log('Email error:', emailError.message); }
    
    res.json({ success: true, id: booking.id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/bookings', verifyToken, async (req, res) => {
  try {
    const bookings = await bookingsDAL.getAll();
    res.json(bookings);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/bookings/:id', async (req, res) => {
  try {
    const booking = await bookingsDAL.getById(req.params.id);
    if (!booking) return res.status(404).json({ error: 'Booking not found' });
    res.json(booking);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/bookings/:id', verifyToken, async (req, res) => {
  try {
    const updated = await bookingsDAL.update(req.params.id, req.body);
    res.json(updated);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/bookings/:id', verifyToken, async (req, res) => {
  try {
    await bookingsDAL.delete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ RATINGS ROUTES ============
app.get('/api/rankings', async (req, res) => {
  try {
    const ratings = await ratingsDAL.getAll();
    res.json(ratings);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/rankings/tour/:tourId', async (req, res) => {
  try {
    const ratings = await ratingsDAL.getByTourId(req.params.tourId);
    res.json(ratings);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/rankings', async (req, res) => {
  try {
    const rating = await ratingsDAL.create(req.body);
    res.json(rating);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/rankings/:id', verifyToken, async (req, res) => {
  try {
    await ratingsDAL.delete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ CONTACTS ROUTES ============
app.post('/api/contacts', async (req, res) => {
  try {
    const contact = await contactsDAL.create(req.body);
    res.json(contact);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/contacts', verifyToken, async (req, res) => {
  try {
    const contacts = await contactsDAL.getAll();
    res.json(contacts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/contacts/:id', verifyToken, async (req, res) => {
  try {
    await contactsDAL.delete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ PAYMENT ROUTES ============
app.post('/api/payment/confirm', async (req, res) => {
  try {
    const { bookingId, transferNumber } = req.body;
    const booking = await bookingsDAL.getById(bookingId);
    if (!booking) return res.status(404).json({ error: 'Booking not found' });
    
    await bookingsDAL.update(bookingId, { paymentStatus: 'completed', transferNumber });
    
    // Send confirmation email
    try {
      await transporter.sendMail({
        from: `"رحلة في مصر" <${process.env.SMTP_USER}>`,
        to: booking.email,
        subject: '✅ تأكيد الحجز النهائي',
        html: `<h2>تم تأكيد حجزك بنجاح!</h2><p>نشكرك على ثقتك بنا. في انتظارك في رحلتك الممتعة.</p>`
      });
    } catch (e) { console.log(e); }
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ SERVER START ============
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});