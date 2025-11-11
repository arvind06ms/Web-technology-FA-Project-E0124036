require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');


const authRouter = require('./routes/auth');

const app = express();

// Security headers
app.use(helmet());

// Limit request body size to reduce abuse
app.use(express.json({ limit: '10kb' }));

// Cookie parser for HttpOnly cookies
app.use(cookieParser());

// Basic rate limiting
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }); // 200 requests per 15 minutes
app.use(limiter);

// Restrict CORS to the front-end origin (set FRONTEND_ORIGIN in .env) and allow credentials for cookies
const FRONTEND = process.env.FRONTEND_ORIGIN || 'http://localhost:8000';
app.use(cors({ origin: FRONTEND, credentials: true }));

// CSRF protection using csurf with cookie-based secrets
const csurf = require('csurf');
app.use(csurf({ cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' } }));

// Provide a small middleware to attach the csrf token to any GET / safe endpoints if needed
app.use(function (req, res, next) {
  // Expose csrf token in a response header for convenience on GET requests
  if (req.method === 'GET' && req.csrfToken) {
    try { res.setHeader('X-CSRF-Token', req.csrfToken()); } catch (e) { /* sometimes not needed */ }
  }
  next();
});

app.use('/api/auth', authRouter);

const PORT = process.env.PORT || 3000;

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('Connected to MongoDB');
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });
