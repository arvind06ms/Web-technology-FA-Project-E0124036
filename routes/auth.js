const express = require('express');
const router = express.Router();
const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const JWT_SECRET = process.env.JWT_SECRET || 'please_change_this_secret';

// POST /api/auth/register
router.post('/register',
  // validation
  body('username').isLength({ min: 3 }).trim().escape(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: 'Invalid input', errors: errors.array() });

    const { username, email, password } = req.body;
    try {
      const exists = await User.findOne({ email });
      if (exists) return res.status(409).json({ message: 'Email already registered' });

      const hash = await bcrypt.hash(password, 12);
      const user = new User({ username, email, password: hash });
      await user.save();
      res.json({ message: 'Registration successful' });
    } catch (err) {
      console.error('Register error', err);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// POST /api/auth/login
router.post('/login',
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: 'Invalid input', errors: errors.array() });

    const { email, password } = req.body;
    try {
      const user = await User.findOne({ email });
      if (!user) return res.status(401).json({ message: 'Invalid credentials' });

      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.status(401).json({ message: 'Invalid credentials' });

      const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

      // Set token as HttpOnly cookie (safer than localStorage)
      res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });

      res.json({ username: user.username });
    } catch (err) {
      console.error('Login error', err);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// Auth middleware: check token from HttpOnly cookie
function authenticate(req, res, next) {
  try {
    const token = req.cookies && req.cookies.token;
    if (!token) return res.status(401).json({ message: 'Not authenticated' });
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

// GET /api/auth/me - returns current user info (protected)
router.get('/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ user });
  } catch (err) {
    console.error('Me error', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/auth/logout - clear auth cookie
router.post('/logout', (req, res) => {
  res.clearCookie('token', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax' });
  res.json({ message: 'Logged out' });
});

// Expose CSRF token endpoint (GET) - client can call this to obtain token for X-CSRF-Token header
router.get('/csrf-token', (req, res) => {
  try {
    const token = req.csrfToken();
    res.json({ csrfToken: token });
  } catch (err) {
    res.status(500).json({ message: 'Could not generate CSRF token' });
  }
});

module.exports = router;
