const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');

const app = express();

// MongoDB connection
mongoose.connect('mongodb://127.0.0.1:27017/eshop')
  .then(() => console.log("Connected to MongoDB"))
  .catch(err => console.log("MongoDB connection failed:", err));

// User Model
const UserSchema = new mongoose.Schema({
  fullName: String,
  username: { type: String, unique: true },
  email: { type: String, unique: true },
  password: String
});

const User = mongoose.model('User', UserSchema);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false
}));

// Serve static files from the root directory
app.use(express.static(path.join(__dirname)));

// Check authentication middleware
function isAuthenticated(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/login-page.html');
}

// Routes
app.post('/register', async (req, res) => {
  try {
    const { fullName, username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      fullName,
      username,
      email,
      password: hashedPassword
    });
    await user.save();
    req.session.userId = user._id;
    res.redirect('/index.html');
  } catch (error) {
    console.error("Registration error:", error);
    res.status(400).send('Registration failed. Username or email may already exist.');
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).send('User not found');
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).send('Invalid password');
    }

    req.session.userId = user._id;
    res.redirect('/index.html');
  } catch (error) {
    console.error("Login error:", error);
    res.status(400).send('Login failed');
  }
});

// Protected route
app.get('/index.html', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login-page.html');
});

// Import and use order routes
const orderRoutes = require('./routes/orderRoutes');
app.use(orderRoutes);

// Start the server
app.listen(3000, () => console.log('Server running on port 3000'));