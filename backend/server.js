// --- 1. Import Dependencies ---
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');

// --- 2. Initialize Application ---
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = 'your_super_secret_key_change_this';
const CLIENT_URL = `http://localhost:${PORT}`;
// IMPORTANT: Add your Gemini API Key here
const GEMINI_API_KEY = 'AIzaSyAxi3J1uf1BuLzrc4NQV86wQmkfORg8tqQ';

// --- 3. Middleware ---
app.use(cors({
    origin: CLIENT_URL,
    credentials: true,
}));
app.use(express.json());
app.use(cookieParser());
app.use(session({ secret: 'a_different_secret_key', resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

// --- 4. Serve Static Files ---
app.use(express.static(path.join(__dirname, 'public')));

// --- 5. Database Connection ---
const MONGO_URI = 'mongodb://localhost:27017/productivityhub';
mongoose.connect(MONGO_URI)
  .then(() => console.log('Successfully connected to MongoDB.'))
  .catch(err => console.error('MongoDB connection error:', err));

// --- 6. Models ---
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String },
    role: { type: String, enum: ['student', 'admin'], default: 'student' },
    googleId: { type: String },
    githubId: { type: String }
});
const User = mongoose.model('User', userSchema);

const todoSchema = new mongoose.Schema({
  text: { type: String, required: true },
  completed: { type: Boolean, default: false },
  isImportant: { type: Boolean, default: false },
  isUrgent: { type: Boolean, default: false },
  dueDate: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
});
const Todo = mongoose.model('Todo', todoSchema);

const noteSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    content: { type: String, default: '' },
    lastModified: { type: Date, default: Date.now },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
});
const Note = mongoose.model('Note', noteSchema);

// --- 7. Passport ---
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => done(err, user));
});

passport.use(new GoogleStrategy({
    clientID: '938471243676-gvcj2p35o3snm016ofjd95cn58u29qp4.apps.googleusercontent.com',
    clientSecret: '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',
    callbackURL: `${CLIENT_URL}/api/auth/google/callback`
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ googleId: profile.id });
        if (user) return done(null, user);
        user = await User.findOne({ email: profile.emails[0].value });
        if (user) {
            user.googleId = profile.id; await user.save(); return done(null, user);
        }
        const newUser = new User({ googleId: profile.id, name: profile.displayName, email: profile.emails[0].value });
        await newUser.save();
        done(null, newUser);
    } catch (err) { done(err, null); }
}));

passport.use(new GitHubStrategy({
    clientID: 'Ov23liC2sL99Eg3BiuAA',
    clientSecret: '656f898ba9d77a4c640a60cbfd04fcdb10f9063f',
    callbackURL: `${CLIENT_URL}/api/auth/github/callback`,
    scope: ['user:email']
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ githubId: profile.id });
        if (user) return done(null, user);
        const email = profile.emails && profile.emails[0].value;
        if (!email) return done(new Error("GitHub email not public."), null);
        user = await User.findOne({ email });
        if (user) { user.githubId = profile.id; await user.save(); return done(null, user); }
        const newUser = new User({ githubId: profile.id, name: profile.displayName || profile.username, email });
        await newUser.save();
        done(null, newUser);
    } catch (err) { done(err, null); }
}));

// --- 8. Auth Middleware ---
const authMiddleware = (req, res, next) => {
    const token = req.cookies?.token;
    if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Invalid token.' });
    }
};

// --- 9. Helper to set cookie ---
const setTokenCookie = (res, user) => {
    const payload = { user: { id: user.id, name: user.name, email: user.email, role: user.role } };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, {
        httpOnly: true,
        secure: false, // Set to true in production (https)
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000,
    });
};

// --- 10. Routes ---
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) return res.status(400).json({ message: 'Please enter all fields.' });
        let user = await User.findOne({ email });
        if (user) return res.status(400).json({ message: 'User already exists.' });
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        user = new User({ name, email, password: hashedPassword });
        await user.save();
        setTokenCookie(res, user);
        res.status(201).json({ user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    } catch (err) {
        res.status(500).json({ message: 'Server error during registration.', error: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: 'Please enter all fields.' });
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'Invalid credentials.' });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials.' });
        setTokenCookie(res, user);
        res.json({ user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    } catch (err) {
        res.status(500).json({ message: 'Server error during login.', error: err.message });
    }
});

app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/api/auth/google/callback', passport.authenticate('google', { failureRedirect: '/?error=true', session: false }), (req, res) => {
    setTokenCookie(res, req.user);
    res.redirect('/');
});

app.get('/api/auth/github', passport.authenticate('github', { scope: ['user:email'] }));
app.get('/api/auth/github/callback', passport.authenticate('github', { failureRedirect: '/?error=true', session: false }), (req, res) => {
    setTokenCookie(res, req.user);
    res.redirect('/');
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json({ user });
    } catch (err) {
        res.status(500).json({ message: 'Error fetching user data.' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('token', { httpOnly: true, sameSite: 'lax' });
    res.json({ message: 'Logged out successfully' });
});

// == NEW AI CHAT ROUTE ==
app.post('/api/ai/chat', authMiddleware, async (req, res) => {
    const { prompt, history } = req.body;

    if (!prompt) {
        return res.status(400).json({ message: 'Prompt is required.' });
    }
    if (!GEMINI_API_KEY || GEMINI_API_KEY === 'YOUR_GEMINI_API_KEY') {
        return res.status(500).json({ message: 'AI API key is not configured on the server.' });
    }

    const GEMINI_API_URL = `https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${GEMINI_API_KEY}`;
    
    const contents = history.map(item => ({
        role: item.role,
        parts: [{ text: item.parts[0].text }]
    }));
    contents.push({ role: 'user', parts: [{ text: prompt }] });

    try {
        const geminiResponse = await fetch(GEMINI_API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ contents }),
        });

        if (!geminiResponse.ok) {
            const errorBody = await geminiResponse.text();
            console.error("Gemini API Error:", errorBody);
            throw new Error(`Gemini API responded with status: ${geminiResponse.status}`);
        }

        const data = await geminiResponse.json();
        
        if (data.candidates && data.candidates.length > 0 && data.candidates[0].content) {
            const aiResponse = data.candidates[0].content.parts[0].text;
            res.json({ response: aiResponse });
        } else {
            res.json({ response: "I'm sorry, I couldn't generate a response for that. Please try a different topic." });
        }

    } catch (err) {
        console.error('Error calling Gemini API:', err);
        res.status(500).json({ message: 'Failed to get response from AI.' });
    }
});


// All other API routes for todos and notes go here...
app.get('/api/todos', authMiddleware, async (req, res) => {
  try {
    const todos = await Todo.find({ user: req.user.id }).sort({ createdAt: -1 });
    res.json(todos);
  } catch (err) { res.status(500).json({ message: 'Server Error' }); }
});
app.post('/api/todos', authMiddleware, async (req, res) => {
  const { text, isImportant, isUrgent, dueDate } = req.body;
  try {
    const newTodo = new Todo({ text, isImportant, isUrgent, dueDate, user: req.user.id });
    const savedTodo = await newTodo.save();
    res.status(201).json(savedTodo);
  } catch (err) { res.status(500).json({ message: 'Server Error' }); }
});
app.put('/api/todos/:id', authMiddleware, async (req, res) => {
  try {
    let todo = await Todo.findById(req.params.id);
    if (!todo || todo.user.toString() !== req.user.id) return res.status(401).json({ message: 'Not authorized' });
    
    todo = await Todo.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(todo);
  } catch (err) { res.status(500).json({ message: 'Server Error' }); }
});
app.delete('/api/todos/:id', authMiddleware, async (req, res) => {
  try {
    let todo = await Todo.findById(req.params.id);
    if (!todo || todo.user.toString() !== req.user.id) return res.status(401).json({ message: 'Not authorized' });

    await Todo.findByIdAndDelete(req.params.id);
    res.json({ message: 'Todo successfully deleted' });
  } catch (err) { res.status(500).json({ message: 'Server Error' }); }
});
app.get('/api/notes', authMiddleware, async (req, res) => {
    try {
        const notes = await Note.find({ user: req.user.id }).sort({ lastModified: -1 });
        res.json(notes);
    } catch (err) { res.status(500).json({ message: 'Server Error' }); }
});
app.post('/api/notes', authMiddleware, async (req, res) => {
    const { title, content } = req.body;
    try {
        const newNote = new Note({ title, content, user: req.user.id });
        const savedNote = await newNote.save();
        res.status(201).json(savedNote);
    } catch (err) { res.status(500).json({ message: 'Server Error' }); }
});
app.put('/api/notes/:id', authMiddleware, async (req, res) => {
    try {
        let note = await Note.findById(req.params.id);
        if (!note || note.user.toString() !== req.user.id) return res.status(401).json({ message: 'Not authorized' });
        
        note = await Note.findByIdAndUpdate(req.params.id, { ...req.body, lastModified: Date.now() }, { new: true });
        res.json(note);
    } catch (err) { res.status(500).json({ message: 'Server Error' }); }
});
app.delete('/api/notes/:id', authMiddleware, async (req, res) => {
    try {
        let note = await Note.findById(req.params.id);
        if (!note || note.user.toString() !== req.user.id) return res.status(401).json({ message: 'Not authorized' });

        await Note.findByIdAndDelete(req.params.id);
        res.json({ message: 'Note successfully deleted' });
    } catch (err) { res.status(500).json({ message: 'Server Error' }); }
});


// --- 11. Fallback to index.html ---
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- 12. Start Server ---
app.listen(PORT, () => {
    console.log(`Server running at ${CLIENT_URL}`);
});