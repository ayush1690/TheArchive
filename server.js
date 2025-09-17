const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// --- MongoDB connection with logging ---
mongoose.connect("mongodb+srv://ayushman1690_db_user:u0VHY6q2lqdGlvK0@thearchive.xxxxx.mongodb.net/breedvision?retryWrites=true&w=majority"
);

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
    console.log('Connected to MongoDB');
});

// --- User schema/model ---
const UserSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String
});
const UserModel = mongoose.model('User', UserSchema);

// --- Image schema/model ---
const ImageSchema = new mongoose.Schema({
    filename: String,
    result: Array, // Array of {breed, prob}
    uploadedAt: { type: Date, default: Date.now },
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User" }
});
const ImageModel = mongoose.model('Image', ImageSchema);

// --- Multer setup ---
const storage = multer.memoryStorage();
const upload = multer({ storage });

// --- JWT secret ---
const JWT_SECRET = "your-secret-key";

// --- Register API ---
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Missing data" });
    const hash = await bcrypt.hash(password, 12);
    try {
        const user = await UserModel.create({ username, password: hash });
        res.json({ message: "User registered", id: user._id });
    } catch (e) {
        console.error("Registration error:", e);
        if (e.code === 11000) {
            res.status(400).json({ error: "Username taken" });
        } else {
            res.status(400).json({ error: e.message });
        }
    }
});

// --- Login API ---
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await UserModel.findOne({ username });
    if (!user) return res.status(400).json({ error: "User not found" });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Invalid password" });
    const token = jwt.sign({ uid: user._id }, JWT_SECRET);
    res.json({ message: "Login success", token });
});

// --- Auth middleware ---
const requireAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "No token" });
    try {
        const decoded = jwt.verify(authHeader.replace("Bearer ", ""), JWT_SECRET);
        req.userId = decoded.uid;
        next();
    } catch {
        res.status(401).json({ error: "Invalid token" });
    }
};

// --- Image upload API ---
app.post('/api/upload', requireAuth, upload.single('image'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No image file uploaded!' });
    // Simulated breed prediction (replace this with TensorFlow.js logic)
    const top3 = [
        { breed: "Gir", prob: 0.88 },
        { breed: "Sahiwal", prob: 0.09 },
        { breed: "Murrah", prob: 0.03 }
    ];
    const saved = await ImageModel.create({
        filename: req.file.originalname,
        result: top3,
        user: req.userId
    });
    res.json({ message: 'Image uploaded and predicted!', breeds: top3, id: saved._id, filename: saved.filename });
});

// --- Get previous results (protected) ---
app.get('/api/results', requireAuth, async (req, res) => {
    const results = await ImageModel.find({ user: req.userId }).sort({ uploadedAt: -1 }).limit(20);
    res.json(results);
});

app.listen(4000, () => console.log('Server running on port 4000'));
