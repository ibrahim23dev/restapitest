const express = require('express');
const dotenv = require('dotenv').config();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

const app = express();
const port = process.env.PORT || 5000;

// Define your JWT secret directly in the code
const JWT_SECRET = "ibrahim640"; // Replace this with your actual secret key

// Middleware
app.use(express.json());
app.use(cors({
    origin: '*' // Update this to restrict access to your frontend URL in production
}));

// MongoDB Connection
mongoose.connect(process.env.DATABASE_URL)
    .then(() => console.log("Database connected successfully."))
    .catch(error => {
        console.error("Database connection failed:", error.message);
        process.exit(1);
    });

// User Schema with Mongoose
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// Middleware to protect routes and check user authentication
const protect = (req, res, next) => {
    const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Not authorized, token missing' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Token expired or invalid' });
    }
};

// Middleware to restrict access based on role
const restrictTo = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Access denied' });
        }
        next();
    };
};

// Authentication controller for login
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid password' });
        }
        const token = jwt.sign(
            { id: user._id, role: user.role },
            JWT_SECRET,
            { expiresIn: '1h' }
        );
        res.status(200).json({ token, role: user.role });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Dashboard controllers
app.get('/api/auth/teacher', protect, restrictTo('Teacher'), (req, res) => {
    res.json({ message: 'Welcome to the Teacher Dashboard' });
});

app.get('/api/auth/coordinator', protect, restrictTo('Coordinator'), (req, res) => {
    res.json({ message: 'Welcome to the Coordinator Dashboard' });
});

// Root endpoint
app.get('/', (req, res) => {
    res.send('Alhamdulillah for Everything');
});

// Start the server
app.listen(port, () => console.log(`Server running on port ${port}`));
