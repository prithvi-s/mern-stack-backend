require('dotenv').config(); // Load environment variables from .env

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 5000; // Use environment variable for port

app.use(cors());
app.use(express.json());

// MongoDB Connection
const uri = process.env.MONGODB_URI || "mongodb://localhost:27017/todos"; // Use environment variable

mongoose.connect(uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => console.log("Connected to MongoDB"))
    .catch(err => console.error("MongoDB connection error:", err));

// User Schema and Model
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// Todo Schema and Model (existing)
const todoSchema = new mongoose.Schema({
    text: { type: String, required: true },
    completed: { type: Boolean, default: false },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true } // Add userId field
});

const Todo = mongoose.model('Todo', todoSchema);

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

    if (token == null) {
        return res.sendStatus(401); // No token
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403); // Invalid token (expired, tampered)
        }

        req.user = user; // Store the decoded user information in req.user
        next(); // Proceed to the next middleware or route handler
    });
};

// API Endpoints (existing)
app.get('/todos', authenticateToken, async (req, res) => { // Apply middleware
    try {
        const userId = req.user.userId; // Extract user ID from the JWT
        const todos = await Todo.find({ userId: userId }); // Filter todos by user ID
        res.json(todos);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/todos', authenticateToken, async (req, res) => { // Apply middleware
    const userId = req.user.userId; // Extract user ID from the JWT
    const todo = new Todo({
        text: req.body.text,
        userId: userId // Associate the todo with the user ID
    });

    try {
        const newTodo = await todo.save();
        res.status(201).json(newTodo);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// Register Endpoint
app.post('/register', async (req, res) => {
    try {
        // 1. Hash the password
        const hashedPassword = await bcrypt.hash(req.body.password, 10); // 10 is the salt rounds

        // 2. Create a new user
        const user = new User({
            username: req.body.username,
            password: hashedPassword
        });

        // 3. Save the user to the database
        const newUser = await user.save();

        // 4. Send a success response
        res.status(201).json({ message: 'User created successfully' });
    } catch (err) {
        // 5. Handle errors
        res.status(500).json({ message: err.message });
    }
});

// Login Endpoint
app.post('/login', async (req, res) => {
    try {
        // 1. Find the user by username
        const user = await User.findOne({ username: req.body.username });

        // 2. If the user doesn't exist, return an error
        if (!user) {
            return res.status(400).json({ message: 'Cannot find user' });
        }

        // 3. Compare the entered password with the hashed password
        const passwordMatch = await bcrypt.compare(req.body.password, user.password);

        // 4. If the passwords don't match, return an error
        if (!passwordMatch) {
            return res.status(400).json({ message: 'Incorrect password' });
        }

        // 5. Generate a JWT
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '10s' }); // Use environment variable

        // 6. Send a success response with the token
        res.json({ message: 'Login successful', token: token });
    } catch (err) {
        // 7. Handle errors
        res.status(500).json({ message: err.message });
    }
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
