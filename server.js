// --- Imports ---
require('dotenv').config(); // Make sure dotenv is configured at the very top
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require('pg'); // Import the Pool object from the pg library
const { GoogleGenerativeAI } = require("@google/generative-ai");

// --- Initial Setup ---
const app = express();
app.use(cors());
app.use(express.json());

// --- PostgreSQL Database Connection ---
// The Pool is a more advanced way to handle connections for web applications.
// It automatically manages multiple connections for you.
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Required for free Render databases
    }
});

// --- API & Security Setup ---
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const JWT_SECRET = process.env.JWT_SECRET;

// =================================================================
// AUTHENTICATION ROUTES (Now using PostgreSQL)
// =================================================================

app.post("/register", async (req, res) => {
    try {
        const { username, password } = req.body;
        // PostgreSQL uses $1, $2, etc., as placeholders for parameters to prevent SQL injection.
        const existingUser = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: "Username already exists." });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        // Insert the new user into the 'users' table.
        const newUser = await pool.query(
            'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id', 
            [username, hashedPassword]
        );
        
        res.status(201).json({ message: "User registered successfully!", userId: newUser.rows[0].id });
    } catch (err) {
        console.error("Register Error:", err.message);
        res.status(500).json({ error: "Server error during registration." });
    }
});

app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        // Find the user in the database.
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ error: "Invalid username or password." });
        }
        
        const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: "Login successful!", token });
    } catch (err) {
        console.error("Login Error:", err.message);
        res.status(500).json({ error: "Server error during login." });
    }
});

// =================================================================
// MIDDLEWARE (No changes here)
// =================================================================
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Access denied. No token provided." });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid token." });
        req.user = user;
        next();
    });
};

// =================================================================
// PROTECTED APPLICATION ROUTES (Now using PostgreSQL)
// =================================================================

app.post("/save-score", verifyToken, async (req, res) => {
    try {
        const { topic, score, total } = req.body;
        const { userId } = req.user;
        // Insert the new score into the 'scores' table.
        await pool.query(
            'INSERT INTO scores (user_id, topic, score, total, date) VALUES ($1, $2, $3, $4, $5)',
            [userId, topic, score, total, new Date().toISOString()]
        );
        res.status(201).json({ message: "Score saved successfully!" });
    } catch (err) {
        console.error("Save Score Error:", err.message);
        res.status(500).json({ error: "Server error while saving score." });
    }
});

app.get("/my-scores", verifyToken, async (req, res) => {
    try {
        const { userId } = req.user;
        // Select all scores for the logged-in user.
        const result = await pool.query('SELECT topic, score, total, date FROM scores WHERE user_id = $1', [userId]);
        res.json(result.rows);
    } catch (err) {
        console.error("Get Scores Error:", err.message);
        res.status(500).json({ error: "Server error while fetching scores." });
    }
});

// --- AI Generation Routes (No changes here) ---
app.post("/generate-quiz", verifyToken, async (req, res) => {
    const { topic, level, questionCount = 5 } = req.body;
    try {
        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash-latest" });
        const prompt = `Generate ${questionCount} multiple choice questions on the topic "${topic}" at a "${level}" difficulty level. The response MUST be a valid JSON array of objects. Do not include any text outside of the JSON array. Each object must have "question", "options" (an array of 4 strings), and "answer" properties.`;
        const result = await model.generateContent(prompt);
        const text = result.response.text();
        const cleanedText = text.replace(/^```json\s*|```\s*$/g, '');
        const questions = JSON.parse(cleanedText);
        res.json({ questions });
    } catch (err) {
        res.status(500).json({ error: "Failed to generate quiz questions." });
    }
});

app.post("/generate-hint", verifyToken, async (req, res) => {
    const { question, options } = req.body;
    try {
        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash-latest" });
        const prompt = `For the following multiple-choice question, provide a short, single-sentence hint that helps the user think about the answer without giving it away. Question: "${question}" Options: ${options.join(", ")} Hint:`;
        const result = await model.generateContent(prompt);
        const hint = result.response.text();
        res.json({ hint });
    } catch (err) {
        res.status(500).json({ error: "Failed to generate hint." });
    }
});

app.post("/generate-study-material", verifyToken, async (req, res) => {
    const { topic } = req.body;
    try {
        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash-latest" });
        const prompt = `Provide a concise, easy-to-understand study guide for the programming topic: "${topic}". The guide should cover the core concepts, key syntax, and a simple code example. Format the response as plain text, using markdown for headings and code blocks.`;
        const result = await model.generateContent(prompt);
        const studyMaterial = result.response.text();
        res.json({ studyMaterial });
    } catch (err) {
        res.status(500).json({ error: "Failed to generate study material." });
    }
});

// --- SERVER START ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Backend running on http://localhost:${PORT}`);
});
