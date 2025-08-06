// (All the imports and setup are the same)
require('dotenv').config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require('pg');
const { GoogleGenerativeAI } = require("@google/generative-ai");

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const JWT_SECRET = process.env.JWT_SECRET;

// (Login, Register, and Middleware are the same)
// ...

// =================================================================
// ADMIN ROUTES
// =================================================================

// This route just gets the list of users. We'll keep it for now.
app.get("/admin/users", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username FROM users ORDER BY id');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Server error while fetching users." });
    }
});

// --- NEW: Route to get all users AND all their scores ---
app.get("/admin/full-data", verifyToken, verifyAdmin, async (req, res) => {
    try {
        // We use a more advanced SQL query with a JOIN to combine data from two tables.
        // This query selects all scores and includes the username for each score's owner.
        const query = `
            SELECT 
                s.id, 
                s.topic, 
                s.score, 
                s.total, 
                s.date, 
                u.username 
            FROM scores s
            JOIN users u ON s.user_id = u.id
            ORDER BY u.username, s.date DESC;
        `;
        const result = await pool.query(query);
        res.json(result.rows); // Send the combined data
    } catch (err) {
        console.error("Get Full Admin Data Error:", err.message);
        res.status(500).json({ error: "Server error while fetching full admin data." });
    }
});


// (The rest of your server.js file is the same)
// ...

// --- SERVER START ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Backend running on http://localhost:${PORT}`);
});
