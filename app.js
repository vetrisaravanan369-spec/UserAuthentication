const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// Sample in-memory "database"
let users = [];

// Register User
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  // check if user already exists
  const existing = users.find(u => u.email === email);
  if (existing) return res.status(400).json({ msg: "User already exists" });

  // hash password
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ name, email, password: hashedPassword });

  res.json({ msg: "User registered successfully!" });
});

// Login User
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(u => u.email === email);
  if (!user) return res.status(400).json({ msg: "User not found" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ msg: "Invalid password" });

  const token = jwt.sign({ email: user.email }, "secretkey", { expiresIn: "1h" });
  res.json({ msg: "Login successful!", token });
});

// Protected Route
app.get("/profile", (req, res) => {
  const token = req.header("Authorization");
  if (!token) return res.status(401).json({ msg: "No token provided" });

  try {
    const decoded = jwt.verify(token.split(" ")[1], "secretkey");
    res.json({ msg: "Welcome to your profile!", user: decoded.email });
  } catch (err) {
    res.status(400).json({ msg: "Invalid token" });
  }
});

// Start Server
app.listen(5000, () => console.log("🚀 Server running on http://localhost:5000"));
