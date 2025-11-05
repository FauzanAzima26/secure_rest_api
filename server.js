const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

// === CONNECT TO MONGODB ===
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB error:", err));

// === USER MODEL ===
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});
const User = mongoose.model("User", userSchema);

// === REGISTER ===
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  await User.create({ username, password: hashed });
  res.json({ status: "success", message: "User registered" });
});

// === LOGIN ===
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ error: "User not found" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: "Invalid password" });

  const token = jwt.sign({ id: user._id, username }, process.env.JWT_SECRET, { expiresIn: "1h" });
  res.json({ status: "success", token });
});

// === PROTECTED ROUTE ===
app.get("/protected", verifyToken, (req, res) => {
  res.json({ message: "Protected data accessed", user: req.user });
});

// === VERIFY TOKEN FUNCTION ===
function verifyToken(req, res, next) {
  const header = req.headers["authorization"];
  if (!header) return res.status(403).json({ error: "Token missing" });

  const token = header.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
}

// === START SERVER ===
app.listen(process.env.PORT, () => {
  console.log(`🚀 Secure REST API running on port ${process.env.PORT}`);
});
