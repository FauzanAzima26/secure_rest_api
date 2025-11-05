const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const users = []; // penyimpanan sementara (bisa diganti DB)

console.log("PORT:", process.env.PORT);
console.log("JWT_SECRET:", process.env.JWT_SECRET);

app.get("/", (req, res) => {
  res.send("🚀 Secure REST API with HTTPS and JWT is running!");
});

// REGISTER
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  users.push({ username, password: hashed });
  res.json({ message: "User registered" });
});

// LOGIN
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: "Missing username or password" });

    const user = users.find(u => u.username === username);
    if (!user) return res.status(400).json({ message: "User not found" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ message: "Invalid password" });

    const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// MIDDLEWARE AUTENTIKASI
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Access denied" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
}

// ROUTE TERLINDUNGI
app.get("/protected", verifyToken, (req, res) => {
  res.json({ message: `Hello ${req.user.username}, you accessed a protected route!` });
});

const PORT = process.env.PORT;
if (!PORT) {
  console.error("❌ No PORT environment variable found");
  process.exit(1);
}

app.get("/health", (req, res) => res.json({ status: "ok" }));
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));