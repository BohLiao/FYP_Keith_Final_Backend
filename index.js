import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import mysql from "mysql2";
import dotenv from "dotenv";
import multer from "multer";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { dirname } from "path";

// Crypto simulation for Kyber + AES
const simulateKyberAesDecrypt = (ciphertext) => {
  try {
    const match = ciphertext.match(/^🔒\[[a-fA-F0-9]{32}\](.+)$/);
    if (!match) return null;
    const base64 = match[1];
    return decodeURIComponent(escape(Buffer.from(base64, "base64").toString()));
  } catch (err) {
    console.error("Decryption error:", err);
    return null;
  }
};

// App setup
dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const app = express();
const port = process.env.PORT || 3001;

app.use(
  cors({
    origin: process.env.FRONTEND_ORIGIN || "*", // fallback to '*' if not defined
    credentials: true,
  })
);
app.use(bodyParser.json());

// MySQL connection
const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: {
    ca: fs.readFileSync(process.env.SSL_CA),
  },
});

db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err.stack);
    return;
  }
  console.log("Connected to MySQL database.");
});

// File uploads
const uploadDir = path.join(__dirname, "public", "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
app.use("/uploads", express.static(uploadDir));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, `${file.fieldname}-${unique}${ext}`);
  },
});
const upload = multer({ storage });

// --- Registration: store encrypted values directly ---
app.post("/register", (req, res) => {
  const { username, password, email, phone } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  const plainUsername = simulateKyberAesDecrypt(username);
  const plainEmail = simulateKyberAesDecrypt(email);

  db.query("SELECT * FROM users", [], (err, results) => {
    if (err) {
      console.error("Database fetch failed:", err);
      return res.status(500).json({ error: "Registration failed" });
    }

    const duplicate = results.find(
      (row) =>
        simulateKyberAesDecrypt(row.username) === plainUsername ||
        simulateKyberAesDecrypt(row.email) === plainEmail
    );

    if (duplicate) {
      return res
        .status(409)
        .json({ error: "Username or email already exists" });
    }

    // Proceed with inserting encrypted values
    const sql =
      "INSERT INTO users (username, password, email, phone, otp) VALUES (?, ?, ?, ?, ?)";
    db.query(sql, [username, password, email, phone, otp], (err2) => {
      if (err2) {
        console.error("Insert error:", err2);
        return res.status(500).json({ error: "Registration failed" });
      }
      return res.status(200).json({ message: "User registered", otp });
    });
  });
});

// --- Login: decrypt to verify ---
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const u = simulateKyberAesDecrypt(username);
  const p = simulateKyberAesDecrypt(password);

  const sql = "SELECT * FROM users";
  db.query(sql, [], (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });

    const user = results.find(
      (row) =>
        simulateKyberAesDecrypt(row.username) === u &&
        simulateKyberAesDecrypt(row.password) === p
    );

    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    db.query(
      "UPDATE users SET otp = ? WHERE id = ?",
      [otp, user.id],
      (err2) => {
        if (err2)
          return res.status(500).json({ error: "Failed to update OTP" });
        return res
          .status(200)
          .json({ message: "OTP sent", username: user.username, otp });
      }
    );
  });
});

// --- Verify OTP ---
app.post("/verify-otp", (req, res) => {
  const { username, otp } = req.body;
  const u = simulateKyberAesDecrypt(username);

  const sql = "SELECT * FROM users";
  db.query(sql, [], (err, results) => {
    if (err) return res.status(500).json({ error: "Server error" });

    const user = results.find(
      (row) => simulateKyberAesDecrypt(row.username) === u && row.otp === otp
    );

    if (!user) return res.status(401).json({ error: "Invalid OTP" });

    db.query("UPDATE users SET otp = NULL WHERE id = ?", [user.id]);
    return res.status(200).json({ message: "OTP verified" });
  });
});

// --- Resend OTP ---
app.post("/resend-otp", (req, res) => {
  const u = simulateKyberAesDecrypt(req.body.username);
  if (!u) return res.status(400).json({ error: "Username is required" });

  const newOtp = Math.floor(100000 + Math.random() * 900000).toString();

  const sql = "SELECT * FROM users";
  db.query(sql, [], (err, results) => {
    if (err) return res.status(500).json({ error: "Server error" });

    const user = results.find(
      (row) => simulateKyberAesDecrypt(row.username) === u
    );
    if (!user) return res.status(404).json({ error: "User not found" });

    db.query(
      "UPDATE users SET otp = ? WHERE id = ?",
      [newOtp, user.id],
      (err2) => {
        if (err2)
          return res.status(500).json({ error: "Failed to update OTP" });
        res.status(200).json({ message: "OTP resent", otp: newOtp });
      }
    );
  });
});

// --- Upload endpoint ---
app.post("/upload", upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });
  const fileUrl = `http://localhost:${port}/uploads/${req.file.filename}`;
  res.json({ url: fileUrl });
});

// --- Users for chat list ---
app.get("/users", (req, res) => {
  db.query("SELECT username FROM users", (err, results) => {
    if (err) return res.status(500).json({ error: "Failed to fetch users" });
    res.status(200).json(results);
  });
});

// --- Get messages ---
app.get("/messages", (req, res) => {
  const { from, to } = req.query;
  if (!from || !to) return res.status(400).json({ error: "Missing from/to" });

  const sql =
    from === "Hacker"
      ? "SELECT * FROM messages ORDER BY timestamp ASC"
      : "SELECT * FROM messages WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?) ORDER BY timestamp ASC";

  const params = from === "Hacker" ? [] : [from, to, to, from];

  db.query(sql, params, (err, results) => {
    if (err) return res.status(500).json({ error: "Failed to fetch messages" });
    res.status(200).json(results);
  });
});

// --- Send message ---
app.post("/send", (req, res) => {
  const { from, to, message } = req.body;
  if (!from || !to || !message)
    return res.status(400).json({ error: "Missing fields" });

  db.query(
    "INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)",
    [from, to, message],
    (err) => {
      if (err) return res.status(500).json({ error: "Failed to send message" });
      res.status(200).json({ message: "Message sent" });
    }
  );
});

// --- Start server ---
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
