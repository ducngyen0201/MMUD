const express = require("express");
const router = express.Router();
const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
const db = require("../db/index");

router.post("/register", async (req, res) => {
  const { username, passwordHash, authKeyHash, kdfSalt } = req.body;

  // 1️⃣ Validate input
  if (!username || !passwordHash || !authKeyHash || !kdfSalt) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    // 2️⃣ Insert user
    await db.execute(
      `INSERT INTO users 
       (username, password_hash, auth_key_hash, kdf_salt)
       VALUES (?, ?, ?, ?)`,
      [
        username,
        passwordHash,
        authKeyHash,
        Buffer.from(kdfSalt, "base64")
      ]
    );

    res.json({ status: "ok" });

  } catch (err) {
    // 3️⃣ Duplicate username
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ error: "User already exists" });
    }

    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // 1️⃣ Validate input
  if (!username || !password) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    // 2️⃣ Lấy user từ DB
    const [rows] = await db.execute(
      "SELECT id, password_hash FROM users WHERE username = ?",
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = rows[0];

    // 3️⃣ Verify password
    const ok = await argon2.verify(user.password_hash, password);
    if (!ok) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // 4️⃣ Tạo JWT session
    const token = jwt.sign(
      { uid: user.id },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );

    res.json({ status: "ok", token });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
