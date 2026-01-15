const express = require("express");
const crypto = require("crypto");
const router = express.Router();
const db = require("../db");
const auth = require("../middleware/auth");
const jwt = require("jsonwebtoken"); // <--- Bạn thiếu import này trong code cũ

// ❌ CŨ: router.post("/masterkey/challenge", ...
// ✅ MỚI: Chỉ để "/challenge" (Vì app.js sẽ lo phần đầu)
router.post("/challenge", auth, async (req, res) => {
  const userId = req.user.uid;
  const nonce = crypto.randomBytes(32);
  // Expires 30 giây (Sửa lại phép tính thời gian cho đúng JS Date)
  const expiresAt = new Date(Date.now() + 30 * 1000); 

  try {
    await db.execute(
      `REPLACE INTO masterkey_nonce (user_id, nonce, expires_at)
       VALUES (?, ?, ?)`,
      [userId, nonce, expiresAt]
    );

    res.json({
      nonce: nonce.toString("base64"),
      expiresIn: 30
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

// ❌ CŨ: router.post("/masterkey/verify", ...
// ✅ MỚI: Chỉ để "/verify"
router.post("/verify", auth, async (req, res) => {
  const userId = req.user.uid;
  const { hmac } = req.body;

  if (!hmac) return res.status(400).json({ error: "Missing HMAC" });

  try {
    const [rows] = await db.execute(
      `SELECT nonce, expires_at FROM masterkey_nonce WHERE user_id = ?`,
      [userId]
    );

    if (rows.length === 0) return res.status(401).json({ error: "No challenge" });
    
    const record = rows[0];
    if (new Date() > new Date(record.expires_at)) {
      return res.status(401).json({ error: "Challenge expired" });
    }

    // Xóa nonce sau khi dùng
    await db.execute(`DELETE FROM masterkey_nonce WHERE user_id = ?`, [userId]);

    // Tạo token mở két
    const unlockToken = jwt.sign(
      { uid: userId, mk: true },
      process.env.JWT_SECRET,
      { expiresIn: "5m" } // 5 phút thôi
    );

    res.json({ status: "ok", unlockToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;