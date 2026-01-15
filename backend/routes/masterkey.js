const express = require("express");
const crypto = require("crypto");
const router = express.Router();
const db = require("../db");
const auth = require("../middleware/auth");
const jwt = require("jsonwebtoken");

// 1. TẠO CHALLENGE
router.post("/challenge", auth, async (req, res) => {
  const userId = req.user.uid;
  const nonce = crypto.randomBytes(32);
  const expiresAt = new Date(Date.now() + 60 * 1000); // 60s

  await db.execute(
    `REPLACE INTO masterkey_nonce (user_id, nonce, expires_at) VALUES (?, ?, ?)`,
    [userId, nonce, expiresAt]
  );

  res.json({
    nonce: nonce.toString("base64"), // Gửi Base64 cho Client dễ ký
    expiresIn: 60
  });
});

// 2. VERIFY (KIỂM TRA CHỮ KÝ HMAC)
router.post("/verify", auth, async (req, res) => {
  const userId = req.user.uid;
  const { hmac } = req.body; // Client gửi chữ ký Hex lên

  if (!hmac) return res.status(400).json({ error: "Missing HMAC" });

  try {
    // Lấy Nonce và AuthKey từ DB
    const [rows] = await db.execute(
      `SELECT m.nonce, m.expires_at, u.auth_key_verifier 
       FROM masterkey_nonce m
       JOIN users u ON m.user_id = u.id
       WHERE m.user_id = ?`,
      [userId]
    );

    if (rows.length === 0) return res.status(401).json({ error: "No challenge found" });
    const record = rows[0];
    console.log("🔍 [SERVER] AuthKey trong DB:", record.auth_key_verifier);

    if (new Date() > new Date(record.expires_at)) {
      return res.status(401).json({ error: "Challenge expired" });
    }

    // --- TÍNH TOÁN HMAC TẠI SERVER ---
    const serverNonceBase64 = record.nonce.toString("base64");
    const userAuthKey = record.auth_key_verifier; // Đây là Key Hex

    // Tính HMAC giống hệt Client: HMAC(Key, Message)
    const calculatedHmac = crypto
      .createHmac("sha256", userAuthKey) // Key
      .update(serverNonceBase64)         // Message (Nonce Base64)
      .digest("hex");                    // Output Hex

    console.log(`Server Calc: ${calculatedHmac} | Client Sent: ${hmac}`);

    if (calculatedHmac !== hmac) {
       return res.status(403).json({ error: "Sai Master Key! (Chữ ký không khớp)" });
    }

    // Nếu đúng -> Xóa Nonce và Cấp Token
    await db.execute(`DELETE FROM masterkey_nonce WHERE user_id = ?`, [userId]);

    const unlockToken = jwt.sign(
      { uid: userId, mk: true },
      process.env.JWT_SECRET,
      { expiresIn: "5m" }
    );

    res.json({ status: "ok", unlockToken });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;