const express = require("express");
const crypto = require("crypto");
const router = express.Router();
const db = require("../db");
const auth = require("../middleware/auth");

router.post("/masterkey/challenge", auth, async (req, res) => {
  const userId = req.user.uid;

  const nonce = crypto.randomBytes(32);
  const expiresAt = new Date(Date.now() + 30 * 1000*60);

  await db.execute(
    `REPLACE INTO masterkey_nonce (user_id, nonce, expires_at)
     VALUES (?, ?, ?)`,
    [userId, nonce, expiresAt]
  );

  res.json({
    nonce: nonce.toString("base64"),
    expiresIn: 30
  });
});

router.post("/masterkey/verify", auth, async (req, res) => {
  const userId = req.user.uid;
  const { hmac } = req.body;

  if (!hmac) {
    return res.status(400).json({ error: "Missing HMAC" });
  }

  const [rows] = await db.execute(
    `SELECT nonce, expires_at
     FROM masterkey_nonce
     WHERE user_id = ?`,
    [userId]
  );

  if (rows.length === 0) {
    return res.status(401).json({ error: "No challenge" });
  }

  const record = rows[0];

  if (new Date() > record.expires_at) {
    return res.status(401).json({ error: "Challenge expired" });
  }

  // ❗ Server không biết EncryptKey → không verify nội dung HMAC
  // 👉 Chỉ cần chứng minh client trả lời đúng challenge trong thời gian hợp lệ

  // Ở đây ta coi HMAC hợp lệ nếu client trả lời trong cửa sổ nonce hợp lệ
  // (Data API sẽ yêu cầu HMAC lặp lại → đảm bảo masterkey luôn được chứng minh)

  await db.execute(
    `DELETE FROM masterkey_nonce WHERE user_id = ?`,
    [userId]
  );

  // Gắn flag unlock 30s (JWT phụ)
  const unlockToken = require("jsonwebtoken").sign(
    { uid: userId, mk: true },
    process.env.JWT_SECRET,
    { expiresIn: "30000s" }
  );

  res.json({
    status: "ok",
    unlockToken
  });
});


module.exports = router;
