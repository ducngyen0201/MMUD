const express = require("express");
const router = express.Router();
const db = require("../db");
const bcrypt = require("bcryptjs"); // Nhớ dùng bcryptjs cho đỡ lỗi
const jwt = require("jsonwebtoken");

// 1. ĐĂNG KÝ
router.post("/register", async (req, res) => {
  // Frontend gửi: username, passwordHash (thô), authKeyHash (là authKey hex), kdfSalt (base64)
  const { username, passwordHash, authKeyHash, kdfSalt } = req.body;

  if (!username || !passwordHash || !authKeyHash || !kdfSalt) {
    return res.status(400).json({ error: "Thiếu thông tin đăng ký" });
  }

  try {
    // Hash mật khẩu đăng nhập để lưu DB
    const serverPasswordHash = await bcrypt.hash(passwordHash, 10);

    // Insert vào DB với tên cột chuẩn theo Schema mới
    await db.execute(
      `INSERT INTO users (username, password_hash, auth_key_verifier, kdf_salt) 
       VALUES (?, ?, ?, ?)`,
      [username, serverPasswordHash, authKeyHash, kdfSalt]
    );

    res.json({ message: "Đăng ký thành công" });
  } catch (err) {
    console.error(err);
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: "Tên đăng nhập đã tồn tại" });
    }
    res.status(500).json({ error: "Lỗi Server" });
  }
});

// 2. ĐĂNG NHẬP
router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Lấy thêm cột kdf_salt
    const [rows] = await db.execute(
      "SELECT id, password_hash, kdf_salt FROM users WHERE username = ?",
      [username]
    );

    if (rows.length === 0) return res.status(401).json({ error: "Sai tài khoản hoặc mật khẩu" });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) return res.status(401).json({ error: "Sai tài khoản hoặc mật khẩu" });

    const token = jwt.sign({ uid: user.id }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.json({
      message: "Đăng nhập thành công",
      token: token,
      salt: user.kdf_salt // <--- QUAN TRỌNG: Trả Salt về cho Client
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Lỗi Server" });
  }
});

module.exports = router;