const express = require("express");
const router = express.Router();
const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
const db = require("../db/index");

// --- 1. ĐĂNG KÝ ---
router.post("/register", async (req, res) => {
  // Giữ nguyên tên biến để không phải sửa Frontend
  const { username, passwordHash, authKeyHash, kdfSalt } = req.body;

  if (!username || !passwordHash || !authKeyHash || !kdfSalt) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    // [SỬA 1]: Băm mật khẩu (Login Password) trước khi lưu
    // passwordHash ở đây thực chất là mật khẩu thô từ Frontend gửi lên
    const safePasswordForDb = await argon2.hash(passwordHash);

    // Lưu vào DB
    await db.execute(
      `INSERT INTO users 
       (username, password_hash, auth_key_hash, kdf_salt)
       VALUES (?, ?, ?, ?)`,
      [
        username,
        safePasswordForDb, // Lưu bản đã băm
        authKeyHash,       // Logic Verify Key giữ nguyên
        Buffer.from(kdfSalt, "base64") // Salt giữ nguyên cách lưu
      ]
    );

    res.json({ status: "ok" });

  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ error: "User already exists" });
    }
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// --- 2. ĐĂNG NHẬP ---
router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    // [SỬA 2]: Phải lấy thêm cột `kdf_salt` từ DB
    const [rows] = await db.execute(
      "SELECT id, password_hash, kdf_salt FROM users WHERE username = ?",
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = rows[0];

    // Kiểm tra mật khẩu (Giờ sẽ không bị lỗi 500 nữa vì lúc đăng ký đã hash đúng chuẩn)
    const ok = await argon2.verify(user.password_hash, password);
    if (!ok) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { uid: user.id },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );

    // [SỬA 3]: Trả về Salt cho Frontend (để tính MasterKey)
    // Chuyển Buffer từ DB sang Hex string để gửi qua JSON an toàn
    const saltHex = user.kdf_salt.toString('hex');

    res.json({ 
        status: "ok", 
        token, 
        // Backend trả về salt, Frontend cần cái này để mở Vault
        user: { username, salt: saltHex } 
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;