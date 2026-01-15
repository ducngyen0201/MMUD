const express = require("express");
const router = express.Router();
const db = require("../db"); // Lưu ý: check đường dẫn db cho đúng
const auth = require("../middleware/auth");
const unlocked = require("../middleware/unlock"); // Vẫn import nhưng chưa dùng ở route

// --- 1. THÊM DỮ LIỆU (POST) ---
router.post("/", auth, async (req, res) => {
  // Frontend gửi lên: domain, ciphertext (là password đã mã hóa), iv, authTag
  const { domain, ciphertext, iv, authTag } = req.body;

  if (!domain || !ciphertext || !iv || !authTag) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    await db.execute(
      `INSERT INTO encrypted_data (user_id, domain, password, iv, auth_tag)
       VALUES (?, ?, ?, ?, ?)`,
      [
        req.user.uid,
        domain,                         // Lưu domain dạng text
        Buffer.from(ciphertext, "hex"), // Lưu password đã mã hóa
        Buffer.from(iv, "hex"),
        Buffer.from(authTag, "hex")
      ]
    );
    res.json({ status: "ok" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// 2. LẤY DỮ LIỆU
router.get("/", auth, async (req, res) => {
  try {
    const [rows] = await db.execute(
      `SELECT id, domain, password, iv, auth_tag
       FROM encrypted_data
       WHERE user_id = ?
       ORDER BY id DESC`, // Sắp xếp mới nhất lên đầu
      [req.user.uid]
    );

    res.json(rows.map(r => ({
      id: r.id,
      domain: r.domain, // Trả về domain
      ciphertext: r.password.toString("hex"), // Cột password trong DB chính là ciphertext
      iv: r.iv.toString("hex"),
      authTag: r.auth_tag.toString("hex")
    })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

// --- 3. SỬA DỮ LIỆU (PUT) ---
router.put("/:id", auth, async (req, res) => {
  const { id } = req.params;
  const { domain, ciphertext, iv, authTag } = req.body;

  if (!domain || !ciphertext || !iv || !authTag) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    const [result] = await db.execute(
      `UPDATE encrypted_data
       SET domain = ?, ciphertext = ?, iv = ?, auth_tag = ?
       WHERE id = ? AND user_id = ?`,
      [
        // 👇 SỬA Ở ĐÂY: Đổi "base64" -> "hex"
        Buffer.from(domain, "hex"),
        Buffer.from(ciphertext, "hex"),
        Buffer.from(iv, "hex"),
        Buffer.from(authTag, "hex"),
        id,
        req.user.uid
      ]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Data not found" });
    }

    res.json({ status: "updated" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// --- 4. XÓA DỮ LIỆU (DELETE) ---
router.delete("/:id", auth, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await db.execute(
      `DELETE FROM encrypted_data
       WHERE id = ? AND user_id = ?`,
      [id, req.user.uid]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Data not found" });
    }

    res.json({ status: "deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;