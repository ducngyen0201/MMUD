const express = require("express");
const router = express.Router();
const db = require("../db");
const auth = require("../middleware/auth");

// --- 1. LẤY DỮ LIỆU (GET /) ---
router.get("/", auth, async (req, res) => {
  try {
    // Chỉ lấy dữ liệu của user đang đăng nhập (req.user.uid)
    const [rows] = await db.execute(
      `SELECT id, domain, password, iv, auth_tag
       FROM encrypted_data
       WHERE user_id = ?
       ORDER BY id DESC`, 
      [req.user.uid]
    );

    // Chuyển đổi Buffer (Binary) sang Hex để gửi về Frontend
    const data = rows.map(r => ({
      id: r.id,
      domain: r.domain,
      // Frontend cần 'ciphertext', DB lưu cột 'password'
      ciphertext: r.password.toString("hex"), 
      iv: r.iv.toString("hex"),
      auth_tag: r.auth_tag.toString("hex")
    }));

    res.json(data);
  } catch (err) {
    console.error("Lỗi GET Data:", err);
    res.status(500).json({ error: "Lỗi Database" });
  }
});

// --- 2. THÊM DỮ LIỆU (POST /) ---
router.post("/", auth, async (req, res) => {
  const { domain, ciphertext, iv, authTag } = req.body; // Frontend gửi authTag hoặc auth_tag đều xử lý được

  // Xử lý biến thể tên trường (authTag vs auth_tag)
  const tag = authTag || req.body.auth_tag;

  if (!domain || !ciphertext || !iv || !tag) {
    return res.status(400).json({ error: "Thiếu dữ liệu (domain/ciphertext/iv/tag)" });
  }

  try {
    await db.execute(
      `INSERT INTO encrypted_data (user_id, domain, password, iv, auth_tag)
       VALUES (?, ?, ?, ?, ?)`,
      [
        req.user.uid,
        domain,
        Buffer.from(ciphertext, "hex"),
        Buffer.from(iv, "hex"),
        Buffer.from(tag, "hex")
      ]
    );
    res.json({ status: "ok", message: "Đã lưu thành công" });
  } catch (err) {
    console.error("Lỗi POST Data:", err);
    res.status(500).json({ error: err.message });
  }
});

// --- 3. XÓA DỮ LIỆU (DELETE /:id) ---
router.delete("/:id", auth, async (req, res) => {
  const { id } = req.params;
  try {
    // Phải có user_id để đảm bảo không xóa nhầm của người khác
    const [result] = await db.execute(
      `DELETE FROM encrypted_data WHERE id = ? AND user_id = ?`,
      [id, req.user.uid]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Không tìm thấy dữ liệu hoặc không có quyền xóa" });
    }

    res.json({ status: "deleted" });
  } catch (err) {
    console.error("Lỗi DELETE:", err);
    res.status(500).json({ error: "Lỗi Server" });
  }
});

module.exports = router;