const express = require("express");
const router = express.Router();
const db = require("../db");
const auth = require("../middleware/auth");
const unlocked = require("../middleware/unlock");

router.post("/data", auth, unlocked, async (req, res) => {
  const { ciphertext, iv, authTag } = req.body;

  if (!ciphertext || !iv || !authTag) {
    return res.status(400).json({ error: "Missing fields" });
  }

  await db.execute(
    `INSERT INTO encrypted_data (user_id, ciphertext, iv, auth_tag)
     VALUES (?, ?, ?, ?)`,
    [
      req.user.uid,
      Buffer.from(ciphertext, "base64"),
      Buffer.from(iv, "base64"),
      Buffer.from(authTag, "base64")
    ]
  );

  res.json({ status: "ok" });
});

router.get("/data", auth, unlocked, async (req, res) => {
  const [rows] = await db.execute(
    `SELECT id, ciphertext, iv, auth_tag
     FROM encrypted_data
     WHERE user_id = ?`,
    [req.user.uid]
  );

  res.json(rows.map(r => ({
    id: r.id,
    ciphertext: r.ciphertext.toString("base64"),
    iv: r.iv.toString("base64"),
    authTag: r.auth_tag.toString("base64")
  })));
});

router.put("/data/:id", auth, unlocked, async (req, res) => {
  const { id } = req.params;
  const { ciphertext, iv, authTag } = req.body;

  if (!ciphertext || !iv || !authTag) {
    return res.status(400).json({ error: "Missing fields" });
  }

  // chỉ update data thuộc user
  const [result] = await db.execute(
    `UPDATE encrypted_data
     SET ciphertext = ?, iv = ?, auth_tag = ?
     WHERE id = ? AND user_id = ?`,
    [
      Buffer.from(ciphertext, "base64"),
      Buffer.from(iv, "base64"),
      Buffer.from(authTag, "base64"),
      id,
      req.user.uid
    ]
  );

  if (result.affectedRows === 0) {
    return res.status(404).json({ error: "Data not found" });
  }

  res.json({ status: "updated" });
});

router.delete("/data/:id", auth, unlocked, async (req, res) => {
  const { id } = req.params;

  const [result] = await db.execute(
    `DELETE FROM encrypted_data
     WHERE id = ? AND user_id = ?`,
    [id, req.user.uid]
  );

  if (result.affectedRows === 0) {
    return res.status(404).json({ error: "Data not found" });
  }

  res.json({ status: "deleted" });
});

module.exports = router;
