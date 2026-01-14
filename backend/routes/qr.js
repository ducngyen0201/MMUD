const { v4: uuidv4 } = require("uuid");

router.post("/qr/init", async (req, res) => {
  const sessionId = uuidv4().replace(/-/g, "");
  const expiresAt = new Date(Date.now() + 60 * 1000);

  await db.execute(
    `INSERT INTO qr_sessions (session_id, expires_at)
     VALUES (?, ?)`,
    [sessionId, expiresAt]
  );

  res.json({ sessionId });
});

const auth = require("../middleware/auth");
const { notify } = require("../ws");

router.post("/qr/approve", auth, async (req, res) => {
  const { sessionId } = req.body;
  const userId = req.user.uid;

  const [rows] = await db.execute(
    `SELECT * FROM qr_sessions
     WHERE session_id = ? AND status = 'PENDING'`,
    [sessionId]
  );

  if (rows.length === 0) {
    return res.status(400).json({ error: "Invalid session" });
  }

  await db.execute(
    `UPDATE qr_sessions
     SET status = 'APPROVED', user_id = ?
     WHERE session_id = ?`,
    [userId, sessionId]
  );

  // push WS event
  notify(sessionId, {
    type: "approved",
    userId
  });

  res.json({ status: "ok" });
});

router.post("/qr/consume", async (req, res) => {
  const { sessionId } = req.body;

  const [rows] = await db.execute(
    `SELECT user_id FROM qr_sessions
     WHERE session_id = ? AND status = 'APPROVED'`,
    [sessionId]
  );

  if (rows.length === 0) {
    return res.status(401).json({ error: "Not approved" });
  }

  const token = require("jsonwebtoken").sign(
    { uid: rows[0].user_id },
    process.env.JWT_SECRET,
    { expiresIn: "15m" }
  );

  res.json({ token });
});