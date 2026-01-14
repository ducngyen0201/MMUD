const jwt = require("jsonwebtoken");

module.exports = function requireUnlocked(req, res, next) {
  const header = req.headers["x-unlock-token"];
  if (!header) return res.sendStatus(403);

  try {
    const payload = jwt.verify(header, process.env.JWT_SECRET);
    if (!payload.mk) return res.sendStatus(403);

    req.user = { uid: payload.uid };
    next();
  } catch {
    res.sendStatus(403);
  }
};
