const crypto = require("crypto");

function hmac(key, data) {
  return crypto.createHmac("sha256", key).update(data).digest();
}

module.exports = { hmac };
