const crypto = require("crypto");

function deriveEncryptKey(masterKey, salt) {
  return crypto.scryptSync(masterKey, salt, 32);
}

module.exports = { deriveEncryptKey };
