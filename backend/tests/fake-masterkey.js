const crypto = require("crypto");
const fetch = require("node-fetch").default;

function hkdf(masterKey, salt, info) {
  return crypto.hkdfSync(
    "sha256",
    Buffer.from(masterKey),
    salt,
    Buffer.from(info),
    32
  );
}

async function verifyMasterKey() {
  const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjEsImlhdCI6MTc2ODM3ODI1NywiZXhwIjoxNzY4Mzc5MTU3fQ.uqWrPsFPVXE9nnPnUcUBBK4RbKi4vM5P3e4n5tAzOdU";
  const masterKey = "my-super-master-key";

  // 1️⃣ xin nonce
  const r1 = await fetch("http://localhost:3000/api/masterkey/challenge", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` }
  });

  const { nonce } = await r1.json();

  // 2️⃣ derive EncryptKey (salt lấy từ DB)
  const salt = Buffer.from("0x0557930B0AAF041CFCB79678A0F9653356E61CA282CA050B1CFB6EA8AB3A1789", "base64");
  const encryptKey = hkdf(masterKey, salt, "encrypt");

  // 3️⃣ tạo HMAC
  const hmac = crypto
    .createHmac("sha256", encryptKey)
    .update(Buffer.from(nonce, "base64"))
    .digest("base64");

  // 4️⃣ gửi verify
  const r2 = await fetch("http://localhost:3000/api/masterkey/verify", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`
    },
    body: JSON.stringify({ hmac })
  });

  console.log(await r2.json());
}

verifyMasterKey();
