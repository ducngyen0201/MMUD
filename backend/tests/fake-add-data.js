const crypto = require("crypto");
const fetch = require("node-fetch").default;

function encrypt(plaintext, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final()
  ]);

  return {
    ciphertext: encrypted.toString("base64"),
    iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64")
  };
}

async function addData() {
  const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjEsImlhdCI6MTc2ODM3ODI1NywiZXhwIjoxNzY4Mzc5MTU3fQ.uqWrPsFPVXE9nnPnUcUBBK4RbKi4vM5P3e4n5tAzOdU";
  const unlockToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjEsIm1rIjp0cnVlLCJpYXQiOjE3NjgzNzg2NzUsImV4cCI6MTc2ODQwODY3NX0.tauhtZ4ZBfT2q1yvT3BamZJJTRAfyT3egD_qbFHf_GA";
  const masterKey = "my-super-master-key";
  const salt = Buffer.from("0x0557930B0AAF041CFCB79678A0F9653356E61CA282CA050B1CFB6EA8AB3A1789", "base64");

  const encryptKey = crypto.hkdfSync(
    "sha256",
    Buffer.from(masterKey),
    salt,
    Buffer.from("encrypt"),
    32
  );

  const payload = encrypt("anh hoàng đẹp trai", encryptKey);

  const res = await fetch("http://localhost:3000/api/data", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${jwt}`,
      "X-Unlock-Token": unlockToken
    },
    body: JSON.stringify(payload)
  });

  console.log(await res.json());
}

addData();
