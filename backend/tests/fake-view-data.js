const crypto = require("crypto");
const fetch = require("node-fetch").default;

function decrypt(ciphertext, iv, authTag, key) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(iv, "base64")
  );

  decipher.setAuthTag(Buffer.from(authTag, "base64"));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertext, "base64")),
    decipher.final()
  ]);

  return decrypted.toString("utf8");
}

async function viewData() {
  const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjEsImlhdCI6MTc2ODM3ODI1NywiZXhwIjoxNzY4Mzc5MTU3fQ.uqWrPsFPVXE9nnPnUcUBBK4RbKi4vM5P3e4n5tAzOdU";
  const unlockToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjEsIm1rIjp0cnVlLCJpYXQiOjE3NjgzNzg2NzUsImV4cCI6MTc2ODQwODY3NX0.tauhtZ4ZBfT2q1yvT3BamZJJTRAfyT3egD_qbFHf_GA";
  const masterKey = "my-super-master-key";
  const salt = Buffer.from("0x0557930B0AAF041CFCB79678A0F9653356E61CA282CA050B1CFB6EA8AB3A1789", "base64");

  // derive EncryptKey
  const encryptKey = crypto.hkdfSync(
    "sha256",
    Buffer.from(masterKey),
    salt,
    Buffer.from("encrypt"),
    32
  );

  // gọi backend
  const res = await fetch("http://localhost:3000/api/data", {
    headers: {
      Authorization: `Bearer ${jwt}`,
      "X-Unlock-Token": unlockToken
    }
  });

  const data = await res.json();

  // decrypt từng record
  data.forEach(item => {
    const plain = decrypt(
      item.ciphertext,
      item.iv,
      item.authTag,
      encryptKey
    );
    console.log("🔓", plain);
  });
}

viewData();
