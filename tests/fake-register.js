const crypto = require("crypto");
const argon2 = require("argon2");
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

async function register() {
  const username = "alice";
  const password = "password123";
  const masterKey = "my-super-master-key";

  // 1️⃣ hash password
  const passwordHash = await argon2.hash(password);

  // 2️⃣ sinh salt
  const salt = crypto.randomBytes(32);

  // 3️⃣ derive authKey
  const authKey = hkdf(masterKey, salt, "auth");

  // 4️⃣ hash authKey
  const authKeyHash = await argon2.hash(authKey);

  // 5️⃣ gửi backend
  const res = await fetch("http://localhost:3000/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username,
      passwordHash,
      authKeyHash,
      kdfSalt: salt.toString("base64")
    })
  });

  console.log(await res.json());
}

register();
