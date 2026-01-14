const form = document.getElementById("registerForm");
const statusEl = document.getElementById("status");

/* ===== CRYPTO HELPERS ===== */

async function deriveKeys(masterKey, salt) {
  const enc = new TextEncoder();

  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(masterKey),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const rootBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: enc.encode(salt),
      iterations: 100000,
      hash: "SHA-256"
    },
    baseKey,
    256
  );

  return {
    authKey: await hkdf(rootBits, "auth"),
    encryptKey: await hkdf(rootBits, "encrypt")
  };
}

async function hkdf(keyBits, info) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBits,
    "HKDF",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array([]),
      info: new TextEncoder().encode(info)
    },
    key,
    256
  );

  return bits;
}

async function sha256(buf) {
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

/* ===== REGISTER FLOW ===== */

form.addEventListener("submit", async (e) => {
  e.preventDefault();

  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  const masterKey = document.getElementById("masterKey").value;

  statusEl.textContent = "⏳ Đang tạo tài khoản...";

  try {
    // 1. Tạo salt cho MasterKey
    const salt = crypto.randomUUID();

    // 2. Derive AuthKey / EncryptKey
    const { authKey, encryptKey } = await deriveKeys(masterKey, salt);

    // 3. Hash AuthKey → gửi server
    const authKeyHash = await sha256(authKey);

    // (EncryptKey KHÔNG gửi, chỉ lưu client khi cần)

    // 4. Gửi dữ liệu lên server
    const res = await fetch("/api/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        password,       // ✅ plaintext
        kdf_salt: salt,
        auth_key_hash: authKeyHash
      })
    });

    if (!res.ok) throw new Error("Register failed");

    statusEl.textContent = "✅ Đăng ký thành công";
    form.reset();

  } catch (err) {
    console.error(err);
    statusEl.textContent = "❌ Đăng ký thất bại";
  }
});
