/* =====================================================
   VaultChat Mobile Authenticator
   - WebAuthn primary
   - HMAC fallback (MasterKey)
   - Web Crypto API only
   ===================================================== */

/* ========= CONFIG ========= */
const API_BASE = "/api/mobile";

/* ========= DOM ========= */
const sessionEl = document.getElementById("sessionId");
const statusEl = document.getElementById("status");
const approveBtn = document.getElementById("approveBtn");
const webauthnBtn = document.getElementById("webauthnBtn");
const masterKeyInput = document.getElementById("masterKey");

/* ========= STATE ========= */
let sessionId = null;
let nonce = null;

/* ========= UTILS ========= */
function setStatus(msg, type = "") {
    statusEl.textContent = msg;
    statusEl.className = "status " + type;
}

function getSessionFromURL() {
    const params = new URLSearchParams(window.location.search);
    return params.get("session");
}

function bufToBase64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function base64ToBuf(base64) {
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

/* ========= CRYPTO ========= */

/**
 * Derive key from MasterKey using PBKDF2
 */
async function deriveKeyFromMaster(masterKey, salt) {
    const enc = new TextEncoder();

    const baseKey = await crypto.subtle.importKey(
        "raw",
        enc.encode(masterKey),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: enc.encode(salt),
            iterations: 100000,
            hash: "SHA-256"
        },
        baseKey,
        { name: "HMAC", hash: "SHA-256", length: 256 },
        false,
        ["sign"]
    );
}

/**
 * Create HMAC proof
 */
async function createHMAC(masterKey, nonce) {
    const key = await deriveKeyFromMaster(masterKey, sessionId);
    const sig = await crypto.subtle.sign(
        "HMAC",
        key,
        new TextEncoder().encode(nonce)
    );
    return bufToBase64(sig);
}

/* ========= API ========= */

async function fetchNonce() {
    const res = await fetch(`${API_BASE}/nonce?session=${sessionId}`);
    if (!res.ok) throw new Error("Không lấy được nonce");
    const data = await res.json();
    return data.nonce;
}

async function sendApprove(payload) {
    const res = await fetch(`${API_BASE}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });

    if (!res.ok) throw new Error("Approve thất bại");
}

/* ========= WEB AUTHN ========= */

async function webauthnAuth() {
    if (!window.PublicKeyCredential) {
        setStatus("❌ Trình duyệt không hỗ trợ WebAuthn", "error");
        return;
    }

    try {
        setStatus("🔐 Đang xác thực sinh trắc…");

        const challenge = base64ToBuf(nonce);

        const assertion = await navigator.credentials.get({
            publicKey: {
                challenge,
                timeout: 60000,
                userVerification: "required"
            }
        });

        const payload = {
            session: sessionId,
            type: "webauthn",
            credential: {
                id: assertion.id,
                rawId: bufToBase64(assertion.rawId),
                response: {
                    authenticatorData: bufToBase64(assertion.response.authenticatorData),
                    clientDataJSON: bufToBase64(assertion.response.clientDataJSON),
                    signature: bufToBase64(assertion.response.signature)
                }
            }
        };

        await sendApprove(payload);
        setStatus("✅ Đã gửi xác thực WebAuthn", "ok");

    } catch (err) {
        console.error(err);
        setStatus("❌ WebAuthn thất bại", "error");
    }
}

/* ========= HMAC FALLBACK ========= */

async function masterKeyAuth() {
    const masterKey = masterKeyInput.value.trim();

    if (!masterKey) {
        setStatus("⚠️ Vui lòng nhập MasterKey", "error");
        return;
    }

    try {
        setStatus("🔑 Đang tạo HMAC…");

        const proof = await createHMAC(masterKey, nonce);

        const payload = {
            session: sessionId,
            type: "hmac",
            proof
        };

        await sendApprove(payload);

        masterKeyInput.value = ""; // không giữ key
        setStatus("✅ Xác thực thành công", "ok");

    } catch (err) {
        console.error(err);
        setStatus("❌ Xác thực thất bại", "error");
    }
}

/* ========= INIT ========= */

async function init() {
    sessionId = getSessionFromURL();

    if (!sessionId) {
        setStatus("❌ Không có session", "error");
        return;
    }

    sessionEl.textContent = sessionId;

    try {
        nonce = await fetchNonce();
        setStatus("📲 Chờ xác thực từ người dùng");
    } catch (err) {
        console.error(err);
        setStatus("❌ Không lấy được nonce", "error");
    }
}

/* ========= EVENTS ========= */
approveBtn.addEventListener("click", masterKeyAuth);
webauthnBtn.addEventListener("click", webauthnAuth);

/* ========= START ========= */
init();
