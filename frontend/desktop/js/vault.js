import { API_URL } from './config.js';
import {
    deriveKeys, encryptData, decryptData, calculateHMAC, base64ToHex,
    generateECDHKeyPair, exportKeyJWK, deriveSharedKey, importKeyJWK
} from './crypto.js';

// ==========================================
// 1. CẤU HÌNH & KHỞI TẠO
// ==========================================
const MY_IP = "192.168.1.118";
const BASE_URL = `https://${MY_IP}:3000`;
const MOBILE_PAGE_URL = `${BASE_URL}/frontend/mobile/mobile.html`;
const socket = io(BASE_URL);

// Biến trạng thái
let token = localStorage.getItem('token');
let unlockToken = null;
let encryptKey = null;
let autoLockTimer = null;
const SESSION_LIMIT_MS = 30000;

// Biến cho QR / Socket
let ecdhKeyPair = null;
let currentSessionId = null;

if (!token) {
    window.location.href = 'login.html';
}

// ==========================================
// 2. LOGIC TẠO QR & KẾT NỐI
// ==========================================
function forceJoinRoom() {
    if (!currentSessionId) return;
    if (socket.connected) {
        socket.emit("desktop_join", currentSessionId);
    } else {
        socket.once("connect", () => {
            socket.emit("desktop_join", currentSessionId);
        });
    }
}

socket.on("connect", forceJoinRoom);

async function initQRCode() {
    try {
        currentSessionId = crypto.randomUUID();
        const fullLink = `${MOBILE_PAGE_URL}#sid=${currentSessionId}`;
        const canvasEl = document.getElementById('qrcode');

        if (!canvasEl) return;

        new QRious({
            element: canvasEl,
            value: fullLink,
            size: 250,
            level: 'L',
            background: 'white',
            foreground: 'black'
        });

        updateStatus("Đang chờ điện thoại quét...", "ok");
        forceJoinRoom();
        console.log("full link: ", fullLink);
    } catch (e) {
        console.error("Lỗi QR:", e);
    }
}

socket.on("notify_mobile_connected", async () => {
    updateStatus("Đang đồng bộ khóa bảo mật...", "ok");
    try {
        if (!ecdhKeyPair) {
            ecdhKeyPair = await generateECDHKeyPair();
        }
        const pubJWK = await exportKeyJWK(ecdhKeyPair.publicKey);
        socket.emit("desktop_send_pubkey", {
            sessionId: currentSessionId,
            pubKey: pubJWK
        });
        updateStatus("Đã gửi Key. Chờ Mobile nhập liệu...", "ok");
    } catch (e) {
        updateStatus("Lỗi: " + e.message, "error");
    }
});

function updateStatus(msg, type) {
    const el = document.getElementById("qrStatus");
    if (el) {
        el.textContent = msg;
        el.className = `status ${type}`;
    }
}

// ==========================================
// 3. XỬ LÝ SỰ KIỆN SOCKET (TỪ MOBILE)
// ==========================================

socket.on("receive_key", async (encryptedPkg) => {
    updateStatus("Đang xác thực...", "ok");
    try {
        const mobilePubKey = await importKeyJWK(encryptedPkg.mobilePub);
        const sharedKey = await deriveSharedKey(ecdhKeyPair.privateKey, mobilePubKey);

        // Giải mã Master Key từ Mobile
        const decryptedMasterKey = await decryptData({
            iv: encryptedPkg.iv,
            ciphertext: encryptedPkg.ciphertext,
            auth_tag: encryptedPkg.auth_tag
        }, sharedKey);

        if (decryptedMasterKey) {
            const success = await performUnlockHandshake(decryptedMasterKey);
            if (success) {
                const salt = localStorage.getItem('salt');
                socket.emit("desktop_send_salt", {
                    sessionId: currentSessionId,
                    salt: salt
                });
                updateStatus("✅ Đã kết nối Mobile!", "ok");
            }
        }
    } catch (e) {
        alert("Lỗi giải mã Key từ Mobile. Vui lòng thử lại.");
        location.reload();
    }
});

socket.on("receive_new_entry", async (entryData) => {
    if (!unlockToken) return;
    try {
        await fetch(`${API_URL}/data`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
                'x-unlock-token': unlockToken
            },
            body: JSON.stringify({
                domain: entryData.domain,
                ciphertext: entryData.ciphertext,
                iv: entryData.iv,
                // 👇 Đảm bảo gửi auth_tag (viết thường) lên Server
                authTag: entryData.auth_tag
            })
        });
        loadData(); // Tải lại bảng để hiển thị ngay
    } catch (e) { console.error(e); }
});

// ==========================================
// 4. LOGIC MỞ KHÓA & QUẢN LÝ PHIÊN
// ==========================================
async function performUnlockHandshake(masterKeyInput) {
    const storedSalt = localStorage.getItem('salt');
    if (!storedSalt) return alert("Lỗi dữ liệu: Không tìm thấy Salt.");

    try {
        const saltHex = base64ToHex(storedSalt);

        const res1 = await fetch(`${API_URL}/masterkey/challenge`, {
            headers: { 'Authorization': `Bearer ${token}` }, method: 'POST'
        });
        const challengeData = await res1.json();

        const keys = await deriveKeys(masterKeyInput, saltHex);
        const signature = await calculateHMAC(keys.authKey, challengeData.nonce);

        const res2 = await fetch(`${API_URL}/masterkey/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ hmac: signature })
        });
        const verifyData = await res2.json();

        if (verifyData.status === "ok") {
            unlockToken = verifyData.unlockToken;
            encryptKey = keys.encryptKey;

            //-----------------------------------------------------------------------------
            // 👇 BÁO MOBILE LÀ ĐÚNG MASTERKEY
            socket.emit("unlock_success", { sessionId: currentSessionId });
            //-----------------------------------------------------------------------------

            // Đồng bộ ID với vault.html (Sử dụng lockScreen và vaultUI)
            const lockEl = document.getElementById('lockScreen');
            const uiEl = document.getElementById('vaultUI');

            if (lockEl) lockEl.classList.add('hidden');
            if (uiEl) uiEl.classList.remove('hidden');

            loadData();
            startSessionTimer();
            return true;
        } else {
            //-----------------------------------------------------------------------------
            socket.emit("unlock_failed", { sessionId: currentSessionId });

            //-----------------------------------------------------------------------------

            alert("Master Key không đúng!");
            // location.reload();
            return false;
        }
    } catch (err) {
        return false;
    }
}

async function lockVault() {
    encryptKey = null;
    const tokenToRevoke = unlockToken;
    unlockToken = null;
    if (autoLockTimer) clearTimeout(autoLockTimer);

    const lockEl = document.getElementById('lockScreen');
    const uiEl = document.getElementById('vaultUI');

    if (uiEl) uiEl.classList.add('hidden');
    if (lockEl) lockEl.classList.remove('hidden');

    const tbody = document.getElementById('passTableBody');
    if (tbody) tbody.innerHTML = '';

    //-------------------------------------------------------------------

    // 🔔 Báo Mobile biết phiên đã hết
    if (currentSessionId) {
        socket.emit("session_expired", {
            sessionId: currentSessionId
        });
    }

    //------------------------------------------------------------------

    if (tokenToRevoke) {
        fetch(`${API_URL}/masterkey/lock`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ unlockToken: tokenToRevoke })
        }).catch(() => { });
    }
    initQRCode();
}

function startSessionTimer() {
    if (autoLockTimer) clearTimeout(autoLockTimer);
    autoLockTimer = setTimeout(lockVault, SESSION_LIMIT_MS);
}

// ==========================================
// 5. HIỂN THỊ DỮ LIỆU (ĐÃ FIX ĐỂ KHỚP VỚI TABLE)
// ==========================================
async function loadData() {
    // 1. Chỉ chạy khi đã có Token và Key giải mã
    if (!unlockToken || !encryptKey) return;

    try {
        const res = await fetch(`${API_URL}/data`, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'x-unlock-token': unlockToken
            }
        });

        if (!res.ok) {
            if (res.status === 403) lockVault();
            return;
        }

        const items = await res.json();
        const tbody = document.getElementById('passTableBody');
        if (!tbody) return;
        tbody.innerHTML = ''; // Xóa trắng dữ liệu cũ để nạp mới

        if (items.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#94a3b8; padding: 20px;">Chưa có dữ liệu. Hãy thêm từ điện thoại.</td></tr>';
            return;
        }

        // 2. Duyệt qua từng mật khẩu nhận được
        for (const [index, item] of items.entries()) {
            try {
                // GIẢI MÃ mật khẩu ngay lập tức bằng Master Key (encryptKey)
                const plainPassword = await decryptData({
                    iv: item.iv,
                    ciphertext: item.ciphertext || item.password,
                    auth_tag: item.auth_tag || item.authTag
                }, encryptKey);

                // Tạo dòng (row) mới cho bảng
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${index + 1}</td>
                    <td><strong>${item.domain}</strong></td>
                    <td>
                        <span class="pass-text" style="font-family: monospace; font-weight: bold; letter-spacing: 2px;">••••••••</span>
                    </td>
                    <td>
                        <div style="display: flex; gap: 8px; justify-content: center;">
                            <button class="btn btn-sm btn-outline btn-copy" title="Copy">📋</button>
                            <button class="btn btn-sm btn-outline btn-toggle" title="Xem/Ẩn">👁️</button>
                            <button class="btn btn-sm btn-delete" style="color:red; border:1px solid #fee2e2;">🗑️</button>
                        </div>
                    </td>
                `;

                // --- XỬ LÝ SỰ KIỆN TRÊN DÒNG ---
                const passSpan = tr.querySelector('.pass-text');
                const btnToggle = tr.querySelector('.btn-toggle');
                let isVisible = false;

                // A. Logic Ẩn/Hiện mật khẩu trực tiếp (Không dùng alert)
                btnToggle.onclick = () => {
                    if (!isVisible) {
                        passSpan.textContent = plainPassword; // Hiển thị pass thật
                        passSpan.style.letterSpacing = "normal";
                        passSpan.style.color = "var(--primary-color)";
                        btnToggle.innerHTML = "🙈"; // Đổi icon thành nhắm mắt
                    } else {
                        passSpan.textContent = "••••••••"; // Ẩn lại
                        passSpan.style.letterSpacing = "2px";
                        passSpan.style.color = "inherit";
                        btnToggle.innerHTML = "👁️";
                    }
                    isVisible = !isVisible;
                    startSessionTimer(); // Reset thời gian tự khóa
                };

                // B. Logic Copy mật khẩu
                tr.querySelector('.btn-copy').onclick = () => {
                    navigator.clipboard.writeText(plainPassword);
                    const btn = tr.querySelector('.btn-copy');
                    btn.innerHTML = "✅";
                    setTimeout(() => { btn.innerHTML = "📋"; }, 1000);
                    startSessionTimer();
                };

                // C. Logic Xóa
                tr.querySelector('.btn-delete').onclick = async () => {
                    if (confirm(`Xóa mật khẩu của "${item.domain}"?`)) {
                        await deleteData(item.id);
                    }
                    startSessionTimer();
                };

                tbody.appendChild(tr);

            } catch (e) {
                console.error("Lỗi dòng:", item.domain, e);
                // Nếu dòng này lỗi (do dữ liệu rác từ điện thoại), hiện thông báo lỗi tại dòng đó
                const trError = document.createElement('tr');
                trError.innerHTML = `
                    <td>${index + 1}</td>
                    <td>${item.domain}</td>
                    <td style="color:red; font-size:0.85rem">⚠️ Lỗi giải mã (Dữ liệu cũ)</td>
                    <td><button class="btn btn-sm btn-delete" onclick="deleteData(${item.id})">🗑️</button></td>
                `;
                tbody.appendChild(trError);
            }
        }
    } catch (e) {
        console.error("Lỗi hệ thống loadData:", e);
    }
}

async function deleteData(id) {
    try {
        const res = await fetch(`${API_URL}/data/${id}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}`, 'x-unlock-token': unlockToken }
        });
        if (res.ok) loadData();
    } catch (e) {
        console.error(e);
    }
}

// Khởi chạy
document.addEventListener("DOMContentLoaded", initQRCode);