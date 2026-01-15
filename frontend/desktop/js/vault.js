import { API_URL } from './config.js';
import { 
    deriveKeys, encryptData, decryptData, calculateHMAC, base64ToHex,
    generateECDHKeyPair, exportKeyJWK, deriveSharedKey, importKeyJWK 
} from './crypto.js';

const MY_IP = "192.168.1.128"; 
const FRONTEND_URL = `http://${MY_IP}:3000/frontend/mobile/mobile.html`;
// ==========================================
// 1. KHAI BÁO BIẾN & SOCKET
// ==========================================
const socket = io("http://localhost:3000"); // Kết nối Socket server

let token = localStorage.getItem('token');
let unlockToken = null; 
let encryptKey = null;  
let autoLockTimer = null; 
const SESSION_LIMIT_MS = 30000; // 30 giây cứng

// Biến cho tính năng QR/Mobile Sync
let ecdhKeyPair = null;
let currentSessionId = null;

// Kiểm tra login
if (!token) {
    window.location.href = 'login.html';
}

// ==========================================
// 2. LOGIC TẠO QR CODE (ĐÃ SỬA LỖI TRÀN DỮ LIỆU)
// ==========================================
async function initQRCode() {
    try {
        currentSessionId = crypto.randomUUID();
        ecdhKeyPair = await generateECDHKeyPair();
        const publicKeyJWK = await exportKeyJWK(ecdhKeyPair.publicKey);

        // Đóng gói dữ liệu
        const rawData = JSON.stringify({
            sid: currentSessionId,
            pub: publicKeyJWK
        });

        // 👇 MÃ HÓA DỮ LIỆU THÀNH URL (Base64) ĐỂ GẮN VÀO LINK
        // Kết quả sẽ là: http://192.168.1.10:5500/mobile.html#data=eyJzaW...
        const encodedData = btoa(rawData);
        const qrLink = `${FRONTEND_URL}#data=${encodedData}`;

        console.log("QR Link:", qrLink); // Debug

        const qrContainer = document.getElementById("qrcode");
        qrContainer.innerHTML = ""; 

        new QRCode(qrContainer, {
            text: qrLink, // <--- QR bây giờ là Link
            width: 250,   // Tăng to lên cho dễ quét
            height: 250,
            colorDark : "#000000",
            colorLight : "#ffffff",
            correctLevel : QRCode.CorrectLevel.L
        });

        document.getElementById("qrStatus").textContent = "Quét bằng Camera thường để mở";
        
        socket.emit("desktop_join", currentSessionId);

    } catch (e) {
        console.error("Lỗi tạo QR:", e);
    }
}

// ==========================================
// 3. LOGIC NHẬN KEY TỪ MOBILE (SOCKET)
// ==========================================
socket.on("receive_key", async (encryptedPkg) => {
    console.log("📦 Đã nhận gói hàng từ Mobile!");
    document.getElementById("qrStatus").textContent = "Đang giải mã & đăng nhập...";
    document.getElementById("qrStatus").className = "text-success small fw-bold";

    try {
        // encryptedPkg gồm: { iv, ciphertext, auth_tag, mobilePub }
        
        // 1. Lấy Public Key của Mobile
        const mobilePubKey = await importKeyJWK(encryptedPkg.mobilePub);
        
        // 2. Tính ra Shared Secret (Khóa chung)
        const sharedKey = await deriveSharedKey(ecdhKeyPair.privateKey, mobilePubKey);

        // 3. Giải mã gói hàng để lấy MasterKey
        const decryptedMasterKey = await decryptData({
            iv: encryptedPkg.iv,
            ciphertext: encryptedPkg.ciphertext,
            auth_tag: encryptedPkg.auth_tag
        }, sharedKey);

        if (decryptedMasterKey) {
            console.log("✅ Mobile Sync thành công!");
            
            // Tự động điền và mở khóa
            document.getElementById('inpMasterKey').value = decryptedMasterKey;
            performUnlockHandshake(decryptedMasterKey);
        } else {
            alert("Giải mã thất bại (Sai key hoặc tấn công mạng).");
        }
    } catch (e) {
        console.error("Lỗi Mobile Sync:", e);
        alert("Có lỗi khi đồng bộ từ điện thoại.");
    }
});

// ==========================================
// 4. LOGIC KHÓA & ĐẾM NGƯỢC
// ==========================================
async function lockVault() {
    console.log("🔒 [TIMEOUT] Khóa két..."); 

    encryptKey = null;
    const tokenToRevoke = unlockToken;
    unlockToken = null;

    if (autoLockTimer) clearTimeout(autoLockTimer);
    autoLockTimer = null;

    document.getElementById('dataList').innerHTML = '';
    document.getElementById('inpMasterKey').value = ''; 
    document.getElementById('appContent').style.display = 'none';
    document.getElementById('lockScreen').style.display = 'flex';

    // Khi bị khóa -> Tạo lại QR mới để sẵn sàng quét tiếp
    initQRCode(); 

    if (tokenToRevoke) {
        fetch(`${API_URL}/masterkey/lock`, { 
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ unlockToken: tokenToRevoke })
        }).catch(() => {});
    }
}

function startSessionTimer() {
    if (autoLockTimer) clearTimeout(autoLockTimer);
    console.log("⏳ Bắt đầu đếm ngược 30s...");
    autoLockTimer = setTimeout(lockVault, SESSION_LIMIT_MS);
}

// ==========================================
// 5. LOGIC ZERO-KNOWLEDGE HANDSHAKE
// ==========================================
async function performUnlockHandshake(masterKeyInput) {
    const storedSalt = localStorage.getItem('salt');
    if (!storedSalt) return alert("Lỗi Salt. Hãy đăng nhập lại.");

    try {
        const saltHex = base64ToHex(storedSalt);
        
        // Xin Challenge
        const res1 = await fetch(`${API_URL}/masterkey/challenge`, {
             headers: { 'Authorization': `Bearer ${token}` }, method: 'POST'
        });
        if (!res1.ok) throw new Error("Lỗi API Challenge");
        const challengeData = await res1.json(); 

        // Tính Key & Ký
        const keys = await deriveKeys(masterKeyInput, saltHex);
        const signature = await calculateHMAC(keys.authKey, challengeData.nonce);

        // Verify
        const res2 = await fetch(`${API_URL}/masterkey/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ hmac: signature })
        });
        const verifyData = await res2.json();

        if (verifyData.status === "ok") {
            unlockToken = verifyData.unlockToken;
            encryptKey = keys.encryptKey;
            
            // UI Update
            document.getElementById('lockScreen').style.display = 'none';
            document.getElementById('appContent').style.display = 'block';
            
            // Load Data & Start Timer
            loadData();
            startSessionTimer();
            return true;
        } else {
            alert("Mở khóa thất bại: " + verifyData.error);
            return false;
        }
    } catch (err) {
        console.error(err);
        alert("Lỗi xác thực.");
        return false;
    }
}

// ==========================================
// 6. UI EVENTS & LOAD DATA
// ==========================================
document.getElementById('btnUnlock').addEventListener('click', async () => {
    const mk = document.getElementById('inpMasterKey').value;
    if (mk) performUnlockHandshake(mk);
});

async function loadData() {
    if (!unlockToken || !encryptKey) return;
    try {
        const res = await fetch(`${API_URL}/data`, {
            headers: { 'Authorization': `Bearer ${token}`, 'x-unlock-token': unlockToken }
        });
        if (!res.ok) {
            if (res.status === 403) lockVault();
            return;
        }
        const items = await res.json();
        const listEl = document.getElementById('dataList');
        listEl.innerHTML = '';

        for (const item of items) {
            try {
                const plain = await decryptData({
                    iv: item.iv, ciphertext: item.ciphertext, auth_tag: item.authTag || item.auth_tag
                }, encryptKey);
                
                const li = document.createElement('li');
                li.className = "list-group-item d-flex justify-content-between align-items-center";
                li.innerHTML = `
                    <div><strong class="text-primary">${item.domain}</strong></div>
                    <button class="btn btn-sm btn-outline-secondary btn-show">Hiện</button>
                `;
                li.querySelector('.btn-show').onclick = function() {
                    if (this.textContent === 'Hiện') {
                        this.textContent = plain;
                        this.classList.remove('btn-outline-secondary');
                        this.classList.add('btn-outline-danger');
                    } else {
                        this.textContent = 'Hiện';
                        this.classList.add('btn-outline-secondary');
                        this.classList.remove('btn-outline-danger');
                    }
                };
                listEl.appendChild(li);
            } catch (e) { console.error("Decrypt fail", e); }
        }
    } catch (e) { console.error(e); }
}

document.getElementById('btnAdd').addEventListener('click', async () => {
    const domain = document.getElementById('inpDomain').value;
    const pass = document.getElementById('newData').value;
    if (!domain || !pass || !encryptKey) return;

    const enc = await encryptData(pass, encryptKey);
    await fetch(`${API_URL}/data`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}`, 'x-unlock-token': unlockToken },
        body: JSON.stringify({ domain, ciphertext: enc.ciphertext, iv: enc.iv, authTag: enc.auth_tag })
    });
    document.getElementById('inpDomain').value = '';
    document.getElementById('newData').value = '';
    loadData();
});

document.getElementById('btnLogout').addEventListener('click', () => {
    localStorage.clear();
    window.location.href = 'login.html';
});

// KHỞI TẠO QR KHI TRANG LOAD (NẾU ĐANG KHÓA)
if (!encryptKey) {
    initQRCode();
}