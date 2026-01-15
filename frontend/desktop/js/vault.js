import { API_URL } from './config.js';
import { 
    deriveKeys, encryptData, decryptData, calculateHMAC, base64ToHex,
    generateECDHKeyPair, exportKeyJWK, deriveSharedKey, importKeyJWK 
} from './crypto.js';

// ==========================================
// 1. CẤU HÌNH & KHỞI TẠO
// ==========================================
const MY_IP = "192.168.1.128"; 

const BASE_URL = `https://${MY_IP}:3000`; 

const MOBILE_PAGE_URL = `${BASE_URL}/frontend/mobile/mobile.html`;
const socket = io(BASE_URL);

// Biến trạng thái
let token = localStorage.getItem('token'); // Token đăng nhập
let unlockToken = null; // Token phiên làm việc (Session)
let encryptKey = null;  // Key dùng để giải mã dữ liệu hiển thị
let autoLockTimer = null; 
const SESSION_LIMIT_MS = 30000*10; // Tự khóa sau 30s

// Biến cho QR / Socket
let ecdhKeyPair = null;
let currentSessionId = null;

// Kiểm tra login
if (!token) {
    window.location.href = 'login.html';
}

// ==========================================
// 2. LOGIC TẠO QR & KẾT NỐI
// ==========================================
async function initQRCode() {
    try {
        currentSessionId = crypto.randomUUID();
        const fullLink = `${MOBILE_PAGE_URL}#sid=${currentSessionId}`;
        console.log("Link QR:", fullLink);

        // 👇 1. Lấy thẻ canvas
        const canvasEl = document.getElementById('qrcode');
        
        // 👇 2. Kiểm tra xem có tìm thấy thẻ không (Debug)
        if (!canvasEl) {
            console.error("LỖI: Không tìm thấy thẻ <canvas id='qrcode'> trong HTML!");
            alert("Lỗi code: Chưa sửa thẻ div thành canvas trong file html!");
            return;
        }

        // 👇 3. Vẽ QR
        new QRious({
            element: canvasEl,  // Trỏ vào thẻ canvas
            value: fullLink,    // Nội dung
            size: 250,          // Kích thước
            level: 'L',         // Mức nén L (Low) để QR thoáng
            background: 'white',
            foreground: 'black'
        });

        updateStatus("Đang chờ điện thoại quét...", "ok");
        socket.emit("desktop_join", currentSessionId);

    } catch (e) {
        console.error("Lỗi QR:", e);
    }
}

// 👇 MỚI: Khi Server báo "Mobile đã vào", Desktop gửi Public Key ngay
socket.on("notify_mobile_connected", async () => {
    console.log("📱 Phát hiện Mobile! Đang gửi Public Key...");
    updateStatus("Đang đồng bộ khóa bảo mật...", "ok");
    
    const pubJWK = await exportKeyJWK(ecdhKeyPair.publicKey);
    
    socket.emit("desktop_send_pubkey", {
        sessionId: currentSessionId,
        pubKey: pubJWK
    });
});

function updateStatus(msg, type) {
    const el = document.getElementById("qrStatus");
    el.textContent = msg;
    el.className = `status ${type}`;
}

// ==========================================
// 3. XỬ LÝ SỰ KIỆN SOCKET (TỪ MOBILE)
// ==========================================

// A. NHẬN KEY TỪ MOBILE ĐỂ MỞ KHÓA
socket.on("receive_key", async (encryptedPkg) => {
    console.log("📦 Đã nhận gói tin Key từ Mobile!");
    updateStatus("Đang xác thực...", "ok");
    
    try {
        // 1. Tính Shared Key (từ Private Key của Desktop + Public Key của Mobile)
        const mobilePubKey = await importKeyJWK(encryptedPkg.mobilePub);
        const sharedKey = await deriveSharedKey(ecdhKeyPair.privateKey, mobilePubKey);
        
        // 2. Giải mã để lấy Master Key
        const decryptedMasterKey = await decryptData({
            iv: encryptedPkg.iv,
            ciphertext: encryptedPkg.ciphertext,
            auth_tag: encryptedPkg.auth_tag
        }, sharedKey);

        if (decryptedMasterKey) {
            // 3. Thực hiện quy trình mở khóa với Server
            const success = await performUnlockHandshake(decryptedMasterKey);
            
            if (success) {
                // 4. QUAN TRỌNG: Gửi Salt sang Mobile 
                // (Để Mobile dùng Salt này mã hóa dữ liệu thêm mới)
                const salt = localStorage.getItem('salt');
                socket.emit("desktop_send_salt", { 
                    sessionId: currentSessionId, 
                    salt: salt 
                });
                
                updateStatus("✅ Đã kết nối Mobile!", "ok");
            }
        }
    } catch (e) {
        console.error(e);
        alert("Lỗi giải mã Key từ Mobile. Vui lòng thử lại.");
        location.reload();
    }
});

// B. NHẬN DỮ LIỆU MỚI TỪ MOBILE (ĐỂ LƯU)
socket.on("receive_new_entry", async (entryData) => {
    console.log("📥 Nhận dữ liệu thêm mới từ Mobile:", entryData);
    
    // Chỉ lưu được khi Desktop đã mở khóa
    if (!unlockToken) return;

    try {
        // Gọi API lưu vào Database (Dữ liệu đã được Mobile mã hóa rồi)
        const res = await fetch(`${API_URL}/data`, {
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
                authTag: entryData.auth_tag
            })
        });

        if (res.ok) {
            startSessionTimer(); // Reset timer vì có hoạt động mới
            loadData(); // Tải lại danh sách hiển thị
            
            // Thông báo nhỏ (Toast) hoặc Alert
            // alert(`Đã thêm "${entryData.domain}" thành công!`); 
        } else {
            console.error("Lỗi lưu data");
        }
    } catch (e) {
        console.error(e);
    }
});

// ==========================================
// 4. LOGIC MỞ KHÓA & QUẢN LÝ PHIÊN
// ==========================================
async function performUnlockHandshake(masterKeyInput) {
    const storedSalt = localStorage.getItem('salt');
    if (!storedSalt) {
        alert("Lỗi dữ liệu: Không tìm thấy Salt.");
        return false;
    }

    try {
        const saltHex = base64ToHex(storedSalt);
        
        // B1: Xin Challenge từ Server
        const res1 = await fetch(`${API_URL}/masterkey/challenge`, {
             headers: { 'Authorization': `Bearer ${token}` }, method: 'POST'
        });
        const challengeData = await res1.json(); 

        // B2: Tính toán Key và Chữ ký (HMAC)
        const keys = await deriveKeys(masterKeyInput, saltHex);
        const signature = await calculateHMAC(keys.authKey, challengeData.nonce);

        // B3: Gửi Verify
        const res2 = await fetch(`${API_URL}/masterkey/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ hmac: signature })
        });
        const verifyData = await res2.json();

        if (verifyData.status === "ok") {
            // Lưu Token và Key giải mã vào RAM
            unlockToken = verifyData.unlockToken;
            encryptKey = keys.encryptKey;
            
            // Chuyển đổi giao diện: Ẩn Lock Screen -> Hiện Dashboard
            document.getElementById('lockScreen').style.display = 'none';
            document.getElementById('appContent').style.display = 'block';
            
            loadData();
            startSessionTimer();
            return true;
        } else {
            alert("Master Key không đúng!");
            location.reload();
            return false;
        }
    } catch (err) {
        console.error(err);
        return false;
    }
}

async function lockVault() {
    console.log("🔒 Khóa két (Timeout hoặc Logout)");
    
    // Xóa sạch biến nhạy cảm trong RAM
    encryptKey = null;
    const tokenToRevoke = unlockToken;
    unlockToken = null;
    if (autoLockTimer) clearTimeout(autoLockTimer);

    // Reset giao diện về màn hình khóa
    document.getElementById('appContent').style.display = 'none';
    const lockScreen = document.getElementById('lockScreen');
    lockScreen.style.removeProperty('display'); // Để CSS tự xử lý hiển thị

    // Xóa danh sách mật khẩu trên màn hình (Bảo mật)
    document.getElementById('dataList').innerHTML = '';

    // Gọi API hủy Token trên server
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

    // Tạo QR mới cho phiên sau
    initQRCode(); 
}

function startSessionTimer() {
    if (autoLockTimer) clearTimeout(autoLockTimer);
    autoLockTimer = setTimeout(lockVault, SESSION_LIMIT_MS);
}

// ==========================================
// 5. HIỂN THỊ DỮ LIỆU & CÁC NÚT BẤM
// ==========================================
async function loadData() {
    if (!unlockToken || !encryptKey) return;
    try {
        const res = await fetch(`${API_URL}/data`, {
            headers: { 'Authorization': `Bearer ${token}`, 'x-unlock-token': unlockToken }
        });
        
        if (!res.ok) {
            if (res.status === 403) lockVault(); // Hết hạn token
            return;
        }

        const items = await res.json();
        const listEl = document.getElementById('dataList');
        listEl.innerHTML = '';

        if (items.length === 0) {
            listEl.innerHTML = '<li style="justify-content:center; color:#94a3b8;">Chưa có dữ liệu. Hãy thêm từ điện thoại.</li>';
            return;
        }

        // Render từng dòng dữ liệu
        for (const item of items) {
            try {
                // Giải mã mật khẩu để hiển thị (khi cần)
                const plainPassword = await decryptData({
                    iv: item.iv, 
                    ciphertext: item.ciphertext, 
                    auth_tag: item.authTag || item.auth_tag
                }, encryptKey);
                
                // Tạo thẻ li
                const li = document.createElement('li');
                // Sử dụng CSS class đã có để style đẹp
                li.innerHTML = `
                    <div style="flex-grow: 1;">
                        <strong>${item.domain}</strong>
                    </div>
                    
                    <div style="display: flex; gap: 8px;">
                        <button class="secondary btn-copy" title="Copy">
                            <i class="fas fa-copy"></i>
                        </button>
                        
                        <button class="secondary btn-show" title="Xem/Ẩn">
                            <i class="fas fa-eye"></i>
                        </button>
                        
                        <button class="btn-delete" style="background: #ef4444; color: white;" title="Xóa">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                `;

                // --- Gắn sự kiện cho các nút ---

                // 1. Nút Copy
                li.querySelector('.btn-copy').onclick = () => {
                    navigator.clipboard.writeText(plainPassword);
                    // Hiệu ứng visual báo đã copy
                    const btn = li.querySelector('.btn-copy');
                    const originalHTML = btn.innerHTML;
                    btn.innerHTML = '<i class="fas fa-check"></i>';
                    setTimeout(() => btn.innerHTML = originalHTML, 1000);
                    startSessionTimer(); // Reset timer vì người dùng đang tương tác
                };

                // 2. Nút Hiện/Ẩn (Toggle)
                const btnShow = li.querySelector('.btn-show');
                let isShown = false;
                
                // Tạo một thẻ span chứa password (mặc định ẩn hoặc hiển thị sao ***)
                // Nhưng để đơn giản, ta alert hoặc đổi text domain (tùy ý). 
                // Ở đây tôi dùng Alert cho bảo mật (tránh người khác nhìn trộm màn hình)
                btnShow.onclick = () => {
                   if (!isShown) {
                       // Hiện password
                       btnShow.innerHTML = '<i class="fas fa-eye-slash"></i>';
                       btnShow.style.color = '#ef4444';
                       // Cách hiển thị: Thay thế text domain tạm thời hoặc Alert
                       alert(`Mật khẩu của [${item.domain}]:\n\n${plainPassword}`);
                   } else {
                       btnShow.innerHTML = '<i class="fas fa-eye"></i>';
                       btnShow.style.color = '';
                   }
                   isShown = !isShown;
                   startSessionTimer();
                };

                // 3. Nút Xóa
                li.querySelector('.btn-delete').onclick = async () => {
                    if (confirm(`Bạn có chắc muốn xóa mật khẩu của "${item.domain}"?`)) {
                        await deleteData(item.id);
                    }
                    startSessionTimer();
                };

                listEl.appendChild(li);

            } catch (e) { 
                console.error("Decrypt fail", e); 
            }
        }
    } catch (e) { 
        console.error(e); 
    }
}

// Hàm Xóa Dữ Liệu
async function deleteData(id) {
    try {
        const res = await fetch(`${API_URL}/data/${id}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}`, 'x-unlock-token': unlockToken }
        });
        if (res.ok) {
            loadData(); // Tải lại danh sách sau khi xóa
        } else {
            alert("Lỗi khi xóa!");
        }
    } catch (e) {
        console.error(e);
    }
}

// ==========================================
// 6. SỰ KIỆN LOGOUT
// ==========================================
document.getElementById('btnLogout').addEventListener('click', () => {
    localStorage.removeItem('token'); // Giữ lại Salt, chỉ xóa Token
    window.location.href = 'login.html';
});

// Chạy lần đầu khi tải trang
initQRCode();