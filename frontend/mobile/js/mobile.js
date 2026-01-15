import { deriveSharedKey, encryptData, importKeyJWK, deriveKeys, base64ToHex } from '../../desktop/js/crypto.js';

// Vì bạn dùng cáp USB giả lập, ta dùng localhost
const SOCKET_URL = "https://192.168.1.128:3000"; 
const socket = io(SOCKET_URL);

// Các biến trạng thái
let activeSessionId = null;   // ID phòng (lấy từ QR)
let desktopPubKey = null;     // Khóa công khai của Desktop (nhận qua Socket)
let mobileEncryptKey = null;  // Khóa dùng để mã hóa dữ liệu (tính từ Salt)
let tempMasterKey = null;     // Lưu tạm Master Key để chờ Salt

// ==========================================
// 1. TỰ ĐỘNG CHẠY KHI TRANG WEB VỪA MỞ
// ==========================================
window.onload = () => {
    if (window.location.hash.includes("#sid=")) {
        activeSessionId = window.location.hash.split("#sid=")[1];
        history.replaceState(null, null, ' '); 

        // Cập nhật giao diện chờ
        document.getElementById('btnLoginMobile').innerText = "Đang chờ Desktop...";
        document.getElementById('btnLoginMobile').disabled = true;
        
        // 👇 QUAN TRỌNG: Nếu socket đã nối rồi thì gửi luôn, chưa thì đợi
        if (socket.connected) {
            socket.emit("mobile_joined", activeSessionId);
        }
    }
};

// 👇 SỰ KIỆN KHI SOCKET KẾT NỐI THÀNH CÔNG
socket.on("connect", () => {
    // Nếu đã có ID phiên thì gửi báo danh ngay
    if (activeSessionId) {
        socket.emit("mobile_joined", activeSessionId);
    }
});

// ==========================================
// 2. LẮNG NGHE SỰ KIỆN TỪ SOCKET
// ==========================================

// A. Nhận Public Key từ Desktop (Ngay sau khi báo danh)
socket.on("receive_desktop_pub", (key) => {
    desktopPubKey = key;
    
    // Mở khóa nút bấm
    const btn = document.getElementById('btnLoginMobile');
    btn.innerText = "KẾT NỐI NGAY";
    btn.className = "btn btn-success w-100 fw-bold";
    btn.disabled = false;
});

// B. Nhận Salt từ Desktop (Sau khi gửi Master Key thành công)
socket.on("receive_salt", async (data) => {
    const saltRaw = data.salt || data;
    console.log("📥 Đã nhận Salt từ Desktop:", saltRaw);

    if (tempMasterKey) {
        try {
            // 👇 QUAN TRỌNG: Chuyển Salt sang Hex trước khi tạo Key
            // Điều này đảm bảo Key trên Mobile khớp 100% với Desktop
            const saltHex = base64ToHex(saltRaw);
            
            const keys = await deriveKeys(tempMasterKey, saltHex);
            mobileEncryptKey = keys.encryptKey;
            
            console.log("✅ Đã tạo mobileEncryptKey thành công!");
            tempMasterKey = null; 

            // Mở khóa nút bấm
            const btn = document.getElementById('btnMobileAdd');
            if (btn) {
                btn.disabled = false;
                btn.innerText = "Lưu Mật Khẩu";
            }
        } catch (e) {
            console.error("Lỗi tạo khóa:", e);
        }
    }
});

// ==========================================
// 3. XỬ LÝ NÚT BẤM "KẾT NỐI" (GỬI KEY)
// ==========================================
document.getElementById('btnLoginMobile').addEventListener('click', async () => {
    const masterKey = document.getElementById('inpMobileKey').value;
    
    // Validate
    if (!masterKey) return alert("Vui lòng nhập Master Key!");
    if (!activeSessionId) return alert("Lỗi phiên làm việc. Hãy quét lại QR.");
    if (!desktopPubKey) return alert("Chưa kết nối được với Desktop (Thiếu PubKey).");

    try {
        // 1. Tạo cặp khóa ECDH tạm thời cho Mobile
        const mobileKeyPair = await window.crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]
        );
        
        // 2. Tính Shared Key (Khóa bí mật chung)
        const desktopKeyObj = await importKeyJWK(desktopPubKey);
        const sharedKey = await deriveSharedKey(mobileKeyPair.privateKey, desktopKeyObj);
        
        // 3. Mã hóa Master Key bằng Shared Key
        const encryptedData = await encryptData(masterKey, sharedKey);
        
        // 4. Xuất Public Key của Mobile để gửi đi
        const mobilePubJWK = await window.crypto.subtle.exportKey("jwk", mobileKeyPair.publicKey);
        
        // 5. Gửi gói tin sang Desktop
        socket.emit("mobile_send_key", {
            sessionId: activeSessionId,
            encryptedKeyPkg: {
                iv: encryptedData.iv,
                ciphertext: encryptedData.ciphertext,
                auth_tag: encryptedData.auth_tag,
                mobilePub: mobilePubJWK
            }
        });

        // 6. Lưu tạm Master Key (để lát nữa nhận Salt thì dùng)
        tempMasterKey = masterKey;

        // 7. Chuyển màn hình
        document.getElementById('screenLogin').classList.add('hidden');
        document.getElementById('screenControl').classList.remove('hidden');

    } catch (e) {
        console.error(e);
        alert("Lỗi kết nối: " + e.message);
    }
});

// ==========================================
// 4. XỬ LÝ NÚT "THÊM DỮ LIỆU"
// ==========================================
document.getElementById('btnMobileAdd').addEventListener('click', async () => {
    // Kiểm tra xem đã có Key mã hóa chưa
    if (!mobileEncryptKey) {
        return alert("Chưa nhận được dữ liệu bảo mật (Salt) từ Desktop. Vui lòng đợi 1-2 giây.");
    }

    const domain = document.getElementById('mDomain').value;
    const pass = document.getElementById('mPass').value;

    if (!domain || !pass) return alert("Vui lòng nhập đủ thông tin!");

    try {
        // 1. Mã hóa mật khẩu (Client-side Encryption)
        const encryptedData = await encryptData(pass, mobileEncryptKey);

        // 2. Gửi sang Desktop (Desktop chỉ việc lưu, không đọc được)
        socket.emit("mobile_add_entry", {
            sessionId: activeSessionId,
            entryData: {
                domain: domain,
                ciphertext: encryptedData.ciphertext,
                iv: encryptedData.iv,
                auth_tag: encryptedData.auth_tag
            }
        });

        // 3. Reset Form
        alert("Đã gửi sang Desktop!");
        document.getElementById('mDomain').value = '';
        document.getElementById('mPass').value = '';
        document.getElementById('mDomain').focus();

    } catch (e) {
        console.error(e);
        alert("Lỗi mã hóa: " + e.message);
    }
});
