import { deriveSharedKey, encryptData, importKeyJWK } from '../desktop/js/crypto.js';

// 👇 QUAN TRỌNG: Thay bằng IP máy tính của bạn
const BACKEND_IP = "192.168.1.10"; 
const socket = io(`http://${BACKEND_IP}:3000`);

let masterKeyCache = localStorage.getItem('mobile_master_key'); // Lưu key vào bộ nhớ tạm
const inpKey = document.getElementById('inpMobileKey');

// Tự động điền key nếu đã từng đăng nhập
if (masterKeyCache) {
    inpKey.value = masterKeyCache;
}

// 1. KIỂM TRA XEM CÓ DỮ LIỆU TỪ QR (LINK) KHÔNG?
window.addEventListener('load', async () => {
    // URL sẽ có dạng: mobile.html#data=eyJ...
    const hash = window.location.hash;
    
    if (hash && hash.startsWith('#data=')) {
        // Lấy phần mã hóa sau dấu =
        const base64Data = hash.substring(6); 
        
        try {
            const jsonString = atob(base64Data);
            const qrData = JSON.parse(jsonString);
            
            console.log("Nhận được lệnh từ Desktop:", qrData);
            
            // Nếu Mobile chưa đăng nhập -> Bắt đăng nhập trước
            if (!masterKeyCache) {
                alert("Vui lòng nhập Master Key trên điện thoại trước!");
                document.getElementById('screenLogin').classList.remove('hidden');
                return;
            }

            // Nếu đã có Key -> Hỏi xác thực luôn
            handleApproveSequence(qrData);

        } catch (e) {
            alert("Link QR lỗi: " + e.message);
        }
    } else {
        // Không có link -> Hiện màn hình đăng nhập thường
        document.getElementById('screenLogin').classList.remove('hidden');
    }
});

// 2. NÚT ĐĂNG NHẬP TRÊN MOBILE
document.getElementById('btnLoginMobile').addEventListener('click', () => {
    const key = inpKey.value;
    if (!key) return alert("Nhập Key đi bạn ơi");

    // Lưu lại dùng cho lần sau
    localStorage.setItem('mobile_master_key', key);
    masterKeyCache = key;
    
    // Nếu đang có hash trên URL (nghĩa là vừa quét xong mới đăng nhập) -> Xử lý luôn
    if (window.location.hash.includes('#data=')) {
        window.location.reload(); // Reload để chạy logic ở trên
    } else {
        alert("Đã lưu Key! Giờ hãy dùng Camera thường quét QR trên Desktop.");
    }
});

// 3. XỬ LÝ PHÊ DUYỆT
async function handleApproveSequence(qrData) {
    // Ẩn Login, Hiện thông báo
    document.getElementById('screenLogin').classList.add('hidden');
    document.getElementById('screenScan').classList.remove('hidden'); // Bạn có thể đổi tên div này thành screenApprove
    document.getElementById('scanResult').textContent = `Đang kết nối tới Desktop...`;
    document.getElementById('reader').style.display = 'none'; // Không cần camera nữa
    document.getElementById('btnStopScan').style.display = 'none';

    // Hỏi xác nhận
    const userConfirm = confirm(`Bạn có muốn đăng nhập trên Desktop không?\nSession ID: ${qrData.sid.substring(0,4)}...`);
    
    if (userConfirm) {
        await sendKeyToDesktop(qrData);
    } else {
        window.location.href = window.location.pathname; // Xóa hash
    }
}

// 4. GỬI KEY (Logic cũ, chỉ sửa phần alert)
async function sendKeyToDesktop(qrData) {
    document.getElementById('scanResult').textContent = "Đang mã hóa & gửi...";
    try {
        const desktopPub = await importKeyJWK(qrData.pub);
        const mobileKeyPair = await window.crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]
        );
        const sharedKey = await deriveSharedKey(mobileKeyPair.privateKey, desktopPub);
        const encryptedData = await encryptData(masterKeyCache, sharedKey);
        const mobilePubJWK = await window.crypto.subtle.exportKey("jwk", mobileKeyPair.publicKey);

        const payload = {
            sessionId: qrData.sid,
            encryptedKeyPkg: {
                iv: encryptedData.iv,
                ciphertext: encryptedData.ciphertext,
                auth_tag: encryptedData.auth_tag,
                mobilePub: mobilePubJWK
            }
        };

        socket.emit("mobile_send_key", payload);
        
        document.getElementById('scanResult').innerHTML = `<h3 class="text-success">✅ Thành công!</h3><p>Desktop đã được mở khóa.</p>`;
        
        // Xóa hash để tránh refresh lại bị gửi tiếp
        history.pushState("", document.title, window.location.pathname);

    } catch (err) {
        console.error(err);
        alert("Lỗi gửi dữ liệu: " + err.message);
    }
}