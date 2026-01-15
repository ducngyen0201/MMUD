import { API_URL } from './config.js';
import { deriveKeys, encryptData, decryptData } from './crypto.js';

let encryptKey = null; // Key giải mã (RAM)
let timeoutParams = null;
let unlockToken = null; // Token mở két từ Server

// 1. Kiểm tra đăng nhập
const token = localStorage.getItem('token');
const salt = localStorage.getItem('salt');

if (!token || !salt) {
    window.location.href = 'login.html';
}

// ---------------------------------------------------------
// 2. Logic Mở Khóa (Handshake với Server + Tính Key Client)
// ---------------------------------------------------------
document.getElementById('btnUnlock').addEventListener('click', async () => {
    const masterKeyInput = document.getElementById('inpMasterKey').value;
    if (!masterKeyInput) return alert('Vui lòng nhập Master Key');

    try {
        // Bước A: Tính toán Key giải mã ở Client
        const keys = await deriveKeys(masterKeyInput, salt);
        
        // Bước B: Xin "Vé mở két" từ Server (Challenge-Response)
        const serverUnlocked = await performUnlockHandshake();
        
        if (!serverUnlocked) {
            alert("Lỗi: Server không cấp quyền mở khóa (Kiểm tra DB masterkey_nonce)");
            return;
        }

        // Nếu cả 2 bước OK -> Lưu Key và hiển thị giao diện
        encryptKey = keys.encryptKey;

        document.getElementById('lockScreen').style.display = 'none';
        document.getElementById('appContent').style.display = 'block';
        document.getElementById('inpMasterKey').value = ''; 

        // Tải dữ liệu ngay
        loadData();
        
        // Bắt đầu đếm ngược tự khóa
        resetAutoLock();

    } catch (e) {
        console.error(e);
        alert('Lỗi tính toán Key hoặc kết nối Server');
    }
});

// Hàm xin Token mở két (Challenge-Response)
async function performUnlockHandshake() {
  const currentToken = localStorage.getItem('token');
    
    if (!currentToken) {
        alert("Bạn chưa đăng nhập!");
        window.location.href = 'login.html';
        return false;
    }  
  
  try {
        // 1. Xin Challenge
        const res1 = await fetch(`${API_URL}/masterkey/challenge`, {
            method: 'POST',
            headers: { 
                'Authorization': `Bearer ${token}` 
            }
        });

        if (res1.status === 401) {
            alert("Phiên đăng nhập hết hạn. Vui lòng đăng nhập lại!");
            localStorage.removeItem('token'); // Xóa token hỏng
            window.location.href = 'login.html';
            return false;
        }
        
        if(!res1.ok) throw new Error("Lỗi lấy Challenge");
        const challengeData = await res1.json();

        // 2. Tính HMAC (Tạm thời gửi fake theo backend hiện tại)
        // Khi nào hoàn thiện, bạn sẽ dùng masterKeyInput để ký vào nonce này
        const fakeHmac = "client-proof-signature"; 

        // 3. Gửi Verify
        const res2 = await fetch(`${API_URL}/masterkey/verify`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}` 
            },
            body: JSON.stringify({ hmac: fakeHmac })
        });

        const verifyData = await res2.json();

        if (verifyData.status === "ok") {
            unlockToken = verifyData.unlockToken;
            return true;
        } else {
            console.error("Server từ chối:", verifyData.error);
            return false;
        }
    } catch (err) {
        console.error("Lỗi handshake:", err);
        return false;
    }
}

// ---------------------------------------------------------
// 3. Tải và Giải mã dữ liệu
// ---------------------------------------------------------
async function loadData() {
    // Kiểm tra đủ 2 chìa khóa: Chìa khóa nhà (Token) + Chìa khóa két (UnlockToken)
    if (!unlockToken || !encryptKey) return;

    try {
        const res = await fetch(`${API_URL}/data`, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'x-unlock-token': unlockToken
            }
        });

        // Xử lý khi hết phiên mở két (Backend trả về 403)
        if (res.status === 403) {
            alert("Phiên làm việc hết hạn. Vui lòng nhập lại Master Key.");
            forceLock(); // Hàm khóa màn hình
            return;
        }

        const items = await res.json();
        const listEl = document.getElementById('dataList');
        listEl.innerHTML = '';

        for (const item of items) {
            const cryptoObj = {
                iv: item.iv, 
                ciphertext: item.ciphertext, // Đây là password đã mã hóa
                auth_tag: item.authTag || item.auth_tag 
            };

            try {
                // Giải mã Password
                const plainPassword = await decryptData(cryptoObj, encryptKey);
                
                const li = document.createElement('li');
                li.className = "list-group-item d-flex justify-content-between align-items-center";
                
                // Hiển thị đẹp: Domain in đậm - Password bên cạnh
                li.innerHTML = `
                    <div>
                        <strong class="text-primary">${item.domain}</strong>
                        <div class="text-muted small">********</div> </div>
                    <button class="btn btn-sm btn-outline-secondary btn-show-pass">Hiện</button>
                `;

                // Xử lý nút "Hiện" để toggle password
                const btnShow = li.querySelector('.btn-show-pass');
                const passDiv = li.querySelector('.text-muted');
                
                btnShow.addEventListener('click', () => {
                    if (passDiv.textContent === '********') {
                        passDiv.textContent = plainPassword;
                        passDiv.classList.remove('text-muted');
                        passDiv.classList.add('text-success', 'fw-bold');
                        btnShow.textContent = 'Ẩn';
                    } else {
                        passDiv.textContent = '********';
                        passDiv.classList.add('text-muted');
                        passDiv.classList.remove('text-success', 'fw-bold');
                        btnShow.textContent = 'Hiện';
                    }
                });

                listEl.appendChild(li);

            } catch (err) {
                console.error("Lỗi giải mã:", err);
            }
        }
    } catch (err) { console.error(err); }
}

// ---------------------------------------------------------
// 4. Thêm dữ liệu mới
// ---------------------------------------------------------
document.getElementById('btnAdd').addEventListener('click', async () => {
    const domain = document.getElementById('inpDomain').value; // Lấy Domain
    const password = document.getElementById('newData').value;  // Lấy Password

    if (!domain || !password) return alert("Vui lòng nhập đủ Domain và Mật khẩu");
    if (!encryptKey) return alert("Hết phiên làm việc. Vui lòng mở khóa lại.");

    // Chỉ Mã hóa Password
    const { iv, ciphertext, auth_tag } = await encryptData(password, encryptKey);

    const res = await fetch(`${API_URL}/data`, {
        method: 'POST',
        headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
            'x-unlock-token': unlockToken
        },
        // Gửi cả domain (không mã hóa) và password (đã mã hóa)
        body: JSON.stringify({ 
            domain: domain,
            ciphertext: ciphertext,
            iv: iv,
            authTag: auth_tag 
        })
    });

    if (res.ok) {
        document.getElementById('inpDomain').value = '';
        document.getElementById('newData').value = '';
        loadData();
    } else {
        alert("Lỗi lưu dữ liệu");
    }
});

// ---------------------------------------------------------
// 5. Logic Auto-Lock
// ---------------------------------------------------------
function resetAutoLock() {
    if (timeoutParams) clearTimeout(timeoutParams);
    timeoutParams = setTimeout(forceLock, 30000); // 30s
}

function forceLock() {
    console.log("Timeout! Locking vault...");
    encryptKey = null; 
    unlockToken = null; // Xóa luôn token server
    document.getElementById('lockScreen').style.display = 'flex';
    document.getElementById('appContent').style.display = 'none';
    document.getElementById('dataList').innerHTML = ''; 
}

window.addEventListener('mousemove', () => { if(encryptKey) resetAutoLock(); });
window.addEventListener('keypress', () => { if(encryptKey) resetAutoLock(); });

// ---------------------------------------------------------
// 6. Helpers
// ---------------------------------------------------------

// Hàm chuyển Base64 (từ Server) sang Hex (cho Crypto JS)
function base64ToHex(str) {
    if (!str) return '';
    const raw = atob(str);
    let result = '';
    for (let i = 0; i < raw.length; i++) {
        const hex = raw.charCodeAt(i).toString(16);
        result += (hex.length === 2 ? hex : '0' + hex);
    }
    return result;
}

document.getElementById('btnLogout').addEventListener('click', () => {
    // 1. Hỏi xác nhận cho chắc chắn (Optional)
    if (!confirm("Bạn có chắc muốn đăng xuất?")) return;

    console.log("Đang đăng xuất...");

    // 2. Xóa sạch mọi thứ trong LocalStorage
    // Đây là bước quan trọng nhất: Mất Token = Mất quyền truy cập
    localStorage.removeItem('token');
    localStorage.removeItem('salt'); 
    localStorage.removeItem('username'); // Nếu bạn có lưu

    // 3. Xóa các biến nhạy cảm trong RAM (Bộ nhớ tạm)
    encryptKey = null;
    unlockToken = null;

    // 4. Chuyển hướng về trang Login
    window.location.href = 'login.html';
});