import { API_URL, WS_URL } from './config.js';

// --- XỬ LÝ LOGIN TRUYỀN THỐNG ---
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        const res = await fetch(`${API_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await res.json();

        if (res.ok) {
            // Login thành công -> Lưu Token và Salt
            localStorage.setItem('token', data.token);
            // Backend cần trả về Salt của user để client dùng tính MasterKey sau này
            if(data.user && data.user.salt) {
                localStorage.setItem('salt', data.user.salt);
            }
            window.location.href = 'vault.html';
        } else {
            alert(data.message || 'Đăng nhập thất bại');
        }
    } catch (err) {
        console.error(err);
        alert('Lỗi kết nối server');
    }
});

// --- XỬ LÝ QR LOGIN (WebSocket) ---
const socket = io(WS_URL);
const qrContainer = document.getElementById("qrcode");

socket.on('connect', () => {
    document.getElementById('qrStatus').innerText = "Hãy dùng App Mobile quét mã này";
    
    // Tạo mã QR chứa SessionID
    qrContainer.innerHTML = ""; 
    const sessionData = JSON.stringify({
        type: 'login-request',
        sid: socket.id
    });
    
    new QRCode(qrContainer, {
        text: sessionData,
        width: 180,
        height: 180
    });
});

// Lắng nghe sự kiện khi Mobile xác nhận thành công
socket.on('login-success', (data) => {
    console.log("Mobile login confirmed!", data);
    if (data.token) {
        localStorage.setItem('token', data.token);
        if (data.salt) localStorage.setItem('salt', data.salt);
        
        alert("Đăng nhập bằng QR thành công!");
        window.location.href = 'vault.html';
    }
});