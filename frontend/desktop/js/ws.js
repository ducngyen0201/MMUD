import { WS_URL } from './config.js';
// Dùng thư viện socket.io-client qua CDN trong file HTML
// <script src="https://cdn.socket.io/4.7.2/socket.io.min.js"></script>

export function initQRLogin(onSuccess) {
    const socket = io(WS_URL);

    // 1. Nhận Session ID để tạo QR
    socket.on('connect', () => {
        const sessionId = socket.id;
        // Hiển thị QR (dùng thư viện qrcode.js)
        const qrData = JSON.stringify({ action: 'login', sid: sessionId });
        new QRCode(document.getElementById("qrcode"), qrData);
    });

    // 2. Lắng nghe Mobile xác nhận thành công
    socket.on('login-success', (data) => {
        // data chứa token hoặc thông tin user
        localStorage.setItem('token', data.token);
        localStorage.setItem('salt', data.salt); // Cần salt để tí nữa derive key
        onSuccess();
    });
}