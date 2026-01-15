import { API_URL } from './config.js';
import { generateSalt, deriveKeys, buf2hex, buf2base64, hex2buf } from './crypto.js';

document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value; // Pass đăng nhập
    const masterKey = document.getElementById('masterKey').value; // Master Key

    try {
        // 1. Tạo Salt ngẫu nhiên (dạng Hex để dùng cho hàm deriveKeys cũ)
        const saltHex = generateSalt(); 
        
        // 2. Tính toán Auth Key từ MasterKey
        const { authVerifier } = await deriveKeys(masterKey, saltHex);

        // 3. Chuẩn bị dữ liệu gửi lên Backend
        // Backend yêu cầu kdfSalt là Base64
        const saltBuffer = hex2buf(saltHex);
        const saltBase64 = buf2base64(saltBuffer);

        const payload = {
            username: username,
            // LƯU Ý: Backend tên là 'passwordHash' nhưng ta gửi password thô
            // Lý do: Backend code bạn gửi lưu trực tiếp biến này. 
            // Nếu gửi hash, argon2.verify lúc login sẽ lỗi format.
            passwordHash: password, 
            authKeyHash: authVerifier,
            kdfSalt: saltBase64
        };

        // 4. Gửi Request
        const response = await fetch(`${API_URL}/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (response.ok) {
            alert('Đăng ký thành công!');
            window.location.href = 'login.html';
        } else {
            alert('Lỗi: ' + (data.error || 'Đăng ký thất bại'));
        }
    } catch (err) {
        console.error(err);
        alert('Lỗi xử lý client-side');
    }
});