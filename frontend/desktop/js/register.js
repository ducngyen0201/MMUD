import { API_URL } from './config.js';
import { generateSalt, deriveKeys, hex2buf, buf2base64 } from './crypto.js';

document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    // 1. Lấy dữ liệu từ Form
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;   // Mật khẩu đăng nhập
    const masterKey = document.getElementById('masterKey').value; // Master Key (Két sắt)

    if (!username || !password || !masterKey) {
        return alert("Vui lòng điền đầy đủ thông tin!");
    }

    // Disable nút để tránh bấm nhiều lần
    const btnSubmit = e.target.querySelector('button');
    btnSubmit.disabled = true;
    btnSubmit.textContent = "Đang xử lý...";

    try {
        console.log("🚀 Bắt đầu tạo tài khoản...");

        // 2. Tạo Salt ngẫu nhiên (dạng Hex để tính toán client-side)
        const saltHex = generateSalt(); 
        
        // 3. Tính toán Key từ MasterKey
        // Hàm deriveKeys trả về: { encryptKey, authKey, authVerifier }
        // Lưu ý: authVerifier chính là Hash(AuthKey)
        const keys = await deriveKeys(masterKey, saltHex);

        if (!keys.authVerifier) {
            throw new Error("Hàm deriveKeys trong crypto.js chưa trả về authVerifier!");
        }

        // 4. Chuẩn bị Salt để gửi lên Server (Chuyển Hex -> Base64 cho gọn DB)
        // Backend sẽ lưu chuỗi Base64 này vào cột kdf_salt
        const saltBuffer = hex2buf(saltHex);
        const saltBase64 = buf2base64(saltBuffer);
        console.log("📝 [REGISTER] AuthKey gửi lên:", keys.authKey);
        // 5. Đóng gói dữ liệu (Payload)
        const payload = {
            username: username,
            
            // Backend sẽ lấy passwordHash này đem đi Argon2 lần nữa rồi mới lưu
            passwordHash: password, 
            
            // Đây là cái Server cần lưu để xác thực (Thay vì lưu MasterKey)
            authKeyHash: keys.authKey, 
            
            // Salt để sau này đăng nhập trả lại cho Client tính toán
            kdfSalt: saltBase64 
        };

        // 6. Gửi Request đăng ký
        const response = await fetch(`${API_URL}/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (response.ok) {
            alert('✅ Đăng ký thành công!');
            window.location.href = 'login.html';
        } else {
            console.error("Lỗi Server:", data);
            alert('❌ Lỗi: ' + (data.error || 'Đăng ký thất bại'));
            btnSubmit.disabled = false;
            btnSubmit.textContent = "Đăng ký";
        }

    } catch (err) {
        console.error("Lỗi Client:", err);
        alert('❌ Lỗi xử lý mã hóa: ' + err.message);
        btnSubmit.disabled = false;
        btnSubmit.textContent = "Đăng ký";
    }
});