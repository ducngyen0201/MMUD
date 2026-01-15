import { API_URL } from './config.js';

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
            // Lưu Token
            localStorage.setItem('token', data.token);
            
            // [QUAN TRỌNG] Lưu Salt
            if (data.salt) {
                localStorage.setItem('salt', data.salt);
                console.log("Đã lưu Salt:", data.salt);
                window.location.href = 'vault.html';
            } else {
                alert("Lỗi dữ liệu: Tài khoản này không có Salt (Do tạo trước khi update DB). Vui lòng tạo tài khoản mới.");
            }
        } else {
            alert(data.error || "Đăng nhập thất bại");
        }
    } catch (err) {
        console.error(err);
        alert("Lỗi kết nối Server");
    }
});