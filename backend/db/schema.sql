-- ====================================================
-- 1. TẠO BẢNG USERS (Lưu thông tin đăng nhập Zero-Knowledge)
-- ====================================================
CREATE TABLE users (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    
    -- Mật khẩu đăng nhập (Đã hash bằng Argon2/Bcrypt)
    password_hash VARCHAR(255) NOT NULL,
    
    -- AuthKey (Dùng để Server kiểm tra HMAC của Challenge-Response)
    -- Code cũ gọi là auth_key_hash, nhưng code mới chuẩn là auth_key_verifier
    auth_key_verifier VARCHAR(255) NOT NULL, 
    
    -- Salt (Base64) để Client tính toán lại MasterKey khi đăng nhập
    kdf_salt VARCHAR(255) NOT NULL, 
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ====================================================
-- 2. TẠO BẢNG ENCRYPTED_DATA (Lưu Password Manager)
-- ====================================================
CREATE TABLE encrypted_data (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id BIGINT NOT NULL,

    -- Tên trang web/tài khoản (Lưu dạng Text để dễ tìm kiếm/hiển thị)
    domain VARCHAR(255) NOT NULL, 

    -- Mật khẩu ĐÃ MÃ HÓA (Ciphertext)
    -- Lưu dạng BLOB để chứa dữ liệu nhị phân
    password BLOB NOT NULL,       
    
    -- IV (Initialization Vector) - Bắt buộc 12 bytes cho AES-GCM
    iv VARBINARY(12) NOT NULL,
    
    -- Auth Tag (Xác thực toàn vẹn) - Bắt buộc 16 bytes
    auth_tag VARBINARY(16) NOT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    -- Nếu xóa User thì xóa luôn dữ liệu của họ
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ====================================================
-- 3. TẠO BẢNG MASTERKEY_NONCE (Challenge-Response)
-- ====================================================
CREATE TABLE masterkey_nonce (
    user_id BIGINT PRIMARY KEY,
    
    -- Chuỗi ngẫu nhiên Server thách đố Client (32 bytes)
    nonce VARBINARY(32) NOT NULL,
    
    -- Thời gian hết hạn của thách đố (thường là 30-60s)
    expires_at TIMESTAMP NOT NULL,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ====================================================
-- 4. TẠO BẢNG QR_SESSIONS (Đồng bộ Mobile -> Desktop)
-- ====================================================
CREATE TABLE qr_sessions (
    -- Session ID (UUID từ Frontend tạo ra)
    session_id VARCHAR(64) PRIMARY KEY,
    
    -- Public Key ECDH của Desktop (Lưu dạng JSON String)
    desktop_public_key TEXT,
    
    -- Dữ liệu Mobile gửi lên (Chứa EncryptKey đã mã hóa)
    mobile_data TEXT,
    
    -- Trạng thái: WAITING (Chờ quét), APPROVED (Đã gửi key), EXPIRED
    status ENUM('WAITING', 'APPROVED', 'EXPIRED') DEFAULT 'WAITING',
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);