// --- CÁC HÀM MẬT MÃ HỌC (Client-Side) ---

// 1. Sinh Salt ngẫu nhiên (16 bytes)
export function generateSalt() {
    const array = new Uint8Array(16);
    window.crypto.getRandomValues(array);
    return buf2hex(array);
}

// 2. Chuyển đổi Utility
export function buf2hex(buffer) {
    return [...new Uint8Array(buffer)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
}

export function hex2buf(hexString) {
    // 1. Nếu đầu vào là null/undefined -> Trả về Buffer rỗng để không lỗi
    if (!hexString) return new Uint8Array(0);

    // 2. Nếu đầu vào ĐÃ LÀ Buffer (Uint8Array) -> Trả về chính nó (Không cần convert nữa)
    if (hexString instanceof Uint8Array) {
        return hexString;
    }

    // 3. Nếu là String -> Convert sang Buffer
    if (typeof hexString === 'string') {
        // Xóa dấu cách nếu có
        const cleanHex = hexString.replace(/\s+/g, '');
        // Đảm bảo độ dài chẵn (thêm số 0 vào đầu nếu lẻ)
        const validHex = cleanHex.length % 2 !== 0 ? '0' + cleanHex : cleanHex;
        
        return new Uint8Array(
            validHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
        );
    }

    // 4. Các trường hợp khác -> Báo lỗi hoặc trả về rỗng
    console.error("hex2buf received invalid type:", typeof hexString);
    return new Uint8Array(0);
}

export function buf2base64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

// 3. CORE: Hàm tách MasterKey -> AuthKey và EncryptKey
// Logic: MasterKey + Salt --(PBKDF2)--> 512 bits. 256 bit đầu là Auth, 256 bit sau là Encrypt.
export async function deriveKeys(masterKeyText, saltHex) {
    const enc = new TextEncoder();
    const salt = hex2buf(saltHex);

    // Import MasterKey vào WebCrypto
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw", enc.encode(masterKeyText), { name: "PBKDF2" }, false, ["deriveBits"]
    );

    // Chạy PBKDF2 (100,000 vòng lặp)
    const derivedBits = await window.crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        512 // Lấy 512 bits
    );

    // Tách key
    const derivedBuffer = new Uint8Array(derivedBits);
    const authKeyRaw = derivedBuffer.slice(0, 32);      // 32 bytes đầu
    const encryptKeyRaw = derivedBuffer.slice(32, 64);  // 32 bytes sau

    // Hash AuthKey một lần nữa để tạo AuthVerifier gửi lên Server (Server chỉ giữ cái này)
    const authVerifierBuf = await window.crypto.subtle.digest("SHA-256", authKeyRaw);
    const authVerifier = buf2hex(authVerifierBuf);

    // Import EncryptKey để dùng mã hóa dữ liệu (AES-GCM)
    const encryptKey = await window.crypto.subtle.importKey(
        "raw", encryptKeyRaw, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]
    );

    return { authVerifier, encryptKey };
}

// 3. encryptData: Tách Ciphertext và AuthTag riêng
export async function encryptData(plainText, key) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 12 bytes IV
    const encoded = new TextEncoder().encode(plainText);

    // WebCrypto AES-GCM output mặc định nối liền Ciphertext + Tag (16 bytes cuối)
    const encryptedBuffer = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encoded
    );

    const buffer = new Uint8Array(encryptedBuffer);
    const tagLength = 16;
    
    // Tách 16 byte cuối làm Auth Tag
    const authTag = buffer.slice(buffer.length - tagLength);
    const ciphertext = buffer.slice(0, buffer.length - tagLength);

    return {
        iv: buf2hex(iv),
        ciphertext: buf2hex(ciphertext),
        auth_tag: buf2hex(authTag) // Lưu ý: Backend dùng key này để insert vào DB
    };
}

// 4. decryptData: Ghép lại để giải mã
export async function decryptData(item, key) {
    try {
        // item chứa: { ciphertext: "hex", iv: "hex", auth_tag: "hex" }
        const iv = hex2buf(item.iv);
        const ciphertext = hex2buf(item.ciphertext); // Nếu DB trả về Buffer thì convert sang Uint8Array
        const tag = hex2buf(item.auth_tag || item.authTag); // Support cả 2 kiểu naming

        // Ghép Ciphertext + Tag lại để WebCrypto hiểu
        const fullBuffer = new Uint8Array(ciphertext.length + tag.length);
        fullBuffer.set(ciphertext);
        fullBuffer.set(tag, ciphertext.length);

        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            fullBuffer
        );
        return new TextDecoder().decode(decrypted);
    } catch (e) {
        console.error("Decrypt failed:", e);
        return null; 
    }
}