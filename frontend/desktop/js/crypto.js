export function generateSalt() {
    const array = new Uint8Array(16);
    window.crypto.getRandomValues(array);
    return buf2hex(array);
}

export function buf2hex(buffer) {
    return [...new Uint8Array(buffer)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
}

export function base64ToHex(str) {
    // Dùng atob để decode Base64 thành chuỗi nhị phân
    const raw = atob(str);
    let result = '';
    for (let i = 0; i < raw.length; i++) {
        const hex = raw.charCodeAt(i).toString(16);
        // Đảm bảo mỗi byte luôn có 2 ký tự (VD: 'a' -> '0a')
        result += (hex.length === 2 ? hex : '0' + hex);
    }
    return result; // Trả về Hex string (giống format lúc đăng ký)
}

export function hex2buf(hexString) {
    if (!hexString) return new Uint8Array(0);
    if (hexString instanceof Uint8Array) return hexString;

    if (typeof hexString === 'string') {
        const cleanHex = hexString.replace(/\s+/g, '');
        const validHex = cleanHex.length % 2 !== 0 ? '0' + cleanHex : cleanHex;
        return new Uint8Array(
            validHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
        );
    }
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


// Logic: MasterKey + Salt --(PBKDF2)--> 512 bits. 
// 256 bit đầu -> AuthKey (để tạo Verifier gửi server)
// 256 bit sau -> EncryptKey (để mã hóa dữ liệu cục bộ)
export async function deriveKeys(masterKeyText, saltHex) {
    const enc = new TextEncoder();
    const salt = hex2buf(saltHex);

    // Import MasterKey
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

    const derivedBuffer = new Uint8Array(derivedBits);
    const authKeyRaw = derivedBuffer.slice(0, 32);      // 32 bytes đầu
    const encryptKeyRaw = derivedBuffer.slice(32, 64);  // 32 bytes sau

    // [CŨ] Hash AuthKey -> AuthVerifier
    const authVerifierBuf = await window.crypto.subtle.digest("SHA-256", authKeyRaw);
    const authVerifier = buf2hex(authVerifierBuf);

    // [MỚI - CẦN THÊM DÒNG NÀY] Chuyển AuthKey gốc sang Hex để gửi lên Register
    const authKeyHex = buf2hex(authKeyRaw); 

    // Import EncryptKey (AES-GCM)
    const encryptKey = await window.crypto.subtle.importKey(
        "raw", encryptKeyRaw, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]
    );

    return { authVerifier, encryptKey, authKey: authKeyHex };
}

// AES ENCRYPTION (MÃ HÓA DỮ LIỆU)

export async function encryptData(plainText, key) {
    // Nếu key không phải CryptoKey (ví dụ gửi nhầm string), báo lỗi
    if (!(key instanceof CryptoKey)) throw new Error("encryptData cần CryptoKey object");

    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plainText);

    const encryptedBuffer = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encoded
    );

    const buffer = new Uint8Array(encryptedBuffer);
    const tagLength = 16;
    
    // Tách Auth Tag (16 bytes cuối)
    const authTag = buffer.slice(buffer.length - tagLength);
    const ciphertext = buffer.slice(0, buffer.length - tagLength);

    return {
        iv: buf2hex(iv),
        ciphertext: buf2hex(ciphertext),
        auth_tag: buf2hex(authTag)
    };
}

export async function decryptData(item, key) {
    try {
        if (!(key instanceof CryptoKey)) throw new Error("decryptData cần CryptoKey object");

        const iv = hex2buf(item.iv);
        const ciphertext = hex2buf(item.ciphertext);
        const tag = hex2buf(item.auth_tag || item.authTag);

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

// Hàm này dùng để ký vào Nonce mà Server gửi xuống
// keyString: MasterKey (hoặc AuthKey) dạng text
// message: Nonce từ server (dạng Base64 hoặc Hex)
export async function calculateHMAC(keyString, message) {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(keyString);
    const msgData = encoder.encode(message);

    // Import key dưới dạng HMAC
    const cryptoKey = await window.crypto.subtle.importKey(
        "raw", 
        keyData, 
        { name: "HMAC", hash: "SHA-256" }, 
        false, 
        ["sign"]
    );

    // Ký message
    const signature = await window.crypto.subtle.sign(
        "HMAC", 
        cryptoKey, 
        msgData
    );

    // Trả về Hex để gửi lên Server verify
    return buf2hex(signature);
}


// 5.1. Tạo cặp khóa ECDH (Public/Private)
export async function generateECDHKeyPair() {
    return await window.crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true, // extractable (để export public key)
        ["deriveKey", "deriveBits"]
    );
}

// 5.2. Export Key sang JSON (Để gửi qua QR Code/Socket)
export async function exportKeyJWK(key) {
    return await window.crypto.subtle.exportKey("jwk", key);
}

// 5.3. Import Key JSON (Khi nhận được từ thiết bị kia)
export async function importKeyJWK(jwkData) {
    return await window.crypto.subtle.importKey(
        "jwk",
        jwkData,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        []
    );
}

// 5.4. Tính toán Khóa Chung (Shared Secret) -> Ra khóa AES
// Dùng PrivateKey của mình + PublicKey của đối phương
export async function deriveSharedKey(privateKey, publicKey) {
    return await window.crypto.subtle.deriveKey(
        { name: "ECDH", public: publicKey },
        privateKey,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"] // Khóa này dùng để mã hóa MasterKey khi truyền tải
    );
}