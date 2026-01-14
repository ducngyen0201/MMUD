const ws = new WebSocket("ws://localhost:3000/ws");

const statusEl = document.getElementById("status");
const qrBox = document.getElementById("qr-box");

ws.onopen = () => {
  console.log("WebSocket connected");
};

ws.onmessage = async (event) => {
  const msg = JSON.parse(event.data);

  // Server tạo session tạm
  if (msg.type === "SESSION_CREATED") {
    const sessionID = msg.sessionID;
    const qrUrl = `https://yourdomain.com/mobile/approve?session=${sessionID}`;

    await QRCode.toCanvas(
      document.createElement("canvas"),
      qrUrl,
      { width: 220 }
    ).then(canvas => {
      qrBox.innerHTML = "";
      qrBox.appendChild(canvas);
    });
  }

  // Mobile đã approve
  if (msg.type === "APPROVED") {
    statusEl.innerText = "✅ Đã xác nhận, đang đăng nhập...";
    setTimeout(() => {
      window.location.href = "vault.html";
    }, 800);
  }
};

ws.onerror = () => {
  statusEl.innerText = "❌ Lỗi kết nối WebSocket";
};
