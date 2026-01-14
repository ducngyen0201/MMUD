const fetch = require("node-fetch").default;
const WebSocket = require("ws");

async function desktop() {
  // 1️⃣ init QR session
  const res = await fetch("http://localhost:3000/api/qr/init", {
    method: "POST"
  });
  const { sessionId } = await res.json();

  console.log("🖥 Desktop sessionId:", sessionId);
  console.log("📱 QR content:", `qr-login:${sessionId}`);

  // 2️⃣ connect WebSocket
  const ws = new WebSocket("ws://localhost:3000");

  ws.on("open", () => {
    ws.send(JSON.stringify({
      type: "bind",
      sessionId
    }));
    console.log("🔗 WS bind OK");
  });

  ws.on("message", msg => {
    const data = JSON.parse(msg.toString());

    if (data.type === "approved") {
      console.log("✅ Desktop received APPROVED from mobile");
      console.log("➡️ Now run: node tests/qr-consume.js");
    }
  });

  ws.on("close", () => {
    console.log("❌ WS closed");
  });
}

desktop();
