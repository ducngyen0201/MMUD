const fetch = require("node-fetch").default;

async function consume() {
  const sessionId = process.argv[2];
  if (!sessionId) {
    console.log("❌ Usage: node tests/qr-consume.js <sessionId>");
    return;
  }

  const res = await fetch("http://localhost:3000/api/qr/consume", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sessionId })
  });

  const data = await res.json();
  console.log("🖥 Desktop login result:", data);

  if (data.token) {
    console.log("🎉 Desktop JWT:", data.token);
  }
}

consume();
