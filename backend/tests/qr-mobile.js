const fetch = require("node-fetch").default;

async function mobileApprove() {
  const sessionId = process.argv[2];
  if (!sessionId) {
    console.log("❌ Usage: node tests/qr-mobile.js <sessionId>");
    return;
  }

  const MOBILE_JWT = "PUT_MOBILE_LOGIN_JWT_HERE";

  const res = await fetch("http://localhost:3000/api/qr/approve", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${MOBILE_JWT}`
    },
    body: JSON.stringify({ sessionId })
  });

  console.log("📱 Mobile approve result:", await res.json());
}

mobileApprove();
