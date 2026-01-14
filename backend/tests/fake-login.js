const fetch = require ("node-fetch").default;

async function login() {
  const res = await fetch("http://localhost:3000/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "alice",
      password: "password123"
    })
  });

  const data = await res.json();
  console.log(data);
}

login();
