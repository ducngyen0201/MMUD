const form = document.getElementById("loginForm");
const statusEl = document.getElementById("status");

form.addEventListener("submit", async (e) => {
  e.preventDefault();

  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;

  statusEl.textContent = "⏳ Đang đăng nhập...";

  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        password // ✅ plaintext over HTTPS
      })
    });

    if (!res.ok) throw new Error("Login failed");

    const data = await res.json();

    // Lưu session token (cookie / localStorage tùy backend)
    localStorage.setItem("sessionToken", data.token);

    statusEl.textContent = "✅ Đăng nhập thành công";
    window.location.href = "/desktop.html";

  } catch (err) {
    console.error(err);
    statusEl.textContent = "❌ Sai username hoặc password";
  }
});
