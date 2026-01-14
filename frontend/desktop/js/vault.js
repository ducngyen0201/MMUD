let timeLeft = 30;
let timer = null;
let isUnlocking = false;

function unlockVaultUI() {
  // reset state
  timeLeft = 30;
  if (timer) clearInterval(timer);

  document.getElementById("lock-screen").style.display = "none";
  document.getElementById("vault").style.display = "block";

  setStatus("✅ Vault đã mở");
  startCountdown();
  loadData();
}

function setStatus(text) {
  const el = document.getElementById("auth-status");
  if (el) el.innerText = text;
}


function startCountdown() {
  const timerEl = document.getElementById("timer");

  timer = setInterval(() => {
    timeLeft--;
    timerEl.innerText = `⏳ ${timeLeft}s`;

    if (timeLeft <= 0) {
      logout();
    }
  }, 1000);
}

function loadData() {
  const items = [
    { id: 1, name: "Facebook" },
    { id: 2, name: "Gmail" },
    { id: 3, name: "Zalo" }
  ];

  const list = document.getElementById("data-list");
  list.innerHTML = "";

  items.forEach(item => {
    const li = document.createElement("li");
    li.innerHTML = `
      ${item.name}
      <button onclick="editItem(${item.id})">✏️</button>
      <button onclick="deleteItem(${item.id})">🗑</button>
    `;
    list.appendChild(li);
  });
}

function addItem() {
  alert("➕ Thêm dữ liệu (mock)");
}

function editItem(id) {
  alert("✏️ Sửa item " + id);
}

function deleteItem(id) {
  alert("🗑 Xóa item " + id);
}

function logout() {
  if (timer) clearInterval(timer);
  alert("⏱ Hết thời gian, cần xác thực lại");
  window.location.reload();
}

window.onload = () => {
  unlockVaultUI();
}