// backend/app.js
require("dotenv").config();
const cors = require('cors');
const express = require("express");
const http = require("http");
const { initWSS } = require("./ws");

// Import Routes
const authRoutes = require("./routes/auth");
const dataRoutes = require("./routes/data"); 
const masterkeyRoutes = require("./routes/masterkey");

const app = express();
const server = http.createServer(app);

// --- 1. Middleware ---
app.use(cors()); // Cho phép mọi nguồn (bao gồm Socket.io ban đầu)
app.use(express.json());

// --- 2. Routes ---
app.use("/api/auth", authRoutes);
app.use("/api/data", dataRoutes);
app.use("/api/masterkey", masterkeyRoutes);

app.get("/health", (req, res) => {
  res.json({ status: "Server is ALIVE!" });
});

// --- 3. Kích hoạt WebSocket ---
initWSS(server); // <--- Truyền server vào hàm init của socket.io

// --- 4. Chạy Server (Dùng biến server, KHÔNG dùng app) ---
const PORT = 3000;
server.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
  console.log(`✅ WebSocket ready at /socket.io/`); 
});