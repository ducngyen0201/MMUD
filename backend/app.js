const express = require("express");
const cors = require("cors");
const http = require("http");
const path = require("path");
const ws = require("./ws");

require("dotenv").config();

const app = express();
const server = http.createServer(app); // Tạo server HTTP

app.use(cors());
app.use(express.json());

// Routes
app.use("/api/auth", require("./routes/auth"));
app.use("/api/masterkey", require("./routes/masterkey"));
app.use("/api/data", require("./routes/data"));
app.use("/frontend", express.static(path.join(__dirname, "../frontend")));

const projectRoot = path.join(__dirname, "../");

app.get("/", (req, res) => {
    res.redirect("/frontend/desktop/login.html");
});

// Kích hoạt Socket.io từ file ws.js
ws.initWSS(server); // <--- DÒNG QUAN TRỌNG NHẤT

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Server chạy tại http://localhost:${PORT}`);
});