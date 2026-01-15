const express = require("express");
const fs = require("fs");
const cors = require("cors");
const https = require("https");
const path = require("path");
const ws = require("./ws");

require("dotenv").config();

const options = {
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.cert')
};

const app = express();
const server = https.createServer(options, app); // Tạo server HTTPS

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
ws.initWSS(server);

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server chạy tại https://localhost:${PORT}`);
});