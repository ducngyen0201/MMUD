require("dotenv").config();
const express = require("express");

const authRoutes = require("./routes/auth");

const app = express();
app.use(express.json());
const masterkeyRoutes = require("./routes/masterkey");
app.use("/api", masterkeyRoutes);

const dataRoutes = require("./routes/data");
app.use("/api", dataRoutes);

app.use("/api", authRoutes);

const http = require("http");
const { initWSS } = require("./ws");

const server = http.createServer(app);
initWSS(server);

server.listen(3000, () => {
  console.log("Server + WS running");
});


app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.listen(3000, () => {
  console.log("Server running at http://localhost:3000");
});
