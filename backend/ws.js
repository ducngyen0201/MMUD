const { Server } = require("socket.io");
let io;

exports.initWSS = (httpServer) => {
  io = new Server(httpServer, {
    cors: { origin: "*", methods: ["GET", "POST"] }
  });

  io.on("connection", (socket) => {
    // 1. Desktop tạo phòng
    socket.on("desktop_join", (sessionId) => {
      socket.join(sessionId);
      console.log(`💻 Desktop joined: ${sessionId}`);
    });

    // 👇 2. QUAN TRỌNG: Mobile báo danh
    socket.on("mobile_joined", (sessionId) => {
      console.log(`📱 Mobile joined: ${sessionId}`);
      socket.join(sessionId);
      // Báo cho Desktop biết là Mobile đã vào
      io.to(sessionId).emit("notify_mobile_connected"); 
    });

    // 👇 3. QUAN TRỌNG: Desktop gửi Public Key trả lời
    socket.on("desktop_send_pubkey", (data) => {
      const { sessionId, pubKey } = data;
      // Gửi Key cho Mobile
      socket.to(sessionId).emit("receive_desktop_pub", pubKey);
    });

    // 4. Mobile gửi Key mở khóa (như cũ)
    socket.on("mobile_send_key", (data) => {
      const { sessionId, encryptedKeyPkg } = data;
      io.to(sessionId).emit("receive_key", encryptedKeyPkg);
    });

    // 5. Desktop gửi Salt (như cũ)
    socket.on("desktop_send_salt", (data) => {
      const { sessionId, salt } = data;
      io.to(sessionId).emit("receive_salt", salt);
    });

    // 6. Mobile gửi Data thêm mới (như cũ)
    socket.on("mobile_add_entry", (data) => {
      const { sessionId, entryData } = data;
      io.to(sessionId).emit("receive_new_entry", entryData);
    });
  });
};

exports.getIO = () => { if (!io) throw new Error("Socket error"); return io; };