const { Server } = require("socket.io");

let io;

exports.initWSS = (httpServer) => {
  // Khởi tạo Socket.io
  io = new Server(httpServer, {
    cors: {
      origin: "*", // Chấp nhận mọi kết nối (Mobile & Desktop)
      methods: ["GET", "POST"]
    }
  });

  io.on("connection", (socket) => {
    console.log("🔌 Client kết nối:", socket.id);

    // 1. Desktop tạo phòng (Khi hiện QR)
    socket.on("desktop_join", (sessionId) => {
      socket.join(sessionId);
      console.log(`💻 Desktop joined room: ${sessionId}`);
    });

    // 2. Mobile gửi Key (Khi quét xong)
    socket.on("mobile_send_key", (data) => {
      const { sessionId, encryptedKeyPkg } = data;
      console.log(`📱 Mobile gửi hàng tới: ${sessionId}`);
      
      // Chuyển tiếp ngay cho Desktop trong phòng đó
      io.to(sessionId).emit("receive_key", encryptedKeyPkg);
    });

    socket.on("disconnect", () => {
      // console.log("❌ Client disconnected");
    });
  });
  
  console.log("✅ Socket.io initialized!");
};

exports.getIO = () => {
  if (!io) throw new Error("Socket.io not initialized!");
  return io;
};