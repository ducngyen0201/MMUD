const { Server } = require("socket.io");

let io;

exports.initWSS = (httpServer) => {
  // Khởi tạo Socket.io gắn vào HttpServer
  io = new Server(httpServer, {
    cors: {
      origin: "*", // Cho phép Frontend (127.0.0.1:5500) kết nối
      methods: ["GET", "POST"]
    }
  });

  io.on("connection", (socket) => {
    console.log("🔌 New client connected:", socket.id);

    // Xử lý các sự kiện socket tại đây
    socket.on("disconnect", () => {
      console.log("❌ Client disconnected:", socket.id);
    });
    
    // Ví dụ: Mobile gửi yêu cầu login
    socket.on('login-request', (data) => {
        console.log("Received login request:", data);
    });
  });
  
  console.log("Initialize Socket.io success");
};

// Hàm tiện ích để file khác (như auth.js) có thể dùng để bắn thông báo
exports.getIO = () => {
  if (!io) {
    throw new Error("Socket.io not initialized!");
  }
  return io;
};