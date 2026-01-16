const { Server } = require("socket.io");
let io;

exports.initWSS = (httpServer) => {
  io = new Server(httpServer, {
    cors: { origin: "*", methods: ["GET", "POST"] }
  });

  io.on("connection", (socket) => {
    // Log nhẹ để biết có người vào
    // console.log(`🔌 Client connected: ${socket.id}`);

    // 1. Desktop tạo phòng
    socket.on("desktop_join", (sid) => {
      socket.join(sid);
    });

    // 2. Mobile báo danh -> Báo cho Desktop
    socket.on("mobile_joined", (sid) => {
      socket.join(sid);
      io.to(sid).emit("notify_mobile_connected");
    });

    // 3. Desktop gửi Key Public
    socket.on("desktop_send_pubkey", (data) => {
      socket.to(data.sessionId).emit("receive_desktop_pub", data.pubKey);
    });

    // 4. Mobile gửi Master Key (đã mã hóa)
    socket.on("mobile_send_key", (data) => {
      io.to(data.sessionId).emit("receive_key", data.encryptedKeyPkg);
    });

    // 5. Desktop gửi Salt
    socket.on("desktop_send_salt", (data) => {
      io.to(data.sessionId).emit("receive_salt", data.salt);
    });

    // 6. Mobile gửi dữ liệu thêm mới
    socket.on("mobile_add_entry", (data) => {
      io.to(data.sessionId).emit("receive_new_entry", data.entryData);
    });


    // thêm 7,8,9----------------------------------

    // 7. Desktop báo unlock thành công
    socket.on("unlock_success", ({ sessionId }) => {
      socket.to(sessionId).emit("unlock_success");
    });

    // 8. Desktop báo unlock thất bại
    socket.on("unlock_failed", ({ sessionId }) => {
      socket.to(sessionId).emit("unlock_failed");
    });

    // 9. Desktop báo hết phiên
    socket.on("session_expired", ({ sessionId }) => {
      socket.to(sessionId).emit("session_expired", { sessionId });
    });

  });
};

exports.getIO = () => { if (!io) throw new Error("Socket error"); return io; };