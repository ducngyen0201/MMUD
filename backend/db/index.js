const mysql = require("mysql2/promise");
require('dotenv').config(); // Đảm bảo đã load biến môi trường

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  connectionLimit: 10
});

// --- Thêm đoạn này để kiểm tra kết nối ---
pool.getConnection()
  .then(connection => {
    console.log("✅ Database connected successfully!");
    connection.release(); // Trả kết nối về pool ngay sau khi kiểm tra xong
  })
  .catch(error => {
    console.error("❌ Database connection failed:", error.message);
  });
// ----------------------------------------

module.exports = pool;