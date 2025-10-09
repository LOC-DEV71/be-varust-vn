const mysql = require("mysql2/promise");

const pool = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// test kết nối
(async () => {
  try {
    const conn = await pool.getConnection();
    console.log("✅ Kết nối MySQL thành công!");
    conn.release();
  } catch (err) {
    console.error("❌ Lỗi kết nối MySQL:", err.message);
  }
})();

module.exports = pool;
