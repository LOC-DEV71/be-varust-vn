const mysql = require("mysql2/promise");

const pool = mysql.createPool({
  host: process.env.MYSQLHOST || "localhost",
  user: process.env.MYSQLUSER || "root",
  password: process.env.MYSQLPASSWORD || "",
  database: "myapp",
  port: process.env.MYSQLPORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

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
