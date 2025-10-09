  const express = require("express");
  const cors = require("cors");
  const bcrypt = require("bcrypt");
  const jwt = require("jsonwebtoken");
  const db = require("./dataBase/db");

  // thêm
  const multer = require("multer");
  const path = require("path");

  const app = express();
  const PORT = process.env.PORT || 3000;
  const SECRET_KEY = "mysecretkey"; 

  app.use(cors());
  app.use(express.json());

  // Multer config
  const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, "uploads/"); // folder uploads
    },
    filename: (req, file, cb) => {
      cb(null, Date.now() + path.extname(file.originalname)); // unique name
    }
  });
  const upload = multer({ storage });

  // cho phép truy cập ảnh qua URL
  app.use("/uploads", express.static("uploads"));

  // Middleware xác thực token  
  function verifyToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.status(401).json({ message: "Thiếu token" });

    const token = authHeader.split(" ")[1]; 
    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      req.user = decoded; 
      next();
    } catch (err) {
      return res.status(401).json({ message: "Token không hợp lệ" });
    }
  }

  // Middleware kiểm tra admin
  function verifyAdmin(req, res, next) {
    verifyToken(req, res, () => {
      if (req.user.role !== "admin") {
        return res.status(403).json({ message: "Không có quyền admin" });
      }
      next();
    });
  }


  // Tạo admin mặc định 
  (async () => {
    try {
      const ADMIN_USERNAME = "admin";
      const ADMIN_EMAIL = "loclc8533@ut.edu.vn";
      const ADMIN_PASSWORD = "admin123"; 

      const [rows] = await db.execute(
        "SELECT id FROM users WHERE role = 'admin' OR username = ? LIMIT 1",
        [ADMIN_USERNAME]
      );

      if (rows.length === 0) {
        const hashed = await bcrypt.hash(ADMIN_PASSWORD, 10);
        const [result] = await db.execute(
          "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
          [ADMIN_USERNAME, ADMIN_EMAIL, hashed, "admin"]
        );

        const token = jwt.sign(
          { id: result.insertId, username: ADMIN_USERNAME, role: "admin" },
          SECRET_KEY,
          { expiresIn: "7d" }
        );

      } else {
        console.log(" Admin đã tồn tại.");
      }
    } catch (err) {
      console.error("Lỗi tạo admin mặc định:", err.message);
    }
  })();

  // Ping test
  app.get("/health", (_, res) => res.send("OK"));

  // Lấy danh sách users (ẩn password)
  app.get("/users", async (req, res) => {
    try {
      const [rows] = await db.execute(
        "SELECT id, username, email, role, created_at, updated_at FROM users ORDER BY id DESC"
      );
      res.json(rows);
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  });
  // sửa user
  app.put("/users/:id", verifyAdmin, async (req, res) => {
    const { username, email, role } = req.body;
    try {
      await db.execute(
        "UPDATE users SET username=?, email=?, role=? WHERE id=?",
        [username, email, role, req.params.id]
      );
      res.json({ success: true, message: "Cập nhật user thành công" });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  });

  //  Delete user
  app.delete("/users/:id", verifyAdmin, async (req, res) => {
    try {
      await db.execute("DELETE FROM users WHERE id=?", [req.params.id]);
      res.json({ success: true, message: "Xóa user thành công" });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  });


  //  Register
  app.post("/register", async (req, res) => {
    const { username, email, password, phone } = req.body;
    if (!username || !email || !password || !phone) {
      return res.status(400).json({ success: false, message: "Thiếu thông tin" });
    }

    try {
      const [dup] = await db.execute(
        "SELECT id FROM users WHERE username = ? OR email = ? OR phone = ?",
        [username, email, phone]
      );
      if (dup.length) {
        return res
          .status(409)
          .json({ success: false, message: "Username, email hoặc phone đã tồn tại" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const [result] = await db.execute(
        "INSERT INTO users (username, email, password, phone, role) VALUES (?, ?, ?, ?, 'user')",
        [username, email, hashedPassword, phone]
      );

      const token = jwt.sign(
        { id: result.insertId, username, role: "user" },
        SECRET_KEY,
        { expiresIn: "1h" }
      );

      res.json({ success: true, message: "Đăng ký thành công", token });
    } catch (err) {
      console.error(err);
      res.status(500).json({ success: false, message: "Server error" });
    }
  });


  //  Login
  app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password)
      return res
        .status(400)
        .json({ success: false, message: "Cần username và password" });

    try {
      const [rows] = await db.execute(
        "SELECT id, username, password, role FROM users WHERE username = ?",
        [username]
      );
      if (rows.length === 0)
        return res
          .status(401)
          .json({ success: false, message: "User not found" });

      const user = rows[0];
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch)
        return res
          .status(401)
          .json({ success: false, message: "Sai mật khẩu" });

      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        SECRET_KEY,
        { expiresIn: "1h" }
      );

      res.json({ success: true, message: "Login thành công", token, role: user.role });
    } catch (err) {
      console.error(err);
      res.status(500).json({ success: false, message: "Server error" });
    }
  });


  // Products
  // Get all products
  app.get("/products", async (req, res) => {
    const [rows] = await db.execute("SELECT * FROM products ORDER BY id DESC");
    res.json(rows);
  });

  // Add product (admin + upload file)
  app.post(
    "/products",
    verifyAdmin,
    upload.fields([
      { name: "image", maxCount: 1 },
      { name: "images1", maxCount: 1 },
      { name: "images2", maxCount: 1 },
      { name: "images3", maxCount: 1 }
    ]),
    async (req, res) => {
      try {
        const {
          title,
          price,
          quantity,
          sale,
          description,
          category,
          hang,
          kieumanhinh,
          kichthuoc,
          tamnen,
          tansoquet,
          dophangiai,
          nhucausudung
        } = req.body;

        const image = req.files["image"] ? `/uploads/${req.files["image"][0].filename}` : null;
        const images1 = req.files["images1"] ? `/uploads/${req.files["images1"][0].filename}` : null;
        const images2 = req.files["images2"] ? `/uploads/${req.files["images2"][0].filename}` : null;
        const images3 = req.files["images3"] ? `/uploads/${req.files["images3"][0].filename}` : null;

        await db.execute(
          `INSERT INTO products 
          (title, price, quantity, sale, description, category, image, images1, images2, images3, hang, kieumanhinh, kichthuoc, tamnen, tansoquet, dophangiai, nhucausudung) 
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            title,
            price,
            quantity,
            sale,
            description,
            category,
            image,
            images1,
            images2,
            images3,
            hang,
            kieumanhinh,
            kichthuoc,
            tamnen,
            tansoquet,
            dophangiai,
            nhucausudung
          ]
        );

        res.json({ success: true, message: "Thêm sản phẩm thành công" });
      } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Lỗi server" });
      }
    }
  );

  // Update product (admin - chưa xử lý file, chỉ text)
  app.put("/products/:id", verifyAdmin, async (req, res) => {
    const { title, price, quantity, description } = req.body;
    await db.execute(
      "UPDATE products SET title=?, price=?, quantity=?, description=? WHERE id=?",
      [title, price, quantity, description, req.params.id]
    );
    res.json({ success: true, message: "Cập nhật sản phẩm thành công" });
  });

  // Delete product (admin)
  app.delete("/products/:id", verifyAdmin, async (req, res) => {
    await db.execute("DELETE FROM products WHERE id=?", [req.params.id]);
    res.json({ success: true, message: "Xóa sản phẩm thành công" });
  });









  //News
  // Get news
  app.get("/news", async (req, res) => {
    const [rows] = await db.execute("SELECT * FROM news ORDER BY id DESC");
    res.json(rows);
  });

  // Add news (admin)
  app.post("/news", verifyAdmin, async (req, res) => {
    const { title, content, image } = req.body;
    await db.execute(
      "INSERT INTO news (title, content, image) VALUES (?, ?, ?)",
      [title, content, image]
    );
    res.json({ success: true, message: "Thêm tin tức thành công" });
  });

  // Update news (admin)
  app.put("/news/:id", verifyAdmin, async (req, res) => {
    const { title, content, image } = req.body;
    await db.execute(
      "UPDATE news SET title=?, content=?, image=? WHERE id=?",
      [title, content, image, req.params.id]
    );
    res.json({ success: true, message: "Cập nhật tin tức thành công" });
  });

  // Delete news (admin)
  app.delete("/news/:id", verifyAdmin, async (req, res) => {
    await db.execute("DELETE FROM news WHERE id=?", [req.params.id]);
    res.json({ success: true, message: "Xóa tin tức thành công" });
  });









  // cart
  // Lấy giỏ hàng của user
  app.get("/cart/:userId", async (req, res) => {
    const { userId } = req.params;
    const [rows] = await db.execute(
      `SELECT c.id, p.title, p.price, c.quantity, c.status
      FROM carts c
      JOIN products p ON c.product_id = p.id
      WHERE c.user_id = ?`,
      [userId]
    );
    res.json(rows);
  });

  // Thêm sản phẩm vào giỏ
  app.post("/cart", async (req, res) => {
    const { user_id, product_id, quantity } = req.body;
    await db.execute(
      "INSERT INTO carts (user_id, product_id, quantity) VALUES (?, ?, ?)",
      [user_id, product_id, quantity]
    );
    res.json({ success: true, message: "Đã thêm vào giỏ hàng" });
  });

  // Update số lượng
  app.put("/cart/:id", async (req, res) => {
    const { quantity } = req.body;
    await db.execute("UPDATE carts SET quantity=? WHERE id=?", [quantity, req.params.id]);
    res.json({ success: true, message: "Cập nhật giỏ hàng thành công" });
  });

  // Xóa khỏi giỏ
  app.delete("/cart/:id", async (req, res) => {
    await db.execute("DELETE FROM carts WHERE id=?", [req.params.id]);
    res.json({ success: true, message: "Xóa sản phẩm khỏi giỏ hàng thành công" });
  });



  // 404 fallback
  app.use((req, res) => {
    res.status(404).json({ success: false, message: "Not found" });
  });

  app.listen(PORT, () => {
    // console.log(`http://localhost:${PORT}`);
  });
