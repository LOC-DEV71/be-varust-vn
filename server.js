  const express = require("express");
  const cors = require("cors");
  const bcrypt = require("bcrypt");
  const jwt = require("jsonwebtoken");
  const path = require("path");
  const multer = require("multer");
  const db = require("./dataBase/db");
  const fs = require("fs");
  require("dotenv").config();

  const app = express();
  const PORT = process.env.PORT || 3000;
  const SECRET_KEY = process.env.SECRET_KEY || "mysecretkey";

  // ================== Middleware ==================
  app.use(cors());
  app.use(express.json());
  app.use("/uploads", express.static(path.join(__dirname, "uploads"))); // phục vụ file ảnh tĩnh

  // Cấu hình multer
  const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, "uploads/"),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)),
  });
  const upload = multer({ storage });

  // Xác thực token
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

  // Xác thực admin
  function verifyAdmin(req, res, next) {
    verifyToken(req, res, () => {
      if (req.user.role !== "admin") {
        return res.status(403).json({ message: "Không có quyền admin" });
      }
      next();
    });
  }

  // ================== Tạo admin mặc định ==================
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
        await db.execute(
          "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
          [ADMIN_USERNAME, ADMIN_EMAIL, hashed, "admin"]
        );
        console.log("✅ Admin mặc định đã được tạo");
      } else {
        console.log("ℹ️ Admin đã tồn tại.");
      }
    } catch (err) {
      console.error("❌ Lỗi tạo admin mặc định:", err.message);
    }
  })();

  // ================== Routes ==================

  // Ping test
  app.get("/health", (_, res) => res.send("OK"));

  // -------- USERS --------
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

  app.delete("/users/:id", verifyAdmin, async (req, res) => {
    try {
      await db.execute("DELETE FROM users WHERE id=?", [req.params.id]);
      res.json({ success: true, message: "Xóa user thành công" });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  });

  // -------- AUTH --------
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
      res.status(500).json({ success: false, message: "Server error" });
    }
  });

  app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ success: false, message: "Cần username và password" });

    try {
      const [rows] = await db.execute(
        "SELECT id, username, password, role FROM users WHERE username = ?",
        [username]
      );
      if (rows.length === 0)
        return res.status(401).json({ success: false, message: "User not found" });

      const user = rows[0];
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch)
        return res.status(401).json({ success: false, message: "Sai mật khẩu" });

      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        SECRET_KEY,
        { expiresIn: "1h" }
      );

      res.json({ success: true, message: "Login thành công", token, role: user.role });
    } catch (err) {
      res.status(500).json({ success: false, message: "Server error" });
    }
  });

  // -------- PRODUCTS (có upload nhiều ảnh) --------
app.get("/products", async (req, res) => {
  try {
    const [rows] = await db.execute("SELECT * FROM products ORDER BY id DESC");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Tạo sản phẩm
app.post(
  "/products",
  verifyAdmin,
  upload.fields([
    { name: "image", maxCount: 1 },
    { name: "images1", maxCount: 1 },
    { name: "images2", maxCount: 1 },
    { name: "images3", maxCount: 1 },
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
        nhucausudung,
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
          sale || 0,
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
          nhucausudung,
        ]
      );

      res.json({ success: true, message: "Thêm sản phẩm thành công" });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
      console.log("Lỗi thêm sản phẩm", err)
    }
  }
);

// Cập nhật sản phẩm
app.put(
  "/products/:id",
  verifyAdmin,
  upload.fields([
    { name: "image", maxCount: 1 },
    { name: "images1", maxCount: 1 },
    { name: "images2", maxCount: 1 },
    { name: "images3", maxCount: 1 },
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
        nhucausudung,
      } = req.body;

      let query = `UPDATE products 
                   SET title=?, price=?, quantity=?, sale=?, description=?, category=?, hang=?, kieumanhinh=?, kichthuoc=?, tamnen=?, tansoquet=?, dophangiai=?, nhucausudung=?`;
      let values = [
        title,
        price,
        quantity,
        sale || 0,
        description,
        category,
        hang,
        kieumanhinh,
        kichthuoc,
        tamnen,
        tansoquet,
        dophangiai,
        nhucausudung,
      ];

      if (req.files["image"]) {
        query += ", image=?";
        values.push(`/uploads/${req.files["image"][0].filename}`);
      }
      if (req.files["images1"]) {
        query += ", images1=?";
        values.push(`/uploads/${req.files["images1"][0].filename}`);
      }
      if (req.files["images2"]) {
        query += ", images2=?";
        values.push(`/uploads/${req.files["images2"][0].filename}`);
      }
      if (req.files["images3"]) {
        query += ", images3=?";
        values.push(`/uploads/${req.files["images3"][0].filename}`);
      }

      query += " WHERE id=?";
      values.push(req.params.id);

      await db.execute(query, values);
      res.json({ success: true, message: "Cập nhật sản phẩm thành công" });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  }
);

// Xóa sản phẩm
app.delete("/products/:id", verifyAdmin, async (req, res) => {
  try {
    // Lấy ảnh cũ ra từ DB
    const [rows] = await db.execute(
      "SELECT image, images1, images2, images3 FROM products WHERE id=?",
      [req.params.id]
    );

    if (rows.length > 0) {
      const product = rows[0];
      [product.image, product.images1, product.images2, product.images3].forEach((img) => {
        if (img) {
          const filePath = path.join(__dirname, img);
          fs.unlink(filePath, (err) => {
            if (err) console.warn("Không tìm thấy file:", filePath);
          });
        }
      });
    }

    // Xoá record trong DB
    await db.execute("DELETE FROM products WHERE id=?", [req.params.id]);
    res.json({ success: true, message: "Xóa sản phẩm thành công" });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});



  // -------- NEWS --------
  app.get("/news", async (req, res) => {
    const [rows] = await db.execute("SELECT * FROM news ORDER BY id DESC");
    res.json(rows);
  });

  app.post("/news", verifyAdmin, async (req, res) => {
    const { title, content, image } = req.body;
    await db.execute(
      "INSERT INTO news (title, content, image) VALUES (?, ?, ?)",
      [title, content, image]
    );
    res.json({ success: true, message: "Thêm tin tức thành công" });
  });

  app.put("/news/:id", verifyAdmin, async (req, res) => {
    const { title, content, image } = req.body;
    await db.execute(
      "UPDATE news SET title=?, content=?, image=? WHERE id=?",
      [title, content, image, req.params.id]
    );
    res.json({ success: true, message: "Cập nhật tin tức thành công" });
  });

  app.delete("/news/:id", verifyAdmin, async (req, res) => {
    await db.execute("DELETE FROM news WHERE id=?", [req.params.id]);
    res.json({ success: true, message: "Xóa tin tức thành công" });
  });

  // =================== CART APIs ===================

// 1. Add to Cart
app.post("/cart", async (req, res) => {
  const { user_id, product_id, quantity } = req.body;

  try {
    // Kiểm tra sản phẩm đã có trong giỏ hàng chưa
    const [rows] = await db.execute(
      "SELECT id, quantity FROM carts WHERE user_id=? AND product_id=? AND status='false'",
      [user_id, product_id]
    );

    if (rows.length > 0) {
      // Nếu có thì cộng dồn số lượng
      const newQuantity = rows[0].quantity + quantity;
      await db.execute(
        "UPDATE carts SET quantity=? WHERE id=?",
        [newQuantity, rows[0].id]
      );
      return res.json({ success: true, message: "Cập nhật số lượng giỏ hàng" });
    } else {
      // Nếu chưa có thì thêm mới
      await db.execute(
        "INSERT INTO carts (user_id, product_id, quantity) VALUES (?, ?, ?)",
        [user_id, product_id, quantity]
      );
      return res.json({ success: true, message: "Đã thêm vào giỏ hàng" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Lỗi server" });
  }
});

// 2. Get Cart by User
app.get("/cart/:userId", async (req, res) => {
  const { userId } = req.params;

  try {
    const [rows] = await db.execute(
      `SELECT 
          c.id AS cart_id,
          c.user_id,
          c.product_id,
          c.quantity,
          c.status,
          c.created_at,
          p.title,
          p.price,
          p.image
       FROM carts c
       JOIN products p ON c.product_id = p.id
       WHERE c.user_id = ?`,
      [userId]
    );

    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Lỗi server" });
  }
});

// 3. Update Cart Item (quantity, status, ...)
app.put("/cart/:id", async (req, res) => {
  const { id } = req.params;
  const { quantity, status } = req.body;

  try {
    let query = "UPDATE carts SET ";
    const params = [];
    
    if (quantity !== undefined) {
      query += "quantity=?, ";
      params.push(quantity);
    }

    if (status !== undefined) {
      query += "status=?, ";
      params.push(status);
    }

    // Xóa dấu "," cuối cùng
    query = query.slice(0, -2); 
    query += " WHERE id=?";
    params.push(id);

    await db.execute(query, params);
    res.json({ success: true, message: "Cập nhật giỏ hàng thành công" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Lỗi server" });
  }
});

// 4. Delete Cart Item
app.delete("/cart/:id", async (req, res) => {
  const { id } = req.params;

  try {
    await db.execute("DELETE FROM carts WHERE id=?", [id]);
    res.json({ success: true, message: "Xóa sản phẩm khỏi giỏ hàng thành công" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Lỗi server" });
  }
});


// =================== ORDERS APIs ===================

// Lấy tất cả đơn hàng (admin)
app.get("/orders", verifyAdmin, async (req, res) => {
  try {
    const [rows] = await db.execute("SELECT * FROM orders ORDER BY id DESC");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Lấy đơn hàng theo user (user tự xem đơn của mình)
app.get("/orders/user/:userId", verifyToken, async (req, res) => {
  try {
    const [rows] = await db.execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC", [
      req.params.userId,
    ]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Đặt hàng từ giỏ hàng
app.post("/orders", verifyToken, async (req, res) => {
  const { receiver_name, phone, address } = req.body;
  const userId = req.user.id;

  try {
    // Lấy giỏ hàng chưa checkout
    const [cartItems] = await db.execute(
      `SELECT c.*, p.price 
       FROM carts c 
       JOIN products p ON c.product_id = p.id 
       WHERE c.user_id=? AND c.status='false'`,
      [userId]
    );

    if (cartItems.length === 0) {
      return res.status(400).json({ success: false, message: "Giỏ hàng trống" });
    }

    // Tính tổng
    const total = cartItems.reduce((sum, item) => sum + item.price * item.quantity, 0);

    // Tạo order
    const [orderResult] = await db.execute(
      "INSERT INTO orders (user_id, receiver_name, phone, address, total, status) VALUES (?, ?, ?, ?, ?, 'pending')",
      [userId, receiver_name, phone, address, total]
    );

    const orderId = orderResult.insertId;

    // Thêm order_items
    for (let item of cartItems) {
      await db.execute(
        "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)",
        [orderId, item.product_id, item.quantity, item.price]
      );
    }

    // Update status giỏ hàng -> true
    await db.execute("UPDATE carts SET status='true' WHERE user_id=?", [userId]);

    res.json({ success: true, message: "Đặt hàng thành công", order_id: orderId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Lỗi server" });
  }
});

// Cập nhật trạng thái đơn hàng (admin)
app.put("/orders/:id", verifyAdmin, async (req, res) => {
  const { status } = req.body;
  try {
    await db.execute("UPDATE orders SET status=? WHERE id=?", [status, req.params.id]);
    res.json({ success: true, message: "Cập nhật trạng thái đơn hàng thành công" });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Xoá đơn hàng (admin)
app.delete("/orders/:id", verifyAdmin, async (req, res) => {
  try {
    await db.execute("DELETE FROM order_items WHERE order_id=?", [req.params.id]);
    await db.execute("DELETE FROM orders WHERE id=?", [req.params.id]);
    res.json({ success: true, message: "Xóa đơn hàng thành công" });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Xem chi tiết items trong đơn
app.get("/order-items/:orderId", verifyToken, async (req, res) => {
  try {
    const [rows] = await db.execute(
      `SELECT oi.*, p.title, p.image 
       FROM order_items oi
       JOIN products p ON oi.product_id = p.id
       WHERE oi.order_id=?`,
      [req.params.orderId]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});



  // ================== 404 fallback ==================
  app.use((req, res) => {
    res.status(404).json({ success: false, message: "Not found" });
  });

  // ================== Server start ==================
  app.listen(PORT, () => {
    console.log(`🚀 Server chạy tại http://localhost:${PORT}`);
  });
