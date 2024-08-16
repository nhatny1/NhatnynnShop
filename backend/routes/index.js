var express = require("express");
var router = express.Router();

//Imort model
const connectDb = require("../model/db");
const { ObjectId } = require("mongodb");

//Lấy tất cả sản phẩm dạng json
router.get("/pro", async (req, res, next) => {
  const db = await connectDb();
  const productCollection = db.collection("products");
  const products = await productCollection.find().toArray();
  if (products) {
    res.status(200).json(products);
  } else {
    res.status(404).json({ message: "Không tìm thấy" });
  }
});
//Lấy danh sách sản phẩm theo idcate
router.get("/productbycate/:idcate", async (req, res, next) => {
  const db = await connectDb();
  const productCollection = db.collection("products");
  const products = await productCollection
    .find({ "category.categoryName": req.params.idcate })
    .toArray();
  if (products) {
    res.status(200).json(products);
  } else {
    res.status(404).json({ message: "Không tìm thấy" });
  }
});

//Tìm kiếm theo sản phẩm
router.get("/search/:keyword", async (req, res, next) => {
  const db = await connectDb();
  const productCollection = db.collection("products");
  const products = await productCollection
    .find({ name: new RegExp(req.params.keyword, "i") })
    .toArray();
  if (products) {
    res.status(200).json(products);
  } else {
    res.status(404).json({ message: "Không tìm thấy" });
  }
});

//lấy chi tiết 1 sản phẩm
router.get("/productdetail/:id", async (req, res, next) => {
  let id = new ObjectId(req.params.id);
  const db = await connectDb();
  const productCollection = db.collection("products");
  const product = await productCollection.findOne({ _id: id });
  if (product) {
    res.status(200).json(product);
  } else {
    res.status(404).json({ message: "Không tìm thấy" });
  }
});

//Đăng ký tài khoản với mã hóa mật khẩu bcrypt
const bcrypt = require("bcryptjs");
router.post("/register", async (req, res, next) => {
  const db = await connectDb();
  const userCollection = db.collection("users");
  const { email, password } = req.body;
  const user = await userCollection.findOne({ email });
  if (user) {
    return res.status(400).json({ message: "Email đã tồn tại" });
  } else {
    const hashPassword = await bcrypt.hash(password, 10);
    const newUser = { email, password: hashPassword, role: "user" };
    try {
      const result = await userCollection.insertOne(newUser);
      if (result.insertedId) {
        res.status(200).json({ message: "Đăng ký thành công" });
      } else {
        res.status(500).json({ message: "Đăng ký thất bại" });
      }
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Có lỗi xảy ra, vui lòng thử lại" });
    }
  }
});
// Đăng ký tài khoản admin với thông tin cụ thể
router.post("/registerAdminSpecific", async (req, res, next) => {
  const db = await connectDb();
  const userCollection = db.collection("users");
  const email = "lamminhvy82@gmail.com";
  const password = "ny12345";
  const user = await userCollection.findOne({ email });
  if (user) {
    return res.status(400).json({ message: "Email đã tồn tại" });
  } else {
    const hashPassword = await bcrypt.hash(password, 10);
    const newUser = { email, password: hashPassword, role: "admin" };
    try {
      const result = await userCollection.insertOne(newUser);
      if (result.insertedId) {
        res.status(200).json({ message: "Đăng ký admin thành công" });
      } else {
        res.status(500).json({ message: "Đăng ký thất bại" });
      }
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Có lỗi xảy ra, vui lòng thử lại" });
    }
  }
});

const jwt = require("jsonwebtoken");
router.post("/login", async (req, res, next) => {
  const db = await connectDb();
  const userCollection = db.collection("users");
  const { email, password } = req.body;
  const user = await userCollection.findOne({ email });
  if (!user) {
    return res.status(404).json({ message: "Email không tồn tại" });
  }
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.status(400).json({ message: "Mật khẩu không chính xác" });
  }
  const token = jwt.sign({ email: user.email, role: user.role }, "secret", {
    expiresIn: "1h",
  });
  res.status(200).json({ token });
});

router.post("/loginAdmin", async (req, res, next) => {
  const db = await connectDb();
  const userCollection = db.collection("users");
  const { email, password } = req.body;
  const user = await userCollection.findOne({ email });
  if (!user) {
    return res.status(404).json({ message: "Email không tồn tại" });
  }
  if (user.role !== "admin") {
    return res.status(403).json({ message: "Bạn không có quyền truy cập" });
  }
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.status(400).json({ message: "Mật khẩu không chính xác" });
  }
  const token = jwt.sign({ email: user.email, role: user.role }, "secret", {
    expiresIn: "1h",
  });
  res.status(200).json({ token });
});

//Kiểm tra token qua Bearer
router.get("/checktoken", async (req, res, next) => {
  const token = req.headers.authorization.split(" ")[1];
  jwt.verify(token, "secret", (err, user) => {
    if (err) {
      return res.status(401).json({ message: "Token không hợp lệ" });
    }
    res.status(200).json({ message: "Token hợp lệ" });
  });
});


//lấy thông tin chi tiết user qua token
router.get("/detailuser", async (req, res, next) => {
  const token = req.headers.authorization.split(" ")[1];
  jwt.verify(token, "secret", async (err, user) => {
    if (err) {
      return res.status(401).json({ message: "Token không hợp lệ" });
    }
    const db = await connectDb();
    const userCollection = db.collection("users");
    const userInfo = await userCollection.findOne({ email: user.email });
    if (userInfo) {
      res.status(200).json(userInfo);
    } else {
      res.status(404).json({ message: "Không tìm thấy user" });
    }
  });
});

//Xóa người dùng
router.delete("/deletuer/:id", async (req, res, next) => {
  const db = await connectDb();
  const userCollection = db.collection("users");
  const id = new ObjectId(req.params.id);
  try {
    const result = await userCollection.deleteOne({ _id: id });
    if (result.deletedCount) {
      res.status(200).json({ message: "Xóa người dùng thành công" });
    } else {
      res.status(404).json({ message: "Không tìm thấy người dùng" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Có lỗi xảy ra, vui lòng thử lại" });
  }
});

//admin
//Lấy danh mục sản phẩm
router.get("/categories", async (req, res, next) => {
  const db = await connectDb();
  const categoryCollection = db.collection("categories");
  const categories = await categoryCollection.find().toArray();
  if (categories) {
    res.status(200).json(categories);
  } else {
    res.status(404).json({ message: "Không tìm thấy" });
  }
});

const multer = require("multer");
//Thiết lập nơi lưu trữ và tên file
let storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "./public/image");
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  },
});
//Kiểm tra file upload
function checkFileUpLoad(req, file, cb) {
  if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/)) {
    return cb(new Error("Bạn chỉ được upload file ảnh"));
  }
  cb(null, true);
}

//Upload file
let upload = multer({ storage: storage, fileFilter: checkFileUpLoad });

//Thêm sản phẩm
router.post("/addproduct", upload.single("image"), async (req, res, next) => {
  const db = await connectDb();
  const productCollection = db.collection("products");
  const { name, price, description, categoryId } = req.body;
  const image = req.file.originalname;
  const newProduct = { name, price, description, categoryId, image };

  try {
    const result = await productCollection.insertOne(newProduct);
    // Check if insertedId exists (indicates successful insertion)
    if (result.insertedId) {
      res.status(200).json({ message: "Thêm sản phẩm thành công" });
    } else {
      res.status(500).json({ message: "Thêm sản phẩm thất bại" }); // Consider using 500 for unexpected errors
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Có lỗi xảy ra, vui lòng thử lại" }); // Generic error message for user
  }
});

//Xóa sản phẩm
router.delete("/deleteproduct/:id", async (req, res, next) => {
  const db = await connectDb();
  const productCollection = db.collection("products");
  const id = new ObjectId(req.params.id);
  try {
    const result = await productCollection.deleteOne({ _id: id });
    if (result.deletedCount) {
      res.status(200).json({ message: "Xóa sản phẩm thành công" });
    } else {
      res.status(404).json({ message: "Không tìm thấy sản phẩm" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Có lỗi xảy ra, vui lòng thử lại" });
  }
});

//Sửa sản phẩm
router.put(
  "/updateproduct/:id",
  upload.single("image"),
  async (req, res, next) => {
    const db = await connectDb();
    const productCollection = db.collection("products");
    const id = new ObjectId(req.params.id);
    const { name, price, description, categoryId } = req.body;
    let updatedProduct = { name, price, description, categoryId };

    if (req.file) {
      const image = req.file.originalname;
      updatedProduct.image = image; //
    }

    try {
      const result = await productCollection.updateOne(
        { _id: id },
        { $set: updatedProduct }
      );
      if (result.matchedCount) {
        res.status(200).json({ message: "Sửa sản phẩm thành công" });
      } else {
        res.status(404).json({ message: "Không tìm thấy sản phẩm" });
      }
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Có lỗi xảy ra, vui lòng thử lại" });
    }
  }
);
//Thêm danh mục
router.post("/addcate", async (req, res, next) => {
  const db = await connectDb();
  const categoryCollection = db.collection("categories");
  const { name, description } = req.body;
  const newCate = { name, description };

  try {
    const result = await categoryCollection.insertOne(newCate);
    // Check if insertedId exists (indicates successful insertion)
    if (result.insertedId) {
      res.status(200).json({ message: "Thêm danh mục thành công" });
    } else {
      res.status(500).json({ message: "Thêm danh mục thất bại" }); // Consider using 500 for unexpected errors
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Có lỗi xảy ra, vui lòng thử lại" }); // Generic error message for user
  }
});
//Xóa danh mục
router.delete("/deletecate/:id", async (req, res, next) => {
  const db = await connectDb();
  const categoryCollection = db.collection("categories");
  const id = new ObjectId(req.params.id);
  try {
    const result = await categoryCollection.deleteOne({ _id: id });
    if (result.deletedCount) {
      res.status(200).json({ message: "Xóa sản phẩm thành công" });
    } else {
      res.status(404).json({ message: "Không tìm thấy sản phẩm" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Có lỗi xảy ra, vui lòng thử lại" });
  }
});

//Sửa danh mục
router.put("/updatecate/:id"),
  async (req, res, next) => {
    const db = await connectDb();
    const categoriesCollection = db.collection("categories");
    const id = new ObjectId(req.params.id);
    const { name } = req.body;
    let updatedProduct = { name };

    try {
      const result = await categoriesCollection.updateOne(
        { _id: id },
        { $set: updatedProduct }
      );
      if (result.matchedCount) {
        res.status(200).json({ message: "Sửa sản phẩm thành công" });
      } else {
        res.status(404).json({ message: "Không tìm thấy sản phẩm" });
      }
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Có lỗi xảy ra, vui lòng thử lại" });
    }
  };

module.exports = router;
