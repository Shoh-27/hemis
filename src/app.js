require("dotenv").config();

const express = require("express");
const cookieParser = require("cookie-parser");

const connectDB = require("./config/db");
const authRoutes = require("./modules/auth/auth.routes");
const authMiddleware = require("./middlewares/auth.middleware");
const roleMiddleware = require("./middlewares/role.middleware");
const authController = require("./modules/auth/auth.controller");

const app = express();

// ─── Connect to Database ───────────────────────────────────────────────────────
connectDB();

// ─── Core Middleware ───────────────────────────────────────────────────────────
app.use(express.json({ limit: "10kb" })); // Prevent large payload attacks
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser(process.env.COOKIE_SECRET));

// Security headers (lightweight; use helmet in production)
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  next();
});

// ─── Routes ───────────────────────────────────────────────────────────────────

// Auth routes (public + protected auth endpoints)
app.use("/api/auth", authRoutes);

// Current user profile — any authenticated user
app.get("/api/me", authMiddleware, authController.getMe);

// Admin-only route example
app.get(
  "/api/admin-only",
  authMiddleware,
  roleMiddleware(["admin"]),
  (req, res) => {
    res.json({
      success: true,
      message: "Welcome, Admin! This is a restricted area.",
      data: { user: req.user.toPublicProfile() },
    });
  }
);

// Teacher + Admin route example
app.get(
  "/api/staff",
  authMiddleware,
  roleMiddleware(["admin", "teacher"]),
  (req, res) => {
    res.json({
      success: true,
      message: "Welcome, staff member!",
      data: { user: req.user.toPublicProfile() },
    });
  }
);

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    status: "ok",
    environment: process.env.NODE_ENV,
    timestamp: new Date().toISOString(),
  });
});

// ─── 404 Handler ──────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.method} ${req.originalUrl} not found`,
  });
});

// ─── Centralized Error Handler ────────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  const isDev = process.env.NODE_ENV === "development";

  // Mongoose duplicate key error
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    return res.status(409).json({
      success: false,
      message: `An account with this ${field} already exists`,
    });
  }

  // Mongoose validation error
  if (err.name === "ValidationError") {
    const errors = Object.values(err.errors).map((e) => ({
      field: e.path,
      message: e.message,
    }));
    return res.status(422).json({
      success: false,
      message: "Validation failed",
      errors,
    });
  }

  // Mongoose CastError (invalid ObjectId)
  if (err.name === "CastError") {
    return res.status(400).json({
      success: false,
      message: `Invalid value for field: ${err.path}`,
    });
  }

  const statusCode = err.statusCode || 500;
  const message =
    statusCode === 500 && !isDev
      ? "An unexpected error occurred. Please try again later."
      : err.message;

  res.status(statusCode).json({
    success: false,
    message,
    ...(isDev && { stack: err.stack }),
  });
});

// ─── Start Server ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 HEMIS Auth API running on port ${PORT} [${process.env.NODE_ENV}]`);
});

module.exports = app;
