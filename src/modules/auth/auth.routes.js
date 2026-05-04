const express = require("express");
const router = express.Router();

const authController = require("./auth.controller");
const { validateRegister, validateLogin } = require("./auth.validation");
const authMiddleware = require("../../middlewares/auth.middleware");

// Public routes
router.post("/register", validateRegister, authController.register);
router.post("/login",    validateLogin,    authController.login);
router.post("/refresh",                    authController.refresh);

// Protected — requires valid access token to logout cleanly
router.post("/logout", authMiddleware, authController.logout);

// Convenience: current user info (can also live in /api/me)
router.get("/me", authMiddleware, authController.getMe);

module.exports = router;
