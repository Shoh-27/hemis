const { verifyAccessToken } = require("../utils/token");
const User = require("../modules/user/user.model");

/**
 * Authenticate requests by verifying the JWT access token.
 * Attaches the full user document to req.user.
 *
 * Accepts token from:
 *   1. Authorization: Bearer <token> header
 *   2. req.query.token (for non-browser clients, e.g. socket upgrades)
 */
const authMiddleware = async (req, res, next) => {
  try {
    let token;

    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.slice(7);
    } else if (req.query?.token) {
      token = req.query.token;
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Access denied. No token provided.",
      });
    }

    let decoded;
    try {
      decoded = verifyAccessToken(token);
    } catch (err) {
      const message =
        err.name === "TokenExpiredError"
          ? "Access token has expired. Please refresh your session."
          : "Invalid access token.";
      return res.status(401).json({ success: false, message });
    }

    const user = await User.findById(decoded.sub);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User associated with this token no longer exists.",
      });
    }

    if (!user.isActive) {
      return res.status(403).json({
        success: false,
        message: "Your account has been deactivated. Contact support.",
      });
    }

    req.user = user;
    next();
  } catch (err) {
    next(err);
  }
};

module.exports = authMiddleware;
