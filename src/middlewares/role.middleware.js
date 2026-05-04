/**
 * Role-based access control middleware factory.
 *
 * Usage:
 *   router.get('/admin-only', authMiddleware, roleMiddleware(['admin']), handler)
 *   router.get('/staff', authMiddleware, roleMiddleware(['admin', 'teacher']), handler)
 *
 * Must be used AFTER authMiddleware (requires req.user).
 *
 * @param {string[]} allowedRoles - Array of roles permitted to access the route
 */
const roleMiddleware = (allowedRoles) => {
  if (!Array.isArray(allowedRoles) || allowedRoles.length === 0) {
    throw new Error("roleMiddleware requires a non-empty array of roles");
  }

  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: `Access denied. Required role(s): ${allowedRoles.join(", ")}. Your role: ${req.user.role}.`,
      });
    }

    next();
  };
};

module.exports = roleMiddleware;
