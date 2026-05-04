const authService = require("./auth.service");
const { getRefreshCookieOptions } = require("../../utils/token");

/**
 * POST /api/auth/register
 */
const register = async (req, res, next) => {
  try {
    const { user, tokens } = await authService.register(req.body);

    res.cookie("refreshToken", tokens.refreshToken, getRefreshCookieOptions());

    return res.status(201).json({
      success: true,
      message: "Account created successfully",
      data: {
        user,
        accessToken: tokens.accessToken,
      },
    });
  } catch (err) {
    next(err);
  }
};

/**
 * POST /api/auth/login
 */
const login = async (req, res, next) => {
  try {
    const { user, tokens } = await authService.login(req.body);

    res.cookie("refreshToken", tokens.refreshToken, getRefreshCookieOptions());

    return res.status(200).json({
      success: true,
      message: "Logged in successfully",
      data: {
        user,
        accessToken: tokens.accessToken,
      },
    });
  } catch (err) {
    next(err);
  }
};

