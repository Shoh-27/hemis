const User = require("../user/user.model");
const {
  generateTokenPair,
  verifyRefreshToken,
  hashValue,
} = require("../../utils/token");
const { hashValue: hashToken } = require("../../utils/hash");

/**
 * Register a new user
 */
const register = async ({ name, email, password, role }) => {
  // Check for existing user
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    const err = new Error("An account with this email already exists");
    err.statusCode = 409;
    throw err;
  }

  // Create user — password hashed by pre-save hook
  const user = await User.create({ name, email, password, role });

  // Generate tokens
  const tokens = generateTokenPair(user);

  // Store hashed refresh token (never store plain tokens in DB)
  user.refreshToken = await hashToken(tokens.refreshToken);
  await user.save({ validateBeforeSave: false });

  return { user: user.toPublicProfile(), tokens };
};

