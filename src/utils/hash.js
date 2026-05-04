const bcrypt = require("bcryptjs");

const SALT_ROUNDS = 12;

/**
 * Hash a plain text string
 */
const hashValue = async (value) => {
  const salt = await bcrypt.genSalt(SALT_ROUNDS);
  return bcrypt.hash(value, salt);
};

/**
 * Compare a plain text value to a hash
 */
const compareHash = async (value, hash) => {
  return bcrypt.compare(value, hash);
};

module.exports = { hashValue, compareHash };
