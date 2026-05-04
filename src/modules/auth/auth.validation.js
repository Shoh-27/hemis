const Joi = require("joi");

const passwordSchema = Joi.string()
  .min(8)
  .max(128)
  .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
  .message(
    "Password must be at least 8 characters and include uppercase, lowercase, and a number"
  );

const registerSchema = Joi.object({
  name: Joi.string().trim().min(2).max(100).required().messages({
    "string.min": "Name must be at least 2 characters",
    "string.max": "Name must not exceed 100 characters",
    "any.required": "Name is required",
  }),
  email: Joi.string().email({ tlds: { allow: false } }).lowercase().required().messages({
    "string.email": "Please provide a valid email address",
    "any.required": "Email is required",
  }),
  password: passwordSchema.required().messages({
    "any.required": "Password is required",
  }),
  role: Joi.string().valid("student", "teacher", "admin").default("student").messages({
    "any.only": "Role must be one of: student, teacher, admin",
  }),
});

const loginSchema = Joi.object({
  email: Joi.string().email({ tlds: { allow: false } }).lowercase().required().messages({
    "string.email": "Please provide a valid email address",
    "any.required": "Email is required",
  }),
  password: Joi.string().required().messages({
    "any.required": "Password is required",
  }),
});

/**
 * Middleware factory for validating request body against a Joi schema
 */
const validate = (schema) => (req, res, next) => {
  const { error, value } = schema.validate(req.body, {
    abortEarly: false,      // Collect all errors, not just the first
    stripUnknown: true,     // Remove fields not in schema
    convert: true,
  });

  if (error) {
    const errors = error.details.map((d) => ({
      field: d.path.join("."),
      message: d.message,
    }));
    return res.status(422).json({
      success: false,
      message: "Validation failed",
      errors,
    });
  }

  req.body = value; // Replace body with sanitized/coerced values
  next();
};

module.exports = {
  validateRegister: validate(registerSchema),
  validateLogin: validate(loginSchema),
};
