import express from "express";
import AuthValidator from "@/validators/auth_validator.js";
import AuthController from "@/controllers/auth_controller.js";
import { rateLimiterMiddleware } from "@/middlewares/rate_limiter_middleware.js";
import Config from "@/config/config.js";

const AuthRouter = express.Router();

// Register new user
AuthRouter.post("/register", AuthValidator.register, AuthController.register);

// Login user
AuthRouter.post("/login", AuthValidator.login, AuthController.login);

// resend ;
AuthRouter.post(
  "/resend-send-verification",
  AuthValidator.resend,
  AuthController.resend
);

// Logout user from the application
AuthRouter.get("/logout", AuthController.logout);

// Get new access token using refresh token
AuthRouter.get("/refresh-token", AuthController.refreshToken);

// Verify user's email address using the verification link sent in the email
AuthRouter.post(
  "/verify-verification-link",
  AuthValidator.verify,
  AuthController.verify
);

// Forgot password - send OTP to user's registered email address
AuthRouter.post(
  "/forgot-password-send-otp",
  rateLimiterMiddleware(
    Config.MAX_REQUEST_OTP,
    Config.WINDOW_SECONDS_OTP,
    Config.BLOCKED_FOR_SECONDS_OTP,
    "Auth"
  ),
  AuthValidator.forgotPasswordSendOtp,
  AuthController.forgotPasswordSendOtp
);

// Verify OTP sent to user's registered email address to reset password
AuthRouter.post(
  "/forgot-password-verify-otp",
  rateLimiterMiddleware(
    Config.MAX_REQUEST_OTP,
    Config.WINDOW_SECONDS_OTP,
    Config.BLOCKED_FOR_SECONDS_OTP,
    "Auth"
  ),
  AuthValidator.forgotPasswordVerifyOtp,
  AuthController.forgotPasswordVerifyOtp
);

export default AuthRouter;
