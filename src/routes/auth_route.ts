import express from "express";
import AuthValidator from "@/validators/auth_validator.js";
import AuthController from "@/controllers/auth_controller.js";
import { rateLimiterMiddleware } from "@/middlewares/rate_limiter_middleware.js";
import Config from "@/config/config.js";
import AuthMiddleware from "@/middlewares/auth_middleware";
import { uploadMiddleware } from "@/middlewares/file_upload_middleware";

const AuthRouter = express.Router();

AuthRouter.post(
  "/register",
  rateLimiterMiddleware(
    Config.MAX_REQUEST_ROUTES,
    Config.WINDOW_SECONDS_ROUTES,
    Config.BLOCKED_FOR_SECONDS_ROUTES,
    "Auth"
  ),
  AuthValidator.register,
  AuthController.register
);

AuthRouter.post(
  "/login",
  rateLimiterMiddleware(
    Config.MAX_REQUEST_ROUTES,
    Config.WINDOW_SECONDS_ROUTES,
    Config.BLOCKED_FOR_SECONDS_ROUTES,
    "Auth"
  ),
  AuthValidator.login,
  AuthController.login
);

AuthRouter.post(
  "/resend",
  rateLimiterMiddleware(
    Config.MAX_REQUEST_ROUTES,
    Config.WINDOW_SECONDS_ROUTES,
    Config.BLOCKED_FOR_SECONDS_ROUTES,
    "Auth"
  ),
  AuthValidator.resend,
  AuthController.resend
);

AuthRouter.post(
  "/verify",
  rateLimiterMiddleware(
    Config.MAX_REQUEST_ROUTES,
    Config.WINDOW_SECONDS_ROUTES,
    Config.BLOCKED_FOR_SECONDS_ROUTES,
    "Auth"
  ),
  AuthValidator.verify,
  AuthController.verify
);

AuthRouter.get("/refresh-token", AuthController.refreshToken);

AuthRouter.get("/logout", AuthController.logout);

AuthRouter.post(
  "/forgot-password",
  rateLimiterMiddleware(
    Config.MAX_REQUEST_ROUTES,
    Config.WINDOW_SECONDS_ROUTES,
    Config.BLOCKED_FOR_SECONDS_ROUTES,
    "Auth"
  ),
  AuthValidator.forgotPassword,
  AuthController.forgotPassword
);

// Verify OTP sent to user's registered email address to reset password
AuthRouter.post(
  "/forgot-password-verify",
  rateLimiterMiddleware(
    Config.MAX_REQUEST_ROUTES,
    Config.WINDOW_SECONDS_ROUTES,
    Config.BLOCKED_FOR_SECONDS_ROUTES,
    "Auth"
  ),
  AuthValidator.forgotPasswordVerify,
  AuthController.forgotPasswordVerify
);

AuthRouter.get("/me", AuthMiddleware.middleware, AuthController.getCurrentUser);

AuthRouter.put(
  "/me",
  AuthMiddleware.middleware,
  uploadMiddleware.single("avatar"),
  AuthValidator.updateUser,
  AuthController.updateCurrentUser
);

export default AuthRouter;
