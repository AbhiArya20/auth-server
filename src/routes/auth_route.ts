import express from "express";
import AuthValidator from "@/validators/auth_validator.js";
import AuthController from "@/controllers/auth_controller.js";
import { rateLimiterMiddleware } from "@/middlewares/rate_limiter_middleware.js";
import Config from "@/config/config.js";
import AuthMiddleware from "@/middlewares/auth_middleware";
import { uploadMiddleware } from "@/middlewares/file_upload_middleware";

const AuthRouter = express.Router();

const rateLimiter = rateLimiterMiddleware(
  Config.MAX_REQUEST_ROUTES,
  Config.WINDOW_SECONDS_ROUTES,
  Config.BLOCKED_FOR_SECONDS_ROUTES,
  "Auth"
);

AuthRouter.post(
  "/register",
  rateLimiter,
  AuthValidator.register,
  AuthController.register
);

AuthRouter.post(
  "/login",
  rateLimiter,
  AuthValidator.login,
  AuthController.login
);

AuthRouter.post(
  "/resend",
  rateLimiter,
  AuthValidator.resend,
  AuthController.resend
);

AuthRouter.post(
  "/verify",
  rateLimiter,
  AuthValidator.verify,
  AuthController.verify
);

AuthRouter.get("/refresh-token", AuthController.refreshToken);

AuthRouter.get("/logout", AuthController.logout);

AuthRouter.post(
  "/forgot-password",
  rateLimiter,
  AuthValidator.forgotPassword,
  AuthController.forgotPassword
);

AuthRouter.post(
  "/forgot-password-verify",
  rateLimiter,
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
