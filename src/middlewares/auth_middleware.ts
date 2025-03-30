import { Request, Response, NextFunction } from "express";
import TokenService from "@/services/token_services";
import Config from "@/config/config";
import {
  ERROR_RESPONSE_CODE,
  ERROR_RESPONSE_MESSAGE,
  USER_STATUS,
} from "@/utils/constants";
import ErrorResponse, {
  createAccountStatusErrorResponse,
} from "@/utils/response-classes.ts/error-response";
import mongoose from "mongoose";
import { logger } from "@/utils/logger/logger";

class AuthMiddleware {
  public static async middleware(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    try {
      const accessToken =
        req.cookies?.[Config.ACCESS_TOKEN_KEY] ??
        req.headers.authorization?.split(" ")[1];

      if (!accessToken) {
        throw new Error(ERROR_RESPONSE_MESSAGE.INVALID_ACCESS_TOKEN_MESSAGE);
      }

      // Verify the token using tokenService
      const user = await TokenService.verifyAccessToken(accessToken);
      if (
        !user ||
        typeof user === "string" ||
        !user._id ||
        mongoose.Types.ObjectId.isValid(user._id) === false
      ) {
        throw new Error(ERROR_RESPONSE_MESSAGE.INVALID_ACCESS_TOKEN_MESSAGE);
      }

      // Check if user is blocked or deleted
      if (
        user.status === USER_STATUS.ACTIVE ||
        user.status === USER_STATUS.DELETED
      ) {
        return res
          .status(401)
          .json(createAccountStatusErrorResponse(user.status));
      }

      // Check if user is verified or not
      if (!user.isEmailVerified) {
        return res.status(401).json(
          new ErrorResponse({
            code: ERROR_RESPONSE_CODE.UNVERIFIED_USER,
            message: ERROR_RESPONSE_MESSAGE.UNVERIFIED_USER_MESSAGE,
          })
        );
      }

      req._id = user._id;

      next();
    } catch (error) {
      logger.error(error);
      return res.status(401).json(
        new ErrorResponse({
          code: ERROR_RESPONSE_CODE.INVALID_TOKEN,
          message: ERROR_RESPONSE_MESSAGE.INVALID_ACCESS_TOKEN_MESSAGE,
        })
      );
    }
  }
}

export default AuthMiddleware;
