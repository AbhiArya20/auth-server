import { Response, Request, NextFunction } from "express";
import Config from "@/config/config.js";
import TokenService from "@/services/token_services.js";
import UserService from "@/services/user_services.js";
import bcrypt from "bcrypt";
import {
  AUTHENTICATION_METHOD,
  ERROR_RESPONSE_CODE,
  ERROR_RESPONSE_MESSAGE,
  SUCCESS_RESPONSE_CODE,
  SUCCESS_RESPONSE_MESSAGE,
  USER_STATUS,
} from "@/utils/constants.js";
import ErrorResponse, {
  createAccountStatusErrorResponse,
  createInvalidRefreshTokenErrorResponse,
} from "@/utils/response-classes.ts/error-response.js";
import UserDTO from "@/dtos/user_dto.js";
import { SuccessResponse } from "@/utils/response-classes.ts/success-response.js";
import { SendEmailService } from "@/services/email_services.js";
import HashService from "@/services/hash_services.js";
import OtpServices from "@/services/otp_services";
import { IUserSchema } from "@/models/user_model";
import { UAParser } from "ua-parser-js";
import { logger } from "@/utils/logger/logger";
import { isEmailMethod, isMethodForMagicLink } from "@/utils/method";

class AuthController {
  public static async register(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    try {
      // Destructure request body
      const { firstName, lastName, email, phone, password, method } = req.body;

      // Get user from database
      let user = await UserService.findOne({
        ...(email && { email }),
        ...(phone && { phone }),
      });

      // if user is already registered
      if (user) {
        return res.status(400).json(
          new ErrorResponse({
            code: ERROR_RESPONSE_CODE.USER_ALREADY_REGISTERED,
            message: ERROR_RESPONSE_MESSAGE.USER_REGISTERED_MESSAGE,
          })
        );
      }

      // Create new user if user not registered
      user = await UserService.create({
        firstName,
        lastName,
        email,
        phone,
        password,
      });

      // Send token or otp depending on the method, and save verificationToken and verificationTokenExpiresAt in database.
      const { userToken } = await AuthControllerUtility.sendVerificationDetails(
        {
          user,
          method,
          email,
          phone,
        }
      );

      // create DTO and send response
      const formattedUser = new UserDTO(user);
      return res.status(200).json(
        new SuccessResponse({
          data: {
            email,
            phone,
            verificationToken: isMethodForMagicLink(method)
              ? undefined
              : userToken,
            method,
            user: formattedUser,
          },
          code: SUCCESS_RESPONSE_CODE.REGISTRATION_SUCCESS,
          message: SUCCESS_RESPONSE_MESSAGE.REGISTRATION_SUCCESS_MESSAGE,
        })
      );
    } catch (error) {
      logger.error(error);
      next(error);
    }
  }

  public static async login(req: Request, res: Response, next: NextFunction) {
    try {
      // Destructure request body
      const { email, phone, password, remember, method } = req.body;

      // Get user from database
      let user = await UserService.findOne({
        ...(email && { email }),
        ...(phone && { phone }),
      });

      // If email is provided and method is PASSWORD
      if (method === AUTHENTICATION_METHOD.PASSWORD && email) {
        // If user does not exist
        if (!user) {
          return res.status(400).json(
            new ErrorResponse({
              code: ERROR_RESPONSE_CODE.INVALID_CREDENTIALS,
              message: ERROR_RESPONSE_MESSAGE.USER_NOT_REGISTER,
            })
          );
        }

        // If password does not exist in database for the user
        if (!user.password) {
          return res.status(400).json(
            new ErrorResponse({
              code: ERROR_RESPONSE_CODE.PASSWORD_NOT_SET,
              message: ERROR_RESPONSE_MESSAGE.PASSWORD_NOT_SET_MESSAGE,
            })
          );
        }

        // If password does not match
        if (!(await bcrypt.compare(password, user.password))) {
          return res.status(400).json(
            new ErrorResponse({
              code: ERROR_RESPONSE_CODE.INVALID_CREDENTIALS,
              message: ERROR_RESPONSE_MESSAGE.INCORRECT_PASSWORD,
            })
          );
        }

        // If user is blocked or deleted
        const { status, isEmailVerified, isPhoneVerified } = user;
        if (status === USER_STATUS.BLOCKED || status === USER_STATUS.DELETED) {
          return res
            .status(status === USER_STATUS.BLOCKED ? 403 : 404)
            .json(createAccountStatusErrorResponse(status));
        }

        // Create DTO
        const formattedUser = new UserDTO(user);

        // If user is not verified
        if (!isEmailVerified && !isPhoneVerified) {
          await AuthControllerUtility.sendVerificationDetails({
            user,
            method,
            email,
            phone,
          });

          return res.status(200).json(
            new SuccessResponse({
              data: { email, phone, method, user: formattedUser },
              code: ERROR_RESPONSE_CODE.UNVERIFIED_USER,
              message: ERROR_RESPONSE_MESSAGE.UNVERIFIED_USER_MESSAGE,
            })
          );
        }

        // Set cookies and send response
        await AuthControllerUtility.setCookies(
          req,
          res,
          { ...formattedUser },
          remember
        );

        return res.status(200).json(
          new SuccessResponse({
            data: { user: formattedUser },
            code: SUCCESS_RESPONSE_CODE.LOGIN_SUCCESS,
            message: SUCCESS_RESPONSE_MESSAGE.LOGIN_SUCCESS_MESSAGE,
          })
        );
      }

      // Create a new user if not registered
      if (!user) {
        user = await UserService.create({
          email,
          phone,
        });
      }

      // If user is blocked or deleted
      const { status } = user;
      if (status === USER_STATUS.BLOCKED || status === USER_STATUS.DELETED) {
        return res
          .status(status === USER_STATUS.BLOCKED ? 403 : 404)
          .json(createAccountStatusErrorResponse(status));
      }

      // Send token or otp depending on the method, and save verificationToken and verificationTokenExpiresAt in database.
      const { hash } = await AuthControllerUtility.sendVerificationDetails({
        user,
        method,
        email,
        phone,
      });

      // Create DTO and send response
      const formattedUser = new UserDTO(user);
      return res.status(200).json(
        new SuccessResponse({
          data: {
            email,
            phone,
            hash: isMethodForMagicLink(method) ? undefined : hash,
            method,
            user: formattedUser,
          },
          code: isMethodForMagicLink(method)
            ? SUCCESS_RESPONSE_CODE.VERIFICATION_LINK_SEND
            : SUCCESS_RESPONSE_CODE.OTP_SENT,
          message: isMethodForMagicLink(method)
            ? SUCCESS_RESPONSE_MESSAGE.REGISTRATION_SUCCESS_MESSAGE
            : SUCCESS_RESPONSE_MESSAGE.OTP_SENT_MESSAGE,
        })
      );
    } catch (error) {
      logger.error(error);
      next(error);
    }
  }

  public static async resend(req: Request, res: Response, next: NextFunction) {
    try {
      // Destructure request body
      const { email, phone, method } = req.body;

      // Get user from database
      const user = await UserService.findOne({
        ...(email && { email }),
        ...(phone && { phone }),
      });

      // If user is not found
      if (!user) {
        return res.status(404).json(
          new ErrorResponse({
            code: ERROR_RESPONSE_CODE.NOT_FOUND,
            message: ERROR_RESPONSE_MESSAGE.USER_NOT_FOUND_MESSAGE,
          })
        );
      }

      // Create DTO
      const formattedUser = new UserDTO(user);

      // If user is blocked or deleted
      const { status } = formattedUser;
      if (status === USER_STATUS.BLOCKED || status === USER_STATUS.DELETED) {
        return res
          .status(status === USER_STATUS.BLOCKED ? 403 : 404)
          .json(createAccountStatusErrorResponse(status));
      }

      // Send token or otp depending on the method, and save verificationToken and verificationTokenExpiresAt in database.
      const { hash } = await AuthControllerUtility.sendVerificationDetails({
        user,
        method,
        email,
        phone,
      });

      // Create DTO and send response
      return res.status(200).json(
        new SuccessResponse({
          data: {
            email,
            phone,
            hash: isMethodForMagicLink(method) ? undefined : hash,
            method,
            user: formattedUser,
          },
          code: isMethodForMagicLink(method)
            ? SUCCESS_RESPONSE_CODE.VERIFICATION_LINK_SEND
            : SUCCESS_RESPONSE_CODE.OTP_SENT,
          message: isMethodForMagicLink(method)
            ? SUCCESS_RESPONSE_MESSAGE.REGISTRATION_SUCCESS_MESSAGE
            : SUCCESS_RESPONSE_MESSAGE.OTP_SENT_MESSAGE,
        })
      );
    } catch (error) {
      logger.error(error);
      next(error);
    }
  }

  public static async verify(req: Request, res: Response, next: NextFunction) {
    try {
      // Destructure request body
      const { phone, email, method, hash, otp } = req.body;

      // Get user from database
      const user = await UserService.findOne({
        ...(email && { email }),
        ...(phone && { phone }),
      });

      // If user is not found
      if (!user) {
        return res.status(404).json(
          new ErrorResponse({
            code: ERROR_RESPONSE_CODE.USER_NOT_REGISTER,
            message: ERROR_RESPONSE_MESSAGE.USER_REGISTERED_MESSAGE,
          })
        );
      }

      const verificationToken = isEmailMethod(method)
        ? user.emailVerificationToken
        : user.phoneVerificationToken;

      const verificationTokenExpiresAt = isEmailMethod(method)
        ? user.emailVerificationTokenExpiresAt
        : user.phoneVerificationTokenExpiresAt;

      // If verification token or verification token date is not found
      // TODO: Fix error message here
      if (!verificationToken || !verificationTokenExpiresAt) {
        return res.status(400).json(
          new ErrorResponse({
            code: isMethodForMagicLink(method)
              ? ERROR_RESPONSE_CODE.INVALID_LINK
              : ERROR_RESPONSE_CODE.INVALID_OTP,
            message: isMethodForMagicLink(method)
              ? ERROR_RESPONSE_MESSAGE.INVALID_VERIFICATION_LINK_MESSAGE
              : ERROR_RESPONSE_MESSAGE.INVALID_OTP_MESSAGE,
          })
        );
      }

      // If verification token expired
      if (verificationTokenExpiresAt.getTime() < Date.now()) {
        return res.status(400).json(
          new ErrorResponse({
            code: ERROR_RESPONSE_CODE.REQUEST_TIMEOUT,
            message: ERROR_RESPONSE_MESSAGE.EXPIRE_VERIFICATION_LINK_MESSAGE,
          })
        );
      }

      // Re-generate the token and hash from the data given by the user
      const { token: generateToken, hash: generatedHash } =
        await AuthControllerUtility.generateTokenAndHash({
          email,
          phone,
          otp,
          method,
          expireAt: verificationTokenExpiresAt.getTime(),
          userId: user._id.toString(),
        });

      // Generate the hash of the token and the secret
      const backendHash = HashService.hash(
        verificationToken,
        Config.SECONDARY_HASH_SECRET
      );

      if (
        hash !== generatedHash ||
        generateToken !== verificationToken ||
        hash != backendHash
      ) {
        return res.status(400).json(
          // TODO: Fix error message here
          new ErrorResponse({
            code: ERROR_RESPONSE_CODE.INVALID_OTP,
            message: ERROR_RESPONSE_MESSAGE.OTP_INVALID_MESSAGE,
          })
        );
      }

      if (
        method === AUTHENTICATION_METHOD.SMS_OTP ||
        method === AUTHENTICATION_METHOD.WHATSAPP_OTP ||
        method === AUTHENTICATION_METHOD.EMAIL_OTP
      ) {
        const key = user._id.toString() + ":" + method + ":" + otp;
        const isUsed = await OtpServices.isUsed(key);
        if (isUsed) {
          return res.status(406).json(
            new ErrorResponse({
              code: ERROR_RESPONSE_CODE.OTP_USED,
              message: ERROR_RESPONSE_MESSAGE.OTP_USED_MESSAGE,
            })
          );
        }
      }

      const formattedUser = new UserDTO(user);

      // If user is blocked or deleted
      const { status } = formattedUser;
      if (status === USER_STATUS.BLOCKED || status === USER_STATUS.DELETED) {
        return res
          .status(status === USER_STATUS.BLOCKED ? 403 : 404)
          .json(createAccountStatusErrorResponse(status));
      }

      // update verification token and verification token date
      if (email) {
        await UserService.updateById(user._id, {
          emailVerificationToken: null,
          emailVerificationTokenExpiresAt: null,
          isEmailVerified: Date.now(),
        });
      } else {
        await UserService.updateById(user._id, {
          phoneVerificationToken: null,
          phoneVerificationTokenExpiresAt: null,
          isPhoneVerified: Date.now(),
        });
      }

      // Set cookies and send response
      await AuthControllerUtility.setCookies(req, res, { ...formattedUser });

      return res.status(200).json(
        new SuccessResponse({
          data: { user: formattedUser },
          code: SUCCESS_RESPONSE_CODE.VERIFICATION_SUCCESSFUL,
          message: SUCCESS_RESPONSE_MESSAGE.VERIFICATION_SUCCESSFUL_MESSAGE,
        })
      );
    } catch (error) {
      logger.error(error);
      next(error);
    }
  }

  public static async refreshToken(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    try {
      const refreshTokenFromCookie =
        req.cookies[Config.REFRESH_TOKEN_KEY] ??
        req.headers.authorization?.split(" ")[1];
      // Validate refresh token
      let user;
      try {
        user = await TokenService.verifyRefreshToken(refreshTokenFromCookie);
        if (typeof user !== "string" && user._id) {
          const token = await TokenService.removeRefreshToken(
            refreshTokenFromCookie,
            user._id
          );
          if (!token) {
            throw new Error("Token Not Found");
          }
        }
      } catch (error) {
        logger.error(error);
        return res.status(401).json(createInvalidRefreshTokenErrorResponse());
      }

      if (typeof user !== "string" && user.email) {
        // Check user's existence
        user = await UserService.findOne({
          ...(user.email && { email: user.email }),
          ...(user.phone && { phone: user.phone }),
        });

        // user = await UserService.findOne({ email: user.email });
        if (!user) {
          return res.status(401).json(
            new ErrorResponse({
              code: ERROR_RESPONSE_CODE.NOT_FOUND,
              message: ERROR_RESPONSE_MESSAGE.USER_NOT_FOUND_MESSAGE,
            })
          );
        }

        // Check user's status
        const { status } = user;
        if (status === USER_STATUS.BLOCKED || status === USER_STATUS.DELETED) {
          return res.status(401).json(createAccountStatusErrorResponse(status));
        }

        // Create UserDTO
        const formattedUser = new UserDTO(user);

        // Set cookies and Send response
        await AuthControllerUtility.setCookies(req, res, { ...formattedUser });
        return res.status(200).json(
          new SuccessResponse({
            data: { user: formattedUser },
            code: SUCCESS_RESPONSE_CODE.LOGIN_SUCCESS,
            message: SUCCESS_RESPONSE_MESSAGE.LOGIN_SUCCESS_MESSAGE,
          })
        );
      } else {
        return res.status(401).json(createInvalidRefreshTokenErrorResponse());
      }
    } catch (error) {
      logger.error(error);
      next(error);
    }
  }

  public static async forgotPassword(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    try {
      // Check user registered
      const { email, phone, method } = req.body;
      const user = await UserService.findOne({
        ...(email && { email }),
        ...(phone && { phone }),
      });

      if (!user) {
        return res.status(404).json(
          new ErrorResponse({
            code: ERROR_RESPONSE_CODE.NOT_FOUND,
            message: ERROR_RESPONSE_MESSAGE.USER_NOT_FOUND_MESSAGE,
          })
        );
      }

      // Check user's status
      const { status } = user;
      if (status === USER_STATUS.BLOCKED || status === USER_STATUS.DELETED) {
        return res
          .status(status === USER_STATUS.BLOCKED ? 403 : 404)
          .json(createAccountStatusErrorResponse(status));
      }

      // Send token or otp depending on the method, and save verificationToken and verificationTokenExpiresAt in database.
      const { hash } = await AuthControllerUtility.sendVerificationDetails({
        user,
        method,
        email,
        phone,
        forgotPassword: true,
      });

      // create DTO and send response
      const formattedUser = new UserDTO(user);
      return res.status(200).json(
        new SuccessResponse({
          data: {
            email,
            phone,
            hash:
              method === AUTHENTICATION_METHOD.MAGIC_LINK ||
              method === AUTHENTICATION_METHOD.PASSWORD
                ? undefined
                : hash,
            method,
            user: formattedUser,
          },
          // TODO: Fix error message here
          code: SUCCESS_RESPONSE_CODE.REGISTRATION_SUCCESS,
          message: SUCCESS_RESPONSE_MESSAGE.REGISTRATION_SUCCESS_MESSAGE,
        })
      );
    } catch (error) {
      logger.error(error);
      next(error);
    }
  }

  public static async forgotPasswordVerify(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    try {
      // Destructure request body
      const { phone, email, method, hash, otp, newPassword } = req.body;

      // Get user from database
      const user = await UserService.findOne({
        ...(email && { email }),
        ...(phone && { phone }),
      });

      // If user is not found
      if (!user) {
        return res.status(404).json(
          new ErrorResponse({
            code: ERROR_RESPONSE_CODE.USER_NOT_REGISTER,
            message: ERROR_RESPONSE_MESSAGE.USER_REGISTERED_MESSAGE,
          })
        );
      }

      const verificationToken = user.passwordResetToken;
      const verificationTokenExpiresAt = user.passwordResetExpiresAt;

      // If verification token or verification token date is not found
      // TODO: Fix error message here
      if (!verificationToken || !verificationTokenExpiresAt) {
        return res.status(400).json(
          new ErrorResponse({
            code: ERROR_RESPONSE_CODE.INVALID_LINK,
            message: ERROR_RESPONSE_MESSAGE.INVALID_VERIFICATION_LINK_MESSAGE,
          })
        );
      }

      // If verification token expired
      if (verificationTokenExpiresAt.getTime() < Date.now()) {
        return res.status(400).json(
          new ErrorResponse({
            code: ERROR_RESPONSE_CODE.REQUEST_TIMEOUT,
            message: ERROR_RESPONSE_MESSAGE.EXPIRE_VERIFICATION_LINK_MESSAGE,
          })
        );
      }

      const { token: generateToken, hash: generatedHash } =
        await AuthControllerUtility.generateTokenAndHash({
          email,
          phone,
          otp,
          method,
          userId: user._id.toString(),
          expireAt: verificationTokenExpiresAt.getTime(),
        });

      const backendHash = HashService.hash(
        verificationToken,
        Config.SECONDARY_HASH_SECRET
      );

      if (
        hash !== generatedHash ||
        generateToken !== verificationToken ||
        hash != backendHash
      ) {
        return res.status(400).json(
          // TODO: Fix error message here
          new ErrorResponse({
            code: ERROR_RESPONSE_CODE.INVALID_OTP,
            message: ERROR_RESPONSE_MESSAGE.OTP_INVALID_MESSAGE,
          })
        );
      }

      if (
        method === AUTHENTICATION_METHOD.SMS_OTP ||
        method === AUTHENTICATION_METHOD.WHATSAPP_OTP ||
        method === AUTHENTICATION_METHOD.EMAIL_OTP
      ) {
        const key = user._id.toString() + ":" + method + ":" + otp;
        const isUsed = await OtpServices.isUsed(key);
        if (isUsed) {
          return res.status(406).json(
            new ErrorResponse({
              code: ERROR_RESPONSE_CODE.OTP_USED,
              message: ERROR_RESPONSE_MESSAGE.OTP_USED_MESSAGE,
            })
          );
        }
      }

      const formattedUser = new UserDTO(user);

      // If user is blocked or deleted
      const { status } = formattedUser;
      if (status === USER_STATUS.BLOCKED || status === USER_STATUS.DELETED) {
        return res
          .status(status === USER_STATUS.BLOCKED ? 403 : 404)
          .json(createAccountStatusErrorResponse(status));
      }

      // update verification token and verification token date

      await UserService.updateById(user._id, {
        password: newPassword,
        passwordResetToken: null,
        passwordResetExpiresAt: null,
      });

      // Set cookies and send response
      await AuthControllerUtility.setCookies(req, res, { ...formattedUser });

      return res.status(200).json(
        new SuccessResponse({
          data: { user: formattedUser },
          code: SUCCESS_RESPONSE_CODE.VERIFICATION_SUCCESSFUL,
          message: SUCCESS_RESPONSE_MESSAGE.VERIFICATION_SUCCESSFUL_MESSAGE,
        })
      );
    } catch (error) {
      logger.error(error);
      next(error);
    }
  }

  public static async logout(req: Request, res: Response, next: NextFunction) {
    try {
      const refreshToken = req.cookies[Config.REFRESH_TOKEN_KEY];
      await TokenService.removeRefreshToken(refreshToken, req._id!.toString());
      res.clearCookie(Config.ACCESS_TOKEN_KEY);
      res.clearCookie(Config.REFRESH_TOKEN_KEY);
      return res
        .status(200)
        .json(new SuccessResponse({ data: null, code: "", message: "" }));
    } catch (error) {
      logger.error(error);
      next(error);
    }
  }

  public static async getCurrentUser(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    try {
      const user = await UserService.findById(req._id!);
      if (!user) {
        return res.status(404).json(
          new ErrorResponse({
            code: ERROR_RESPONSE_CODE.NOT_FOUND,
            message: ERROR_RESPONSE_MESSAGE.USER_NOT_FOUND_MESSAGE,
          })
        );
      }

      const formattedUser = new UserDTO(user);

      return res.status(200).json(
        new SuccessResponse({
          code: SUCCESS_RESPONSE_CODE.GET_CURRENT_USER_SUCCESS,
          message: SUCCESS_RESPONSE_MESSAGE.GET_CURRENT_USER_SUCCESS_MESSAGE,
          data: { formattedUser },
        })
      );
    } catch (error) {
      logger.error(error);
      next(error);
    }
  }

  public static async updateCurrentUser(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    try {
      const { firstName, lastName, avatar } = req.body;

      const user = await UserService.updateById(req._id!, {
        firstName,
        lastName,
        avatar,
      });
      if (!user) {
        return res.status(404).json(
          new ErrorResponse({
            code: ERROR_RESPONSE_CODE.NOT_FOUND,
            message: ERROR_RESPONSE_CODE.USER_NOT_FOUND_MESSAGE,
          })
        );
      }

      const formattedUser = new UserDTO(user);

      return res.status(200).json(
        new SuccessResponse({
          code: SUCCESS_RESPONSE_CODE.UPDATE_CURRENT_USER_SUCCESS,
          message: SUCCESS_RESPONSE_MESSAGE.UPDATE_CURRENT_USER_SUCCESS_MESSAGE,
          data: { formattedUser },
        })
      );
    } catch (error) {
      logger.error(error);
      next(error);
    }
  }
}

type GenerateTokenAndHashProps = {
  email: string;
  phone: string;
  otp: number;
  method: AUTHENTICATION_METHOD;
  userId: string;
  expireAt: number;
};

type HandleUserVerificationProps = {
  user: IUserSchema;
  method: string;
  email: string;
  phone: string;
  forgotPassword?: boolean;
};

class AuthControllerUtility {
  public static async sendVerificationDetails({
    user,
    method,
    email,
    phone,
    forgotPassword = false,
  }: HandleUserVerificationProps) {
    const otp = await OtpServices.generateOtp();

    // Calculate expire time
    const expireTimeInSeconds =
      method === AUTHENTICATION_METHOD.MAGIC_LINK ||
      method === AUTHENTICATION_METHOD.PASSWORD
        ? Config.VERIFICATION_TOKEN_EXPIRE_TIME
        : Config.OTP_EXPIRE_TIME;
    const expireAt = Date.now() + expireTimeInSeconds * 1000;

    // Generate token and hash
    const { dbToken, userToken } =
      await AuthControllerUtility.generateTokenAndHash({
        email,
        phone,
        otp,
        method,
        expireAt,
        userId: user._id.toString(),
      });

    if (forgotPassword) {
      await UserService.updateById(user._id, {
        passwordResetToken: dbToken,
        passwordResetExpiresAt: expireAt,
      });
    } else {
      // Update user with verification token and expiration date
      if (email) {
        await UserService.updateById(user._id, {
          emailVerificationToken: dbToken,
          emailVerificationTokenExpiresAt: expireAt,
        });
      } else {
        await UserService.updateById(user._id, {
          phoneVerificationToken: dbToken,
          phoneVerificationTokenExpiresAt: expireAt,
        });
      }
    }

    // Send OTP via the chosen method
    if (
      email &&
      (method === AUTHENTICATION_METHOD.MAGIC_LINK ||
        method === AUTHENTICATION_METHOD.PASSWORD)
    ) {
      await SendEmailService.sendVerifyEmail(
        email,
        user.firstName ?? "",
        userToken,
        method,
        forgotPassword
      );
    } else if (email && method === AUTHENTICATION_METHOD.EMAIL_OTP) {
      await SendEmailService.sendOTPEmail(email, user.firstName ?? "", otp);
    } else if (phone && method === AUTHENTICATION_METHOD.SMS_OTP) {
      await OtpServices.sendOtpViaPhone(phone, otp);
    } else if (phone && method === AUTHENTICATION_METHOD.WHATSAPP_OTP) {
      await OtpServices.sendOtpViaWhatsapp(phone, otp);
    }

    return { userToken };
  }

  public static async generateTokenAndHash({
    email,
    phone,
    otp,
    method,
    userId,
    expireAt,
  }: GenerateTokenAndHashProps) {
    // Create data for hashing
    const elements = [email ?? phone, method, userId, expireAt];

    // Add OTP if method is other than MAGIC_LINK
    if (
      method !== AUTHENTICATION_METHOD.MAGIC_LINK &&
      method !== AUTHENTICATION_METHOD.PASSWORD
    ) {
      elements.push(otp);
    }

    // Join the elements to create the data string
    const data = elements.join(".");

    // Generate token and hash
    const dbToken = HashService.hash(data);
    const userToken = HashService.hash(dbToken, Config.SECONDARY_HASH_SECRET);

    return { dbToken, userToken }; // Return both token and hash
  }

  public static async setCookies(
    req: Request,
    res: Response,
    user: UserDTO,
    remember: boolean = true
  ) {
    // Create token and store in DB
    const { accessToken, refreshToken } = await TokenService.generateTokens(
      user
    );

    const userAgent = UAParser(req.headers["user-agent"]);
    console.log(userAgent);

    await TokenService.storeRefreshToken({
      token: refreshToken,
      userId: user._id,
      ip: req.ip,
      browser: userAgent.browser.toString(),
      engine: userAgent.engine.toString(),
      os: userAgent.os.toString(),
      device: userAgent.device.toString(),
      cpu: userAgent.cpu.toString(),
    });

    // Set cookies in response
    res.cookie(Config.ACCESS_TOKEN_KEY, accessToken, {
      maxAge: Config.ACCESS_TOKEN_MAX_AGE / 1000,
      httpOnly: Config.NODE_ENV === "production",
      secure: Config.IS_SECURE,
      sameSite: "lax",
    });
    res.cookie(Config.REFRESH_TOKEN_KEY, refreshToken, {
      maxAge: remember ? Config.REFRESH_TOKEN_MAX_AGE : undefined,
      httpOnly: Config.NODE_ENV === "production",
      secure: Config.IS_SECURE,
      sameSite: "lax",
    });
  }
}

export default AuthController;
