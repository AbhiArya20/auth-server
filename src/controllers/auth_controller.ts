import { Response, Request, NextFunction } from "express";
import Config from "@/config/config.js";
import TokenService from "@/services/token_services.js";
import UserService from "@/services/user_services.js";
import bcrypt from "bcrypt";
import Constants, {
  AuthenticationMethod,
  UserStatus,
} from "@/utils/constants.js";
import ErrorResponse, {
  createAccountStatusErrorResponse,
  createInvalidRefreshTokenErrorResponse,
} from "@/utils/response-classes.ts/error-response.js";
import UserDTO from "@/dtos/user_dto.js";
import { SuccessResponse } from "@/utils/response-classes.ts/success-response.js";
import { SendEmailService } from "@/services/email_services.js";
import { HashServices } from "@/services/hash_services.js";
import crypto from "crypto";
import RedisClient from "@/config/redis.js";
import OtpServices from "@/services/otp_services";
import { IUserSchema } from "@/models/user_model";

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
            code: Constants.USER_ALREADY_REGISTERED,
            message: Constants.USER_REGISTERED_MESSAGE,
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
      const { hash } = await AuthControllerUtility.sendVerificationDetails({
        user,
        method,
        email,
        phone,
      });

      // create DTO and send response
      const formattedUser = new UserDTO(user);
      return res.status(200).json(
        new SuccessResponse({
          data: {
            email,
            phone,
            hash: method === AuthenticationMethod.MAGIC_LINK ? undefined : hash,
            method,
            user: formattedUser,
          },
          code: Constants.REGISTRATION_SUCCESS,
          message: Constants.REGISTRATION_SUCCESS_MESSAGE,
        })
      );
    } catch (error) {
      console.error(error);
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
      if (email && method === AuthenticationMethod.PASSWORD) {
        // If user does not exist
        if (!user) {
          return res.status(400).json(
            new ErrorResponse({
              code: Constants.INVALID_CREDENTIALS,
              message: Constants.USER_NOT_REGISTER,
            })
          );
        }

        // If password does not exist in database for the user
        if (!user.password) {
          return res.status(400).json(
            new ErrorResponse({
              code: Constants.PASSWORD_NOT_SET,
              message: Constants.PASSWORD_NOT_SET_MESSAGE,
            })
          );
        }

        // If password does not match
        if (!(await bcrypt.compare(password, user.password))) {
          return res.status(400).json(
            new ErrorResponse({
              code: Constants.INVALID_CREDENTIALS,
              message: Constants.INCORRECT_PASSWORD,
            })
          );
        }

        // Create DTO
        const formattedUser = new UserDTO(user);

        // If user is blocked or deleted
        const { status, isEmailVerified, isPhoneVerified } = formattedUser;
        if (status === UserStatus.BLOCKED || status === UserStatus.DELETED) {
          return res
            .status(status === UserStatus.BLOCKED ? 403 : 404)
            .json(createAccountStatusErrorResponse(status));
        }

        // If user is not verified
        if (!isEmailVerified && !isPhoneVerified) {
          return res.status(200).json(
            new SuccessResponse({
              data: { formattedUser },
              code: Constants.UNVERIFIED_USER,
              message: Constants.UNVERIFIED_USER_MESSAGE,
            })
          );
        }

        // Set cookies and send response
        await AuthControllerUtility.setCookies(
          res,
          { ...formattedUser },
          remember
        );
        return res.status(200).json(
          new SuccessResponse({
            data: { user: formattedUser },
            code: Constants.LOGIN_SUCCESS,
            message: Constants.LOGIN_SUCCESS_MESSAGE,
          })
        );
      }

      // Create a new user if not registered
      if (!user) {
        // Create new user
        user = await UserService.create({
          email,
          phone,
          password,
        });
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
            hash: method === AuthenticationMethod.MAGIC_LINK ? undefined : hash,
            method,
            user: formattedUser,
          },
          code: Constants.REGISTRATION_SUCCESS,
          message: Constants.REGISTRATION_SUCCESS_MESSAGE,
        })
      );
    } catch (error) {
      console.error(error);
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
            code: Constants.NOT_FOUND,
            message: Constants.USER_NOT_FOUND_MESSAGE,
          })
        );
      }

      // Create DTO
      const formattedUser = new UserDTO(user);

      // If user is blocked or deleted
      const { status, isEmailVerified, isPhoneVerified } = formattedUser;
      if (status === UserStatus.BLOCKED || status === UserStatus.DELETED) {
        return res
          .status(status === UserStatus.BLOCKED ? 403 : 404)
          .json(createAccountStatusErrorResponse(status));
      }

      // If user is already verified
      if ((email && isEmailVerified) || (phone && isPhoneVerified)) {
        return res.status(406).json(
          new ErrorResponse({
            code: Constants.ALREADY_VERIFIED,
            message: Constants.ALREADY_VERIFIED_MESSAGE,
          })
        );
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
            hash: method === AuthenticationMethod.MAGIC_LINK ? undefined : hash,
            method,
            user: formattedUser,
          },
          code: Constants.VERIFICATION_LINK_SEND,
          message: Constants.VERIFICATION_LINK_SEND_MESSAGE,
        })
      );
    } catch (error) {
      console.error(error);
      next(error);
    }
  }

  public static async verify(req: Request, res: Response, next: NextFunction) {
    try {
      // Destructure request body
      const { phone, email, method, hash } = req.body;

      // Get hash and expire time from hash
      const [hashFromFrontend, expireTime] = hash.split("-");

      // if hash expired
      if (+expireTime < Date.now()) {
        return res.status(408).json(
          new ErrorResponse({
            code: Constants.REQUEST_TIMEOUT,
            message: Constants.EXPIRE_VERIFICATION_LINK_MESSAGE,
          })
        );
      }

      // Get user from database
      const user = await UserService.findOne({
        ...(email && { email }),
        ...(phone && { phone }),
      });

      // If user is not found
      if (!user) {
        return res.status(404).json(
          new ErrorResponse({
            code: Constants.INVALID_LINK,
            message: Constants.INVALID_VERIFICATION_LINK_MESSAGE,
          })
        );
      }

      if (!user.verificationToken) {
        return res.status(404).json(
          new ErrorResponse({
            code: Constants.INVALID_LINK,
            message: Constants.INVALID_VERIFICATION_LINK_MESSAGE,
          })
        );
      }

      if (!user.verificationTokenExpiresAt) {
        return res.status(404).json(
          new ErrorResponse({
            code: Constants.INVALID_LINK,
            message: Constants.INVALID_VERIFICATION_LINK_MESSAGE,
          })
        );
      }

      if (user.verificationTokenExpiresAt.getMilliseconds() < Date.now()) {
        return res.status(404).json(
          new ErrorResponse({
            code: Constants.INVALID_LINK,
            message: Constants.INVALID_VERIFICATION_LINK_MESSAGE,
          })
        );
      }

      const generatedHash = HashServices.hash(
        user.verificationToken,
        Config.SECONDARY_HASH_SECRET
      );
      const isHashValid = hashFromFrontend === generatedHash;
      if (!isHashValid) {
        return res.status(400).json(
          new ErrorResponse({
            code: Constants.INVALID_LINK,
            message: Constants.INVALID_VERIFICATION_LINK_MESSAGE,
          })
        );
      }

      // Verify Hash
      const data = `${email}.${user.customerId}.${expireTime}`;
      const actualHash = HashServices.hash(data);

      if (hashFromFrontend != actualHash) {
        return res.status(400).json(
          new ErrorResponse({
            code: Constants.INVALID_LINK,
            message: Constants.INVALID_VERIFICATION_LINK_MESSAGE,
          })
        );
      }

      if (user.isEmailVerified) {
        return res.status(409).json(
          new ErrorResponse({
            code: Constants.ALREADY_VERIFIED,
            message: Constants.ALREADY_VERIFIED_MESSAGE,
          })
        );
      }

      // Check user's status
      const { status } = user;
      if (status === "Blocked" || status === "Deleted") {
        return res
          .status(status === "Blocked" ? 403 : 404)
          .json(createAccountStatusErrorResponse(status));
      }

      // Update user's email verified
      user = await UserService.updateOne(
        { _id: user._id },
        { $set: { isEmailVerified: true } }
      );

      const formattedUser = new UserDTO(user!);
      return res.status(200).json(
        new SuccessResponse({
          data: formattedUser,
          code: Constants.VERIFICATION_SUCCESSFUL,
          message: Constants.VERIFICATION_SUCCESSFUL_MESSAGE,
        })
      );
    } catch (error) {
      console.error(error);
      next(error);
    }
  }

  public static async refreshToken(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    try {
      const refreshTokenFromCookie = req.cookies[Config.REFRESH_TOKEN_KEY];
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
        console.error(error);
        return res.status(401).json(createInvalidRefreshTokenErrorResponse());
      }

      if (typeof user !== "string" && user.email) {
        // Check user's existence
        user = await UserService.findOneWithEmail({ email: user.email });
        if (!user) {
          return res.status(401).json(
            new ErrorResponse({
              code: Constants.NOT_FOUND,
              message: Constants.USER_NOT_FOUND_MESSAGE,
            })
          );
        }

        // Check user's status
        const { status } = user;
        if (status === "Blocked" || status === "Deleted") {
          return res.status(401).json(createAccountStatusErrorResponse(status));
        }

        // Create UserDTO
        const formattedUser = new UserDTO(user);

        // Delete CustomerId if user's email is not verified
        if (!formattedUser.isEmailVerified) {
          delete formattedUser.customerId; // Important delete for security
        }

        // Set cookies and Send response
        await setCookies(res, { ...formattedUser });
        return res.status(200).json(
          new SuccessResponse({
            data: formattedUser,
            code: Constants.LOGIN_SUCCESS,
            message: Constants.LOGIN_SUCCESS_MESSAGE,
          })
        );
      } else {
        return res.status(401).json(createInvalidRefreshTokenErrorResponse());
      }
    } catch (error) {
      console.error(error);
      next(error);
    }
  }

  public static async forgotPasswordSendOtp(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    try {
      // Check user registered
      const { email } = req.body;
      const user = await UserService.findOneWithEmail({ email });
      if (!user) {
        return res.status(404).json(
          new ErrorResponse({
            code: Constants.NOT_FOUND,
            message: Constants.USER_NOT_FOUND_MESSAGE,
          })
        );
      }

      // Check user's status
      const { status } = user;
      if (status === "Blocked" || status === "Deleted") {
        return res
          .status(status === "Blocked" ? 403 : 404)
          .json(createAccountStatusErrorResponse(status));
      }

      // Generate OTP and hash
      const otp = await crypto.randomInt(100000, 1000000);
      const expireTime = Date.now() + 5 * 60 * 1000;
      const data = `${email}.${otp}.${expireTime}`;
      const hash = HashServices.hash(data);

      // Send OTP via email and send response
      await SendEmailService.sendOTPEmail(email, user.firstName, otp);

      return res.status(200).json(
        new SuccessResponse({
          data: { hash: `${hash}.${expireTime}`, email },
          code: Constants.OTP_SENT,
          message: Constants.OTP_SENT_MESSAGE,
        })
      );
    } catch (error) {
      console.error(error);
      next(error);
    }
  }

  public static async forgotPasswordVerifyOtp(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    try {
      const { otp, hash, email, newPassword } = req.body;

      const [hashFromFrontend, expireTime] = hash.split(".");

      // Check for OTP expired?
      if (expireTime < Date.now()) {
        return res.status(408).json(
          new ErrorResponse({
            code: Constants.REQUEST_TIMEOUT,
            message: Constants.OTP_EXPIRED_MESSAGE,
          })
        );
      }

      // Check OTP is correct
      const data = `${email}.${otp}.${expireTime}`;
      const computedHash = HashServices.hash(data);

      if (computedHash !== hashFromFrontend) {
        return res.status(400).json(
          new ErrorResponse({
            code: Constants.INVALID_OTP,
            message: Constants.OTP_INVALID_MESSAGE,
          })
        );
      }

      const key = "OTP:" + email + ":" + otp;
      const isUsed = await RedisClient.get(key);

      if (isUsed) {
        return res.status(406).json(
          new ErrorResponse({
            code: Constants.OTP_USED,
            message: Constants.OTP_USED_MESSAGE,
          })
        );
      }

      await RedisClient.setex(key, 300, 1);

      // Check user registered
      let user = await UserService.findOneWithEmail({ email });
      if (!user) {
        return res.status(404).json(
          new ErrorResponse({
            code: Constants.NOT_FOUND,
            message: Constants.USER_NOT_FOUND_MESSAGE,
          })
        );
      }

      // Check user's status
      const { status } = user;
      if (status === "Blocked" || status === "Deleted") {
        return res.status(401).json(createAccountStatusErrorResponse(status));
      }

      user = await UserService.updateOne(
        { _id: user._id },
        { $set: { password: newPassword } }
      );

      // Create DTO
      const formattedUser = new UserDTO(user!);

      // Delete CustomerId if user's email is not verified
      if (!formattedUser.isEmailVerified) {
        delete formattedUser.customerId; // Important delete for security
      }

      // Set cookies and Send response
      await setCookies(res, { ...formattedUser });
      return res.status(200).json(
        new SuccessResponse({
          data: formattedUser,
          code: Constants.LOGIN_SUCCESS,
          message: Constants.LOGIN_SUCCESS_MESSAGE,
        })
      );
    } catch (error) {
      console.error(error);
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
      console.error(error);
      next(error);
    }
  }
}

type GenerateTokenAndHashProps = {
  email: string;
  phone: string;
  otp: number;
  method: string;
  userId: string;
};

type HandleUserVerificationProps = {
  user: IUserSchema;
  method: string;
  email: string;
  phone: string;
};

class AuthControllerUtility {
  public static async sendVerificationDetails({
    user,
    method,
    email,
    phone,
  }: HandleUserVerificationProps) {
    const otp = await OtpServices.generateOtp();
    const { token, hash, expireAt } =
      await AuthControllerUtility.generateTokenAndHash({
        email,
        phone,
        otp,
        method,
        userId: user._id.toString(),
      });

    // Update user with verification token and expiration date
    await UserService.updateById(user._id, {
      $set: {
        verificationToken: token,
        verificationTokenExpiresAt: expireAt,
      },
    });

    // Send OTP via the chosen method
    if (email && method === AuthenticationMethod.MAGIC_LINK) {
      await SendEmailService.sendVerifyEmail(email, user.firstName ?? "", hash);
    } else if (email && method === AuthenticationMethod.EMAIL_OTP) {
      await SendEmailService.sendOTPEmail(email, user.firstName ?? "", otp);
    } else if (phone && method === AuthenticationMethod.SMS_OTP) {
      await OtpServices.sendOtpViaPhone(phone, otp);
    } else if (phone && method === AuthenticationMethod.WHATSAPP_OTP) {
      await OtpServices.sendOtpViaWhatsapp(phone, otp);
    }

    return { hash };
  }

  public static async generateTokenAndHash({
    email,
    phone,
    otp,
    method,
    userId,
  }: GenerateTokenAndHashProps) {
    // Calculate expire time
    const expireTimeInSeconds =
      method === AuthenticationMethod.MAGIC_LINK
        ? Config.VERIFICATION_TOKEN_EXPIRE_TIME
        : Config.OTP_EXPIRE_TIME;
    const expireAt = Date.now() + expireTimeInSeconds * 1000;

    // Create data for hashing
    const elements = [email ?? phone, method, userId, expireAt];

    // Add OTP if method is other than MAGIC_LINK
    if (method !== AuthenticationMethod.MAGIC_LINK) {
      elements.push(otp);
    }

    // Join the elements to create the data string
    const data = elements.join(".");

    // Generate token and hash
    const token = HashServices.hash(data);
    const hash =
      HashServices.hash(token, Config.SECONDARY_HASH_SECRET) + "-" + expireAt;

    return { token, hash, expireAt }; // Return both token and hash
  }

  public static async setCookies(
    res: Response,
    user: UserDTO,
    remember: boolean = false
  ) {
    // Create token and store in DB
    const { accessToken, refreshToken } = await TokenService.generateTokens(
      user
    );
    await TokenService.storeRefreshToken({ refreshToken, userId: user._id });

    // Set cookies in response
    res.cookie(Config.ACCESS_TOKEN_KEY, accessToken, {
      maxAge: Config.ACCESS_TOKEN_MAX_AGE / 1000,
      httpOnly: false,
      secure: Config.IS_SECURE,
      sameSite: "lax",
    });
    res.cookie(Config.REFRESH_TOKEN_KEY, refreshToken, {
      maxAge: remember ? Config.REFRESH_TOKEN_MAX_AGE : undefined,
      httpOnly: false,
      secure: Config.IS_SECURE,
      sameSite: "lax",
    });
  }
}

export default AuthController;
