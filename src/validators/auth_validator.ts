import { Response, Request, NextFunction } from "express";
import { z } from "zod";
import { createValidationErrorResponse } from "@/utils/response-classes.ts/error-response";
import { AUTHENTICATION_METHOD } from "@/utils/constants";
import { isEmailMethod, isPhoneMethod } from "@/utils/method";

const firstNameZod = z
  .string({ message: "First name cannot be empty" })
  .toLowerCase()
  .trim()
  .min(3, { message: "First name must be at least 3 characters long." })
  .max(30, {
    message: "First Name must be less than or equal to 30 characters long.",
  });

const lastNameZod = z
  .string({ message: "Last name cannot be empty" })
  .toLowerCase()
  .trim()
  .min(3, { message: "Last name must be at least 3 characters long." })
  .max(30, {
    message: "Last Name must be less than or equal to 30 characters long.",
  })
  .optional();

const emailZod = z
  .string({ message: "Please provide a valid email address." })
  .trim()
  .toLowerCase()
  .min(3, "Email must contain at least 3 characters")
  .max(50, "Email must be less than or equal to 50 characters long.")
  .email({
    message: "Please provide a valid email address.",
  });

const phoneZod = z
  .string({ message: "Please provide a valid phone number." })
  .trim()
  .min(10, "Phone number must contain at least 10 digits")
  .max(10, "Phone number should not be more than 10 digits.")
  .regex(/^\d{10}$/, {
    message: "Please provide a valid phone number.",
  });

const passwordZod = z
  .string({ message: "Password cannot be empty" })
  .trim()
  .min(8, "Password must contain at least 8 digits")
  .max(32, "Password must be less than or equal to 32 characters long.")
  .regex(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$!%*?&])[A-Za-z\d@#$!%*?&]{8,32}$/,
    {
      message:
        "Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character",
    }
  );

const verificationTokenZod = z
  .string({
    message: "Verification token cannot be empty. Please provide a valid token",
  })
  .trim()
  .min(1, {
    message: "Verification token cannot be empty. Please provide a valid token",
  });

const otpZod = z
  .number()
  .min(100000, { message: "OTP must be a 6-digit number." })
  .max(999999, { message: "OTP must be a 6-digit number." });

const avatarZod = z.object({
  image: z.string().url().optional(),
  etag: z.string().optional(),
});

const methodZod = z.enum(
  [
    AUTHENTICATION_METHOD.MAGIC_LINK,
    AUTHENTICATION_METHOD.EMAIL_OTP,
    AUTHENTICATION_METHOD.SMS_OTP,
    AUTHENTICATION_METHOD.WHATSAPP_OTP,
    AUTHENTICATION_METHOD.PASSWORD,
  ],
  {
    message: "please provide a valid authentication method",
  }
);

type superRefinedProps = {
  email?: string;
  phone?: string;
  method: string;
};

function superRefined(
  { email, phone, method }: superRefinedProps,
  ctx: z.RefinementCtx
) {
  // Check if both email and phone are provided
  if (email && phone) {
    ctx.addIssue({
      path: ["email", "phone"],
      message: "Please provide either email or phone number, but not both.",
      code: z.ZodIssueCode.custom,
      params: {
        type: "custom",
        code: "EMAIL_OR_PHONE_REQUIRED",
      },
    });
  }

  // Check if neither email nor phone is provided
  if (!email && !phone) {
    ctx.addIssue({
      path: ["email", "phone"],
      message: "Please provide either email or phone number.",
      code: z.ZodIssueCode.custom,
      params: {
        type: "custom",
        code: "EMAIL_OR_PHONE_REQUIRED",
      },
    });
  }

  // Email must be present when method is MAGIC_LINK, EMAIL_OTP, or PASSWORD
  if (isEmailMethod(method) && !email) {
    ctx.addIssue({
      path: ["email", "method"],
      message: `email is only allowed with method ${AUTHENTICATION_METHOD.MAGIC_LINK}, ${AUTHENTICATION_METHOD.EMAIL_OTP}, or ${AUTHENTICATION_METHOD.PASSWORD}.`,
      code: z.ZodIssueCode.custom,
      params: {
        type: "custom",
        code: "ALLOWED_METHOD_FOR_EMAIL",
      },
    });
  }

  // Phone must be present when method is SMS_OTP or WHATSAPP_OTP
  if (isPhoneMethod(method) && !phone) {
    ctx.addIssue({
      path: ["phone", "method"],
      message: `phone number is only allowed with method ${AUTHENTICATION_METHOD.SMS_OTP} or ${AUTHENTICATION_METHOD.WHATSAPP_OTP}.`,
      code: z.ZodIssueCode.custom,
      params: {
        type: "custom",
        code: "ALLOWED_METHOD_FOR_PHONE",
      },
    });
  }
}

const registerZodSchema = z
  .object({
    firstName: firstNameZod.optional(),
    lastName: lastNameZod,
    email: emailZod.optional(),
    phone: phoneZod.optional(),
    password: passwordZod.optional(),
    method: methodZod,
  })
  .superRefine(({ email, phone, method, password }, ctx) => {
    superRefined({ email, phone, method }, ctx);

    if (method === AUTHENTICATION_METHOD.PASSWORD && !password) {
      ctx.addIssue({
        path: ["password"],
        message: "Password is required when method is PASSWORD",
        code: z.ZodIssueCode.custom,
        params: {
          type: "custom",
          code: "PASSWORD_REQUIRED",
        },
      });
    }
  });

const loginZodSchema = z
  .object({
    email: emailZod.optional(),
    phone: phoneZod.optional(),
    password: z
      .string({ message: "Password cannot be empty" })
      .trim()
      .min(1, "Password cannot be empty")
      .optional(),
    remember: z.boolean().optional().default(true),
    method: methodZod,
  })
  .superRefine(({ email, phone, method, password }, ctx) => {
    superRefined({ email, phone, method }, ctx);

    if (method === AUTHENTICATION_METHOD.PASSWORD && !password) {
      ctx.addIssue({
        path: ["password"],
        message: "Password is required when method is PASSWORD",
        code: z.ZodIssueCode.custom,
        params: {
          type: "custom",
          code: "PASSWORD_REQUIRED",
        },
      });
    }
  });

const resendZodSchema = z
  .object({
    email: emailZod.optional(),
    phone: phoneZod.optional(),
    method: methodZod,
  })
  .superRefine(({ email, phone, method }, ctx) => {
    superRefined({ email, phone, method }, ctx);
  });

const verifyZodSchema = z
  .object({
    email: emailZod.optional(),
    phone: phoneZod.optional(),
    method: methodZod,
    verificationToken: verificationTokenZod,
    otp: otpZod.optional(),
  })
  .superRefine(({ email, phone, method }, ctx) =>
    superRefined({ email, phone, method }, ctx)
  );

const forgotPasswordZodSchema = z
  .object({
    email: emailZod.optional(),
    phone: phoneZod.optional(),
    method: methodZod.exclude([AUTHENTICATION_METHOD.PASSWORD]),
  })
  .superRefine(({ email, phone, method }, ctx) =>
    superRefined({ email, phone, method }, ctx)
  );

const forgotPasswordVerifyZodSchema = z
  .object({
    email: emailZod.optional(),
    phone: phoneZod.optional(),
    method: methodZod.exclude([AUTHENTICATION_METHOD.PASSWORD]),
    verificationToken: verificationTokenZod,
    otp: otpZod.optional(),
    password: passwordZod,
  })
  .superRefine(({ email, phone, method }, ctx) =>
    superRefined({ email, phone, method }, ctx)
  );

const updateUserZodSchema = z.object({
  firstName: firstNameZod.optional(),
  lastName: lastNameZod,
  avatar: avatarZod.optional(),
});

class AuthValidator {
  public static register(req: Request, res: Response, next: NextFunction) {
    const { error, data } = registerZodSchema.safeParse(req.body);
    if (error)
      return res.status(400).json(createValidationErrorResponse(error));
    req.body = data;
    next();
  }

  public static login(req: Request, res: Response, next: NextFunction) {
    const { error, data } = loginZodSchema.safeParse(req.body);
    if (error)
      return res.status(400).json(createValidationErrorResponse(error));
    req.body = data;
    next();
  }

  public static resend(req: Request, res: Response, next: NextFunction) {
    const { error, data } = resendZodSchema.safeParse(req.body);
    if (error)
      return res.status(400).json(createValidationErrorResponse(error));
    req.body = data;
    next();
  }

  public static verify(req: Request, res: Response, next: NextFunction) {
    const { error, data } = verifyZodSchema.safeParse(req.body);
    if (error)
      return res.status(400).json(createValidationErrorResponse(error));
    req.body = data;
    next();
  }

  public static forgotPassword(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    const { error, data } = forgotPasswordZodSchema.safeParse(req.body);
    if (error)
      return res.status(400).json(createValidationErrorResponse(error));
    req.body = data;
    next();
  }

  public static forgotPasswordVerify(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    const { error, data } = forgotPasswordVerifyZodSchema.safeParse(req.body);
    if (error)
      return res.status(400).json(createValidationErrorResponse(error));
    req.body = data;
    next();
  }

  public static updateUser(req: Request, res: Response, next: NextFunction) {
    if (req.file) {
      const { location, etag } = req.file;
      req.body.avatar = {
        image: location,
        etag,
      };
    }
    const { error, data } = updateUserZodSchema.safeParse(req.body);
    if (error)
      return res.status(400).json(createValidationErrorResponse(error));
    req.body = data;
    next();
  }
}

export default AuthValidator;
