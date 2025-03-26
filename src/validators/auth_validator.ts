import { Response, Request, NextFunction } from "express";
import { z } from "zod";
import { createValidationErrorResponse } from "@/utils/response-classes.ts/error-response.js";
import { AuthenticationMethod } from "@/utils/constants";

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
  .max(10, "Phone number must be less than or equal to 10 digits.")
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

const hashZod = z
  .string({ message: "Token cannot be empty" })
  .trim()
  .min(1, { message: "Token cannot be empty" });

const otpZod = z
  .number()
  .min(100000, { message: "OTP must be a 6-digit number." })
  .max(999999, { message: "OTP must be a 6-digit number." });

const methodZod = z.enum([
  AuthenticationMethod.MAGIC_LINK,
  AuthenticationMethod.EMAIL_OTP,
  AuthenticationMethod.SMS_OTP,
  AuthenticationMethod.WHATSAPP_OTP,
  AuthenticationMethod.PASSWORD,
]);

type superRefinedProps = {
  email?: string;
  phone?: string;
  method: string;
  password?: string;
};

function superRefined(
  { email, phone, method, password }: superRefinedProps,
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
  if (
    email &&
    !(
      method === AuthenticationMethod.MAGIC_LINK ||
      method === AuthenticationMethod.EMAIL_OTP ||
      method === AuthenticationMethod.PASSWORD
    )
  ) {
    ctx.addIssue({
      path: ["email", "method"],
      message: `email is only allowed with method ${AuthenticationMethod.MAGIC_LINK}, ${AuthenticationMethod.EMAIL_OTP}, or ${AuthenticationMethod.PASSWORD}.`,
      code: z.ZodIssueCode.custom,
      params: {
        type: "custom",
        code: "ALLOWED_METHOD_FOR_EMAIL",
      },
    });
  }

  if (email && method === AuthenticationMethod.PASSWORD && !password) {
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

  // Phone must be present when method is SMS_OTP or WHATSAPP_OTP
  if (
    phone &&
    !(
      method === AuthenticationMethod.SMS_OTP ||
      method === AuthenticationMethod.WHATSAPP_OTP
    )
  ) {
    ctx.addIssue({
      path: ["phone", "method"],
      message: `phone number is only allowed with method ${AuthenticationMethod.SMS_OTP} or ${AuthenticationMethod.WHATSAPP_OTP}.`,
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
  .superRefine(({ email, phone, method, password }, ctx) =>
    superRefined({ email, phone, method, password }, ctx)
  );

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
  .superRefine(({ email, phone, method, password }, ctx) =>
    superRefined({ email, phone, method, password }, ctx)
  );

const resendZodSchema = z
  .object({
    email: emailZod.optional(),
    phone: phoneZod.optional(),
    method: methodZod.exclude([AuthenticationMethod.PASSWORD]),
  })
  .superRefine(({ email, phone, method }, ctx) =>
    superRefined({ email, phone, method }, ctx)
  );

const verifyZodSchema = z
  .object({
    email: emailZod.optional(),
    phone: phoneZod.optional(),
    method: methodZod.exclude([AuthenticationMethod.PASSWORD]),
    otp: otpZod.optional(),
    hash: hashZod,
  })
  .superRefine(({ email, phone, method }, ctx) =>
    superRefined({ email, phone, method }, ctx)
  );

const forgotPasswordVerifyOtpZodSchema = z
  .object({
    email: emailZod,
    phone: phoneZod,
    hash: hashZod,
    otp: otpZod,
    newPassword: passwordZod,
    confirmNewPassword: passwordZod,
  })
  .refine(
    (values) => values.newPassword === values.confirmNewPassword,
    "The passwords do not match. Please re-enter them."
  );

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

  public static forgotPasswordSendOtp(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    const { error, data } = emailZodSchema.safeParse(req.body);
    if (error)
      return res.status(400).json(createValidationErrorResponse(error));
    req.body = data;
    next();
  }

  public static forgotPasswordVerifyOtp(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    const { error, data } = forgotPasswordVerifyOtpZodSchema.safeParse(
      req.body
    );
    if (error)
      return res.status(400).json(createValidationErrorResponse(error));
    req.body = data;
    next();
  }
}

export default AuthValidator;
