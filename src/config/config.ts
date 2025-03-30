import { logger } from "@/utils/logger/logger";
import { config } from "dotenv";
import { z } from "zod";
config();

class Config {
  // Define Zod schema for the environment variables
  private static schema = z.object({
    NODE_ENV: z.enum(["development", "production"]),
    APP_NAME: z.string(),
    APP_LOGO_URL: z.string(),
    APP_SUPPORT_EMAIL: z.string().email(),
    PORT: z.coerce.number().min(1),
    DB_URL: z.string(),
    CORS_ORIGIN: z
      .string()
      .optional()
      .transform((val) => val?.split(",") ?? []),
    PRIMARY_HASH_SECRET: z.string(),
    SECONDARY_HASH_SECRET: z.string(),
    IS_SECURE: z.coerce.boolean(),
    MAX_REQUEST: z.coerce.number().min(1),
    WINDOW_SECONDS: z.coerce.number().min(1),
    BLOCKED_FOR_SECONDS: z.coerce.number().min(1),
    MAX_REQUEST_ROUTES: z.coerce.number().min(1),
    WINDOW_SECONDS_ROUTES: z.coerce.number().min(1),
    BLOCKED_FOR_SECONDS_ROUTES: z.coerce.number().min(1),
    REDIS_HOST: z.string(),
    REDIS_PORT: z.coerce.number().min(1),
    REDIS_USERNAME: z.string(),
    REDIS_PASSWORD: z.string(),
    CACHE_TIME: z.coerce.number().min(1),
    JWT_ACCESS_TOKEN_SECRET: z.string(),
    JWT_REFRESH_TOKEN_SECRET: z.string(),
    ACCESS_TOKEN_KEY: z.string(),
    REFRESH_TOKEN_KEY: z.string(),
    ACCESS_TOKEN_MAX_AGE: z.coerce.number().min(1),
    REFRESH_TOKEN_MAX_AGE: z.coerce.number().min(1),
    AWS_SECRET_ACCESS_KEY: z.string(),
    AWS_ACCESS_KEY: z.string(),
    AWS_REGION: z.string(),
    AWS_S3_BUCKET: z.string(),
    SMTP_EMAIL: z.string().email(),
    SMTP_PASSWORD: z.string(),
    SMTP_SERVICE: z.string(),
    SMTP_HOST: z.string(),
    SMTP_PORT: z.coerce.number().min(1),
    OTP_AUTH_KEY: z.string(),
    OTP_SENDER: z.string(),
    OTP_TEMPLATE_ID: z.string(),
    OTP_SMS_URL: z.string().url(),
    OTP_WHATSAPP_URL: z.string().url(),
    OTP_CAMPAIGN_NAME: z.string(),
    OTP_ROUTE: z.string(),
    OTP_CODING: z.string(),
    OTP_EXPIRE_TIME: z.coerce.number().min(1).default(300),
    VERIFICATION_TOKEN_EXPIRE_TIME: z.coerce.number().min(1).default(300),
    BACKEND_URL: z.string().url(),
    FRONTEND_URL: z.string().url(),
  });

  // Validating environment variables using Zod schema
  private static validateEnv() {
    const parsed = this.schema.safeParse(process.env);
    if (!parsed.success) {
      logger.error("Invalid environment variables:", parsed.error.errors);
      throw new Error("Invalid environment variables");
    }
    return parsed.data;
  }

  // Load and validate the environment variables
  static readonly config = Config.validateEnv();

  // Node environment
  static readonly NODE_ENV = Config.config.NODE_ENV;

  // App configuration
  static readonly APP_NAME = Config.config.APP_NAME;
  static readonly APP_LOGO_URL = Config.config.APP_LOGO_URL;
  static readonly APP_SUPPORT_EMAIL = Config.config.APP_SUPPORT_EMAIL;

  // Port
  static readonly PORT = Config.config.PORT;

  // Database connection URL
  static readonly DB_URL = Config.config.DB_URL;

  // CORS
  static readonly CORS_ORIGIN = Config.config.CORS_ORIGIN;

  // Hash secrets for hash
  static readonly PRIMARY_HASH_SECRET = Config.config.PRIMARY_HASH_SECRET;
  static readonly SECONDARY_HASH_SECRET = Config.config.SECONDARY_HASH_SECRET;

  // Whether you are using HTTP or HTTPS
  static readonly IS_SECURE = Config.config.IS_SECURE;

  // Rate limiter configuration
  static readonly MAX_REQUEST = Config.config.MAX_REQUEST;
  static readonly WINDOW_SECONDS = Config.config.WINDOW_SECONDS;
  static readonly BLOCKED_FOR_SECONDS = Config.config.BLOCKED_FOR_SECONDS;

  // Ratelimiter for send OTP or verify OTP
  static readonly MAX_REQUEST_ROUTES = Config.config.MAX_REQUEST_ROUTES;
  static readonly WINDOW_SECONDS_ROUTES = Config.config.WINDOW_SECONDS_ROUTES;
  static readonly BLOCKED_FOR_SECONDS_ROUTES =
    Config.config.BLOCKED_FOR_SECONDS_ROUTES;

  // Redis configuration
  static readonly REDIS_HOST = Config.config.REDIS_HOST;
  static readonly REDIS_PORT = Config.config.REDIS_PORT;
  static readonly REDIS_USERNAME = Config.config.REDIS_USERNAME;
  static readonly REDIS_PASSWORD = Config.config.REDIS_PASSWORD;
  static readonly CACHE_TIME = Config.config.CACHE_TIME;

  // JWT Token Configuration such as access_token_secret, refresh_token_secret, access_token_key, refresh_token_key, access_token_max_age, refresh_token_max_age
  static readonly JWT_ACCESS_TOKEN_SECRET =
    Config.config.JWT_ACCESS_TOKEN_SECRET;
  static readonly JWT_REFRESH_TOKEN_SECRET =
    Config.config.JWT_REFRESH_TOKEN_SECRET;
  static readonly ACCESS_TOKEN_KEY = Config.config.ACCESS_TOKEN_KEY;
  static readonly REFRESH_TOKEN_KEY = Config.config.REFRESH_TOKEN_KEY;
  static readonly ACCESS_TOKEN_MAX_AGE = Config.config.ACCESS_TOKEN_MAX_AGE;
  static readonly REFRESH_TOKEN_MAX_AGE = Config.config.REFRESH_TOKEN_MAX_AGE;

  // AWS Configuration
  static readonly AWS_SECRET_ACCESS_KEY = Config.config.AWS_SECRET_ACCESS_KEY;
  static readonly AWS_ACCESS_KEY = Config.config.AWS_ACCESS_KEY;
  static readonly AWS_REGION = Config.config.AWS_REGION;
  static readonly AWS_S3_BUCKET = Config.config.AWS_S3_BUCKET;

  // SMTP Configuration
  static readonly SMTP_EMAIL = Config.config.SMTP_EMAIL;
  static readonly SMTP_PASSWORD = Config.config.SMTP_PASSWORD;
  static readonly SMTP_SERVICE = Config.config.SMTP_SERVICE;
  static readonly SMTP_HOST = Config.config.SMTP_HOST;
  static readonly SMTP_PORT = Config.config.SMTP_PORT;

  // OTP Configuration - for the services https://bulk24sms.com/
  static readonly OTP_AUTH_KEY = Config.config.OTP_AUTH_KEY;
  static readonly OTP_SENDER = Config.config.OTP_SENDER;
  static readonly OTP_TEMPLATE_ID = Config.config.OTP_TEMPLATE_ID;
  static readonly OTP_SMS_URL = Config.config.OTP_SMS_URL;
  static readonly OTP_WHATSAPP_URL = Config.config.OTP_WHATSAPP_URL;
  static readonly OTP_CAMPAIGN_NAME = Config.config.OTP_CAMPAIGN_NAME;
  static readonly OTP_ROUTE = Config.config.OTP_ROUTE;
  static readonly OTP_CODING = Config.config.OTP_CODING;
  static readonly OTP_EXPIRE_TIME = Config.config.OTP_EXPIRE_TIME;

  // Verification Token Configuration
  static readonly VERIFICATION_TOKEN_EXPIRE_TIME =
    Config.config.VERIFICATION_TOKEN_EXPIRE_TIME;

  // Backend and Frontend URLs
  static readonly BACKEND_URL = Config.config.BACKEND_URL;
  static readonly FRONTEND_URL = Config.config.FRONTEND_URL;
}

export default Config;
