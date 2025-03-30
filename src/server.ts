import express, { NextFunction, Request, Response } from "express";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import { queryParser } from "express-query-parser";
import cors, { CorsOptions } from "cors";
import dbConnect from "@/config/database.js";
import morgan from "morgan";
import { rateLimiterMiddleware } from "@/middlewares/rate_limiter_middleware.js";
import AuthRouter from "@/routes/auth_route.js";
import ErrorResponse, {
  createServerErrorResponse,
} from "@/utils/response-classes.ts/error-response.js";
import {
  ERROR_RESPONSE_CODE,
  ERROR_RESPONSE_MESSAGE,
} from "@/utils/constants.js";
import Config from "@/config/config.js";
import helmet from "helmet";
import multer from "multer";
import { logger } from "@/utils/logger/logger";

class Server {
  static async createServer() {
    // Connect to the database
    await dbConnect();

    // Create an express app
    const app = express();

    // Configure security middlewares
    app.use(helmet());

    // Configure CORS
    const corsOptions: CorsOptions = {
      origin: Config.CORS_ORIGIN,
      methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      credentials: true,
    };
    app.use(cors(corsOptions));

    // Disable x-powered-by response headers
    app.disable("x-powered-by");

    // Configure morgan middleware for logging incoming requests to the console
    app.use(morgan("dev"));

    // Configure body parser middleware
    app.use(bodyParser.json({ limit: "2mb" }));

    // Configure rate limiter middleware
    app.use(
      rateLimiterMiddleware(
        Config.MAX_REQUEST,
        Config.WINDOW_SECONDS,
        Config.BLOCKED_FOR_SECONDS
      )
    );

    // Configure query parser middleware
    const queryParserConfig = {
      parseNull: true,
      parseUndefined: true,
      parseBoolean: true,
      parseNumber: true,
    };
    app.use(queryParser(queryParserConfig));

    // Configure cookie parser middleware
    app.use(cookieParser());

    // Configure routes
    app.use("/v1/", AuthRouter);
    app.get("/", (req: Request, res: Response) => {
      res.status(200).json({
        message: "welcome to the auth server.",
        status: "Running",
        yourIP: JSON.stringify(req.ip),
      });
    });

    // Errors handling middleware
    app.use(
      (error: unknown, req: Request, res: Response, next: NextFunction) => {
        if (!error) {
          return res.status(404).json(
            new ErrorResponse({
              code: ERROR_RESPONSE_CODE.NOT_FOUND,
              message: ERROR_RESPONSE_MESSAGE.ROUTE_NOT_FOUND_MESSAGE,
            })
          );
        }

        logger.error(error);

        if (error instanceof SyntaxError) {
          return res.status(400).json(
            new ErrorResponse({
              code: ERROR_RESPONSE_CODE.INVALID_REQUEST_BODY,
              message: ERROR_RESPONSE_MESSAGE.INVALID_REQUEST_BODY_MESSAGE,
              error: error,
            })
          );
        }

        if (error instanceof multer.MulterError) {
          let message = `File Upload Failed ${error.code}`;
          switch (error.code) {
            case "LIMIT_PART_COUNT":
              message =
                "Too many parts in the request. Please reduce the number of parts (maximum is 100) and try again.";
              break;
            case "LIMIT_FILE_SIZE":
              message =
                "The file is too large. The maximum file size allowed is 8MB for image and 200MB for video";
              break;
            case "LIMIT_FILE_COUNT":
              message =
                "Too many files uploaded. The maximum number of files allowed is 1";
              break;
            case "LIMIT_FIELD_KEY":
              message =
                "The field name is too long. The maximum length for field names is 100 characters";
              break;
            case "LIMIT_FIELD_VALUE":
              message =
                "The field value is too long. The maximum length for field values is 1MB";
              break;
            case "LIMIT_FIELD_COUNT":
              message =
                "Too many fields in the request. The maximum number of fields allowed is 100";
              break;
            case "LIMIT_UNEXPECTED_FILE":
              message =
                error.message ||
                `The field "${error.field}" is not allowed. Please check the field name and try again`;
              break;
            default:
              message = `File Upload Failed: ${error.code}`;
          }
          return res.status(400).json(
            new ErrorResponse({
              error: error,
              code: error.code,
              message: message,
            })
          );
        }

        res.status(500).json(createServerErrorResponse());
        next();
      }
    );
    return app;
  }
}

export default Server;
