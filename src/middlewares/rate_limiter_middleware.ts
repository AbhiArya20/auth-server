import { Request, Response, NextFunction } from "express";
import RedisClient from "@/config/redis.js";
import RedisKeys from "@/utils/redis/redis_keys.js";
import ErrorResponse, {
  createServerErrorResponse,
} from "@/utils/response-classes.ts/error-response.js";

const rateLimiterMiddleware = (
  maxRequests: number,
  windowSeconds: number,
  blockedForSeconds: number,
  area?: string
) => {
  const middleware = async (
    req: Request,
    res: Response,
    next: NextFunction
  ) => {
    // Generate a unique key for rate limiting based on the request's
    const keySeparator =
      req._id?.toString() ??
      req.ip ??
      req.body.email ??
      req.body.phone ??
      "UNKNOWN_USER_OR_IP";
    const key = RedisKeys.getRateLimiterKey(keySeparator, area);
    try {
      // Increment the request count for the key and set its expiration time
      const currentRequests: number = await RedisClient.incr(key);
      if (currentRequests === 1) {
        await RedisClient.expire(key, windowSeconds); // Set expiration only for the first request
      }

      // Calculate the remaining requests and set the rate limit headers in the response
      const remainingRequests: number = maxRequests - currentRequests;
      res.setHeader("X-RateLimit-Limit", maxRequests);
      res.setHeader("X-RateLimit-Remaining", Math.max(remainingRequests, 0));
      res.setHeader(
        "X-RateLimit-Reset",
        Math.floor((Date.now() + windowSeconds * 1000) / 1000)
      );

      // If the current request count exceeds the rate limit
      if (currentRequests > maxRequests) {
        let microSecondTime: number = Date.now() + blockedForSeconds * 1000;

        // Adjust the block duration based on the area and the number of requests exceeding the limit
        microSecondTime = Math.round(
          microSecondTime +
            Math.pow(2, Math.min(currentRequests - maxRequests, 35))
        );

        // Set the expiration time for the key and send a 429 response with an error message
        await RedisClient.expire(key, Math.round(microSecondTime / 1000));
        const date: Date = new Date(microSecondTime);
        return res.status(429).json(
          new ErrorResponse({
            error: {
              code: "RATE_LIMIT_EXCEEDED",
              retryAfter: microSecondTime,
            },
            code: "RATE_LIMIT_EXCEEDED",
            message: `You have exceeded the rate limit of ${maxRequests} requests per ${windowSeconds} seconds. Try after ${date.getDate()} ${date.toLocaleString(
              "en-US",
              { month: "short" }
            )} ${date.getFullYear()} ${date.toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
            })}`,
          })
        );
      }
      // Continue to the next middleware function
      next();
    } catch (error) {
      // Handle any errors that occur during rate limiting
      console.error(error);
      return res.status(500).json(createServerErrorResponse);
    }
  };
  return middleware;
};

export { rateLimiterMiddleware };
