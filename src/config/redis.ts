import Redis from "ioredis";
import { RedisOptions } from "ioredis";
import Config from "@/config/config.js";

// Redis options configuration object with explicit type
const redisOptions: RedisOptions = {
  port: Config.REDIS_PORT,
  host: Config.REDIS_HOST,
  username: Config.REDIS_USERNAME,
  password: Config.REDIS_PASSWORD,
};

// Redis client.
const RedisClient = new Redis(redisOptions);

export default RedisClient;
