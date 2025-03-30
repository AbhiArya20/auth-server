import Redis from "ioredis";
import { RedisOptions } from "ioredis";
import Config from "@/config/config";

const redisOptions: RedisOptions = {
  port: Config.REDIS_PORT,
  host: Config.REDIS_HOST,
  username: Config.REDIS_USERNAME,
  password: Config.REDIS_PASSWORD,
};

const RedisClient = new Redis(redisOptions);

export default RedisClient;
