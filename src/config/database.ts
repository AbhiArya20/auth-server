import mongoose from "mongoose";
import Config from "@/config/config";
import { logger } from "@/utils/logger/logger";

async function dbConnect() {
  await mongoose.connect(Config.DB_URL);
  logger.info("Database Connected on " + Config.DB_URL);
}

export default dbConnect;
