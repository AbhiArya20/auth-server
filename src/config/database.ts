import mongoose from "mongoose";
import Config from "@/config/config.js";

async function dbConnect() {
  await mongoose.connect(Config.DB_URL);
  console.log("Database Connected on", Config.DB_URL);
}

export { dbConnect };
