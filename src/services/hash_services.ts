import crypto from "crypto";
import Config from "@/config/config.js";

export class HashServices {
  static hash(data: string, key = Config.PRIMARY_HASH_SECRET): string {
    return crypto.createHmac("sha256", key).update(data).digest("hex");
  }
}
