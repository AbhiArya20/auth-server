import crypto from "crypto";
import axios from "axios";
import Config from "@/config/config";
import RedisClient from "@/config/redis";

const createMessage = (otp: number) => {
  return `Dear User Your Mobile Verification Code is : ${otp} Please Verify Your Mobile Number. ${Config.APP_NAME}`;
};

class OtpService {
  // Generate OTP
  public static async generateOtp() {
    return crypto.randomInt(100000, 1000000);
  }

  // Send OTP Via Phone
  public static async sendOtpViaPhone(phone: string, otp: number) {
    const configuration = {
      campaign_name: Config.OTP_CAMPAIGN_NAME,
      auth_key: Config.OTP_AUTH_KEY,
      sender: Config.OTP_SENDER,
      route: Config.OTP_ROUTE,
      receivers: phone,
      message: {
        msgdata: createMessage(otp),
        Template_ID: Config.OTP_TEMPLATE_ID,
        coding: Config.OTP_CODING,
      },
    };

    await axios.post(Config.OTP_SMS_URL, configuration);
  }

  // Send OTP via whatsapp
  public static async sendOtpViaWhatsapp(phone: string, otp: number) {
    const configuration = {
      campaign_name: Config.OTP_CAMPAIGN_NAME,
      auth_key: Config.OTP_AUTH_KEY,
      sender: Config.OTP_SENDER,
      receivers: phone,
      message: {
        contentType: "Text",
        content: createMessage(otp),
      },
    };

    await axios.post(Config.OTP_WHATSAPP_URL, configuration);
  }

  // Verify OTP hash
  public static async verifyOtp(
    hashFromFrontend: string,
    computedHash: string
  ) {
    return hashFromFrontend === computedHash;
  }

  public static async isUsed(key: string) {
    const isUsed = await RedisClient.get(key);
    if (isUsed) {
      return true;
    }
    await RedisClient.setex(key, 600, 1);
    return false;
  }
}

export default OtpService;
