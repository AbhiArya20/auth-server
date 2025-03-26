import jwt from "jsonwebtoken";
import { ObjectId, UpdateQuery, FilterQuery } from "mongoose";
import Config from "@/config/config.js";
import RefreshUserModel, {
  IRefreshUserSchema,
} from "@/models/refresh_user_model.js";
import UserDTO from "@/dtos/user_dto.js";

class TokenService {
  // Verify Access Token
  public static async verifyAccessToken(accessToken: string) {
    return jwt.verify(accessToken, Config.JWT_ACCESS_TOKEN_SECRET);
  }

  // Verify Refresh Token
  public static async verifyRefreshToken(refreshToken: string) {
    return jwt.verify(refreshToken, Config.JWT_REFRESH_TOKEN_SECRET);
  }

  // Generates tokens
  public static async generateTokens(payload: UserDTO) {
    const accessToken = jwt.sign(payload, Config.JWT_ACCESS_TOKEN_SECRET, {
      expiresIn: Config.ACCESS_TOKEN_MAX_AGE,
    });
    const refreshToken = jwt.sign(payload, Config.JWT_REFRESH_TOKEN_SECRET, {
      expiresIn: Config.ACCESS_TOKEN_MAX_AGE,
    });
    return { accessToken, refreshToken };
  }

  // Store Refresh Token
  public static async storeRefreshToken(data: UpdateQuery<IRefreshUserSchema>) {
    await RefreshUserModel.create(data);
  }

  // find RefreshToken
  public static async findRefreshToken(query: FilterQuery<IRefreshUserSchema>) {
    return await RefreshUserModel.findOne(query);
  }

  // Remove RefreshToken
  public static async removeRefreshToken(
    refreshToken: string,
    userId: string | ObjectId
  ) {
    return await RefreshUserModel.findOneAndDelete({
      userId,
      token: refreshToken,
    });
  }
}

export default TokenService;
