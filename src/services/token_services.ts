import jwt from "jsonwebtoken";
import { ObjectId, UpdateQuery, FilterQuery } from "mongoose";
import Config from "@/config/config";
import RefreshTokenModel, {
  IRefreshTokenSchema,
} from "@/models/refresh_token_model";
import UserDTO from "@/dtos/user_dto";

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
  public static async storeRefreshToken(
    data: UpdateQuery<IRefreshTokenSchema>
  ) {
    await RefreshTokenModel.create(data);
  }

  // find RefreshToken
  public static async findRefreshToken(
    query: FilterQuery<IRefreshTokenSchema>
  ) {
    return await RefreshTokenModel.findOne(query);
  }

  // Remove RefreshToken
  public static async removeRefreshToken(
    refreshToken: string,
    userId: string | ObjectId | undefined
  ) {
    return await RefreshTokenModel.findOneAndDelete({
      token: refreshToken,
      ...(userId && { userId }),
    });
  }
}

export default TokenService;
