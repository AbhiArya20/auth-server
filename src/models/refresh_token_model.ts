import mongoose, { ObjectId } from "mongoose";
import UserModel from "@/models/user_model";

export interface IRefreshTokenSchema {
  _id: ObjectId;
  token: string;
  userId: ObjectId;
  ip: string;
  browser: string;
  engine: string;
  os: string;
  device: string;
  cpu: string;
  createdAt: Date;
  updatedAt: Date;
}

const refreshTokenSchema = new mongoose.Schema<IRefreshTokenSchema>(
  {
    token: {
      type: String,
      required: true,
      unique: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: UserModel.modelName,
      required: true,
    },
    ip: {
      type: String,
      required: true,
    },
    browser: {
      type: String,
    },
    engine: {
      type: String,
    },
    os: {
      type: String,
    },
    device: {
      type: String,
    },
    cpu: {
      type: String,
    },
  },
  {
    timestamps: true,
    toJSON: { getters: true },
  }
);

const RefreshTokenModel = mongoose.model<IRefreshTokenSchema>(
  "refresh_tokens",
  refreshTokenSchema
);

export default RefreshTokenModel;
