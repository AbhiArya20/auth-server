import mongoose, { ObjectId } from "mongoose";
import UserModel from "./user_model";

export interface IRefreshUserSchema {
  _id: ObjectId;
  token: string;
  userId: ObjectId;
  ip: string;
  createdAt: Date;
  updatedAt: Date;
}

const refreshUserSchema = new mongoose.Schema<IRefreshUserSchema>(
  {
    token: {
      type: String,
      required: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: UserModel.modelName,
      required: true,
      unique: true,
    },
  },
  {
    timestamps: true,
    toJSON: { getters: true },
  }
);

const RefreshUserModel = mongoose.model<IRefreshUserSchema>(
  "refresh_users",
  refreshUserSchema
);

export default RefreshUserModel;
