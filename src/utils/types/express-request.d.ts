import UserDTO from "@/dtos/user_dto.js";
import { ObjectId } from "mongoose";

declare module "express-serve-static-core" {
  interface Request {
    _id?: ObjectId;
    user?: UserDTO;
    file?: MulterS3File;
  }
}
