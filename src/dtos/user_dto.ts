import { IImages, IUserSchema } from "@/models/user_model.js";
import { UserRole, UserStatus } from "@/utils/constants";
import StringFunction from "@/utils/string_functions.js";

class UserDTO {
  _id: string;
  firstName?: string;
  lastName?: string;
  email?: string;
  isEmailVerified: Date | undefined;
  phone?: string;
  isPhoneVerified: Date | undefined;
  role: (typeof UserRole)[keyof typeof UserRole];
  status: (typeof UserStatus)[keyof typeof UserStatus];
  avatar?: IImages;
  createdAt: Date;
  updatedAt: Date;

  constructor(user: IUserSchema) {
    this._id = user._id.toString();
    this.firstName = user.firstName
      ? StringFunction.capitalize(user.firstName)
      : undefined;
    this.lastName = user.lastName
      ? StringFunction.capitalize(user.lastName)
      : undefined;
    this.email = user.email;
    this.isEmailVerified = user.isEmailVerified;
    this.phone = user.phone;
    this.isPhoneVerified = user.isPhoneVerified;
    this.avatar = user.avatar;
    this.role = user.role;
    this.status = user.status;
    this.createdAt = user.createdAt;
    this.updatedAt = user.updatedAt;
  }
}

export default UserDTO;
