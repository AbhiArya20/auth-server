import mongoose, { ObjectId, UpdateQuery } from "mongoose";
import bcrypt from "bcrypt";
import { USER_ROLE, USER_STATUS } from "@/utils/constants";

export interface IImages {
  image: string;
  etag: string;
}

// Email and Phone is optional here but we are mark either email or phone as required.
// We make sure email or phone is available in the validation schema.
export interface IUserSchema {
  _id: ObjectId;
  firstName?: string;
  lastName?: string;
  email?: string;
  isEmailVerified?: Date;
  phone?: string;
  isPhoneVerified?: Date;
  password?: string;
  role: (typeof USER_ROLE)[keyof typeof USER_ROLE];
  status: (typeof USER_STATUS)[keyof typeof USER_STATUS];
  avatar?: IImages;
  emailVerificationToken?: string;
  emailVerificationTokenExpiresAt?: Date;
  phoneVerificationToken?: string;
  phoneVerificationTokenExpiresAt?: Date;
  passwordResetToken?: string;
  passwordResetExpiresAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

const userSchema = new mongoose.Schema<IUserSchema>(
  {
    firstName: {
      type: String,
      lowercase: true,
      trim: true,
      minLength: 3,
      maxLength: 30,
    },
    lastName: {
      type: String,
      lowercase: true,
      trim: true,
      minLength: 3,
      maxLength: 30,
    },
    email: {
      type: String,
      lowercase: true,
      trim: true,
      unique: true,
      minLength: 3,
      maxLength: 50,
      sparse: true,
    },
    isEmailVerified: {
      type: Date,
    },
    phone: {
      type: String,
      trim: true,
      unique: true,
      minLength: 10,
      maxLength: 10,
      sparse: true,
    },
    isPhoneVerified: {
      type: Date,
    },
    password: {
      type: String,
    },
    role: {
      type: String,
      enum: [USER_ROLE.ADMIN, USER_ROLE.USER],
      default: USER_ROLE.USER,
    },
    status: {
      type: String,
      default: USER_STATUS.ACTIVE,
      enum: [USER_STATUS.ACTIVE, USER_STATUS.BLOCKED, USER_STATUS.DELETED],
    },
    avatar: {
      type: {
        image: { type: String, required: true },
        etag: { type: String, required: true },
      },
    },
    emailVerificationToken: {
      type: String,
    },
    emailVerificationTokenExpiresAt: {
      type: Date,
    },
    phoneVerificationToken: {
      type: String,
    },
    phoneVerificationTokenExpiresAt: {
      type: Date,
    },
    passwordResetToken: {
      type: String,
    },
    passwordResetExpiresAt: {
      type: Date,
    },
  },
  {
    timestamps: true,
    toJSON: { getters: true },
  }
);

userSchema.pre("save", async function (next) {
  if (this.password) {
    if (!this.isModified("password")) return next();
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(this.password, salt);
    this.password = hash;
  }
  next();
});

userSchema.pre("findOneAndUpdate", async function (next) {
  const update = this.getUpdate() as UpdateQuery<IUserSchema>;

  if (update && update.$set && update.$set.password) {
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(update.$set.password, salt);
    update.$set.password = hash;
  }
  next();
});

const UserModel = mongoose.model<IUserSchema>("users", userSchema);

export default UserModel;
