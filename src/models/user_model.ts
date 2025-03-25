import mongoose, { ObjectId, UpdateQuery } from "mongoose";
import bcrypt from "bcrypt";
import { UserRole, UserStatus } from "@/utils/constants";

export interface IImages {
  image: string;
  etag: string;
}

// Email and Phone is optional here but we should mark either email or phone as required.
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
  role: (typeof UserRole)[keyof typeof UserRole];
  status: (typeof UserStatus)[keyof typeof UserStatus];
  avatar?: IImages;
  verificationToken?: string;
  verificationTokenExpiresAt?: Date;
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
      enum: [UserRole.ADMIN, UserRole.USER],
      default: UserRole.USER,
    },
    status: {
      type: String,
      default: UserStatus.ACTIVE,
      enum: [UserStatus.ACTIVE, UserStatus.BLOCKED, UserStatus.DELETED],
    },
    avatar: {
      type: {
        image: { type: String, required: true },
        etag: { type: String, required: true },
      },
    },
    verificationToken: {
      type: String,
    },
    verificationTokenExpiresAt: {
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
