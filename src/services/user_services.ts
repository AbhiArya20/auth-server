import { FilterQuery, ObjectId, UpdateQuery } from "mongoose";
import UserModel, { IUserSchema } from "@/models/user_model";
import RedisFunctions from "@/utils/redis/redis_function";
import RedisKeys from "@/utils/redis/redis_keys";

class UserService {
  public static async find(
    query: FilterQuery<IUserSchema> = {},
    sort: Record<string, 1 | -1> = { createdAt: -1 },
    skip: number = 0,
    limit: number = 20
  ) {
    return await UserModel.find<IUserSchema>(query)
      .sort(sort)
      .skip(skip)
      .limit(limit);
  }

  public static async findOne(query: FilterQuery<IUserSchema>) {
    return await UserModel.findOne<IUserSchema>(query);
  }

  public static async findById(id: ObjectId | string) {
    const callback = async () => await UserModel.findById<IUserSchema>(id);
    return await RedisFunctions.get(
      RedisKeys.getUserKey(id?.toString()),
      callback
    );
  }

  public static async create(
    data: Omit<
      IUserSchema | "_id",
      | "isEmailVerified"
      | "isPhoneVerified"
      | "role"
      | "status"
      | "avatar"
      | "emailVerificationToken"
      | "emailVerificationTokenExpiresAt"
      | "phoneVerificationToken"
      | "phoneVerificationTokenExpiresAt"
      | "passwordResetToken"
      | "passwordResetExpiresAt"
    >
  ) {
    const user = new UserModel(data);
    const savedUser = (await user.save()).toObject();
    return savedUser as unknown as IUserSchema;
  }

  public static async updateOne(
    query: FilterQuery<IUserSchema>,
    data: UpdateQuery<IUserSchema>
  ) {
    return await UserModel.findOneAndUpdate<IUserSchema>(query, data, {
      new: true,
    });
  }

  public static async updateById(id: ObjectId, data: UpdateQuery<IUserSchema>) {
    const callback = async () =>
      await UserModel.findByIdAndUpdate<IUserSchema>(id, data, {
        new: true,
      });
    return await RedisFunctions.update(
      RedisKeys.getUserKey(id?.toString()),
      callback
    );
  }

  public static async getCount(query: FilterQuery<IUserSchema> = {}) {
    return await UserModel.find(query).countDocuments();
  }
}

export default UserService;
