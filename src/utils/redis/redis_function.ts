import Config from "@/config/config.js";
import RedisClient from "@/config/redis.js";

class RedisFunctions {
  public static async get<T>(
    key: string,
    fetchFromDatabaseCallback: () => Promise<T>
  ) {
    // Attempt to retrieve data from Redis cache
    const cachedData = await RedisClient.get(key);

    if (cachedData) {
      // If data exists in cache, parse and return it
      return JSON.parse(cachedData) as T;
    }

    // If no data in cache, fetch data from MongoDB
    const mongoData = await fetchFromDatabaseCallback();

    if (mongoData) {
      // If data is fetched from MongoDB, store it in Redis cache
      RedisClient.setex(key, Config.CACHE_TIME, JSON.stringify(mongoData));
    }

    return mongoData;
  }

  public static async update<T>(
    key: string,
    updateToDatabaseCallback: () => Promise<T>
  ) {
    // Update data in the database
    const updatedData = await updateToDatabaseCallback();

    // Update the cache with the new data
    await RedisClient.setex(
      key,
      Config.CACHE_TIME,
      JSON.stringify(updatedData)
    );

    return updatedData;
  }

  public static async clear<T>(
    key: string,
    clearFromDatabaseCallback: () => Promise<T>
  ) {
    // Clear data from the database
    const createdData = await clearFromDatabaseCallback();

    // Remove the cache entry for the given key
    await RedisClient.del(key);

    return createdData;
  }
}

export default RedisFunctions;
