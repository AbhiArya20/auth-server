class RedisKeys {
  public static getRateLimiterKey(keySeparator: string, area = "root") {
    return `ratelimit:${keySeparator}:${area}`;
  }
  public static getUserKey(_id?: string) {
    return `user:${_id}`;
  }
}
export default RedisKeys;
