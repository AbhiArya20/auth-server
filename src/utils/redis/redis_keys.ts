class RedisKeys {
  public static getRateLimiterKey(keySeparator: string, area = "root") {
    return `ratelimit:${keySeparator}:${area}`;
  }
  public static getUserKey(_id?: string) {
    return `user:${_id}`;
  }
  public static getUserStatusKey(_id?: string) {
    return `user:status:${_id}`;
  }
}
export default RedisKeys;
