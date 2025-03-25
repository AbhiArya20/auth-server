class StringFunction {
  public static capitalize(str: string) {
    if (!str) return str;
    return str
      .split(" ")
      .map((word) => {
        return word.charAt(0).toUpperCase() + word.slice(1);
      })
      .join(" ");
  }
}

export default StringFunction;
