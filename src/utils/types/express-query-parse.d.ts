// types/express-query-parser.d.ts
declare module "express-query-parser" {
  import { RequestHandler } from "express";

  type Cast = "boolean" | "number" | "string" | "array" | "default";
  type CastOption = boolean | Cast;

  interface QueryParserOptions {
    parseNull?: boolean;
    parseUndefined?: boolean;
    parseBoolean?: boolean;
    parseNumber?: boolean;
    parseArray?: boolean;
    parseWithPrefix?: "query" | "body" | "both";
    enable?: CastOption | { [key: string]: CastOption };
  }

  function queryParser(options?: QueryParserOptions): RequestHandler;

  export { queryParser };
}
