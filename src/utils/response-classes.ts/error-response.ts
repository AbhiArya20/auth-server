import {
  AUTHENTICATION_METHOD,
  ERROR_RESPONSE_CODE,
  ERROR_RESPONSE_MESSAGE,
  USER_STATUS,
} from "@/utils/constants";
import { ZodError } from "zod";
import { isMethodForMagicLink } from "@/utils/method";
class ErrorResponse<T> {
  success: boolean;
  code: string;
  message: string;
  error?: T;
  constructor(response: { code: string; message: string; error?: T }) {
    this.success = false;
    this.code = response.code;
    this.message = response.message;
    this.error = response.error;
  }
}

export default ErrorResponse;

export const createValidationErrorResponse = (error: ZodError) => {
  return new ErrorResponse({
    code: ERROR_RESPONSE_CODE.VALIDATION_ERROR,
    message:
      error?.errors[0]?.message ??
      ERROR_RESPONSE_MESSAGE.INVALID_REQUEST_BODY_MESSAGE,
    error: error,
  });
};

export const createAccountStatusErrorResponse = (
  status: (typeof USER_STATUS)[keyof typeof USER_STATUS]
) => {
  return new ErrorResponse({
    code:
      status == USER_STATUS.BLOCKED
        ? ERROR_RESPONSE_CODE.ACCOUNT_BLOCKED
        : ERROR_RESPONSE_CODE.ACCOUNT_DELETED,
    message:
      status == USER_STATUS.BLOCKED
        ? ERROR_RESPONSE_MESSAGE.ACCOUNT_BLOCKED_MESSAGE
        : ERROR_RESPONSE_MESSAGE.ACCOUNT_DELETED_MESSAGE,
  });
};

export const createInvalidRefreshTokenErrorResponse = () => {
  return new ErrorResponse({
    code: ERROR_RESPONSE_CODE.INVALID_TOKEN,
    message: ERROR_RESPONSE_MESSAGE.INVALID_ACCESS_TOKEN_MESSAGE,
  });
};

export const createServerErrorResponse = () => {
  return new ErrorResponse({
    code: ERROR_RESPONSE_CODE.SERVER_ERROR,
    message: ERROR_RESPONSE_MESSAGE.SERVER_ERROR_MESSAGE,
  });
};

export const createInvalidVerificationTokenErrorResponse = (
  method: AUTHENTICATION_METHOD
) => {
  return new ErrorResponse({
    code: isMethodForMagicLink(method)
      ? ERROR_RESPONSE_CODE.INVALID_LINK
      : ERROR_RESPONSE_CODE.INVALID_OTP,
    message: isMethodForMagicLink(method)
      ? ERROR_RESPONSE_MESSAGE.INVALID_VERIFICATION_LINK_MESSAGE
      : ERROR_RESPONSE_MESSAGE.INVALID_OTP_MESSAGE,
  });
};

export const createOtpUsedErrorResponse = () => {
  return new ErrorResponse({
    code: ERROR_RESPONSE_CODE.OTP_USED,
    message: ERROR_RESPONSE_MESSAGE.OTP_USED_MESSAGE,
  });
};
