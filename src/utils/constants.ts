class ERROR_RESPONSE_CODE {
  static readonly SERVER_ERROR = "SERVER_ERROR";
  static readonly INVALID_OTP = "INVALID_OTP";
  static readonly VALIDATION_ERROR = "VALIDATION_ERROR";
  static readonly INVALID_CREDENTIALS = "INVALID_CREDENTIALS";
  static readonly PASSWORD_NOT_SET = "PASSWORD_NOT_SET";
  static readonly UNVERIFIED_USER = "UNVERIFIED_USER";
  static readonly ACCOUNT_DELETED = "ACCOUNT_DELETED";
  static readonly ACCOUNT_BLOCKED = "ACCOUNT_BLOCKED";
  static readonly INVALID_TOKEN = "INVALID_TOKEN";
  static readonly NOT_FOUND = "NOT_FOUND";
  static readonly USER_ALREADY_REGISTERED = "USER_ALREADY_REGISTERED";
  static readonly USER_NOT_REGISTER = "USER_NOT_REGISTER";
  static readonly REQUEST_TIMEOUT = "REQUEST_TIMEOUT";
  static readonly INVALID_LINK = "INVALID_LINK";
  static readonly ALREADY_VERIFIED = "ALREADY_VERIFIED";
  static readonly OTP_SENT = "OTP_SENT";
  static readonly OTP_USED = "OTP_USED";
  static readonly INVALID_REQUEST_BODY = "INVALID_REQUEST_BODY";
}

class ERROR_RESPONSE_MESSAGE {
  static readonly SERVER_ERROR_MESSAGE = "Something unexpected occurred.";
  static readonly ROUTE_NOT_FOUND_MESSAGE =
    "The requested URL was not found on this server. That’s all we know.";

  static readonly USER_NOT_REGISTER =
    "We couldn't find an account associated with this information. Please make sure you've entered the correct details or create a new account.";
  static readonly INCORRECT_PASSWORD =
    "The password you entered is incorrect. Please try again.";
  static readonly PASSWORD_NOT_SET_MESSAGE =
    "Password has not been set. Please try login with another method.";
  static readonly UNVERIFIED_USER_MESSAGE =
    "Your account has not been verified yet. Please check your inbox for the verification link";
  static readonly ACCOUNT_DELETED_MESSAGE =
    "We couldn't find the account you're trying to access. It may have been deleted or never existed.";
  static readonly ACCOUNT_BLOCKED_MESSAGE =
    "Your account has been blocked. Please contact support for assistance.";
  static readonly EXPIRED_REFRESH_TOKEN_MESSAGE =
    "The refresh token has expired. Please log in again.";
  static readonly EXPIRED_ACCESS_TOKEN_MESSAGE =
    "The access token has expired. Please log in again.";
  static readonly INVALID_ACCESS_TOKEN_MESSAGE =
    "The access token is invalid. Please log in again.";
  static readonly INVALID_REFRESH_TOKEN_MESSAGE =
    "The refresh token is invalid. Please log in again.";
  static readonly USER_NOT_FOUND_MESSAGE =
    "We couldn't find an account with the provided information";
  static readonly USER_REGISTERED_MESSAGE =
    "An account is already associated with these details. Please use a different one or log in.";
  static readonly EXPIRE_VERIFICATION_LINK_MESSAGE =
    "The verification details has expired. Please request a new one.";
  static readonly OTP_EXPIRED_MESSAGE =
    "The OTP has expired. Please request a new one to continue.";
  static readonly INVALID_OTP_MESSAGE =
    "The OTP you entered is not valid. Please ensure the code is correct and try again.";
  static readonly EXPIRED_OTP_MESSAGE =
    "The OTP has expired. Please request a new one to continue.";
  static readonly INVALID_VERIFICATION_LINK_MESSAGE =
    "The token you provided is invalid. Please check the the token and try again.";
  static readonly ALREADY_VERIFIED_MESSAGE =
    "Your account has already been verified. Please log in to proceed.";
  static readonly OTP_SENT_MESSAGE =
    "An OTP has been sent to your account. Please check and enter it to proceed.";
  static readonly OTP_USED_MESSAGE =
    "Whoops! Looks like that OTP has already been used. Request a fresh one and try again";

  static readonly INVALID_REQUEST_BODY_MESSAGE =
    "The request body is invalid. Please check the request body and try again.";
}

class SUCCESS_RESPONSE_MESSAGE {
  static readonly REGISTRATION_SUCCESS_MESSAGE =
    "Registration successful. Please verify your account to complete the setup.";
  static readonly LOGIN_SUCCESS_MESSAGE = "Login successful. Welcome back!";

  static readonly OTP_SENT_MESSAGE =
    "An OTP has been sent. Please check and enter it to proceed.";
  static readonly VERIFICATION_LINK_SEND_MESSAGE =
    "A verification link has been sent to your account. Please check your inbox to complete the verification.";
  static readonly VERIFICATION_SUCCESSFUL_MESSAGE =
    "Your account has been verified successfully";
  static readonly REFRESH_TOKEN_SUCCESS_MESSAGE =
    "Your refresh token has been refreshed successfully";
  static readonly FORGOT_PASSWORD_INITIATED_MESSAGE =
    "A verification link has been sent to your account. Please check your inbox to complete the verification.";
  static readonly FORGOT_PASSWORD_SUCCESSFUL_MESSAGE =
    "Your password has been reset successfully";
  static readonly LOGOUT_SUCCESS_MESSAGE =
    "You have been logged out successfully";
  static readonly GET_CURRENT_USER_SUCCESS_MESSAGE =
    "Your account details have been fetched successfully";
  static readonly UPDATE_CURRENT_USER_SUCCESS_MESSAGE =
    "Your account details have been updated successfully";
}

class SUCCESS_RESPONSE_CODE {
  static readonly LOGIN_SUCCESS = "LOGIN_SUCCESS";
  static readonly REGISTRATION_SUCCESS = "REGISTRATION_SUCCESS";
  static readonly OTP_SENT = "OTP_SENT";
  static readonly VERIFICATION_LINK_SEND = "VERIFICATION_LINK_SEND";
  static readonly VERIFICATION_SUCCESSFUL = "VERIFICATION_SUCCESSFUL";
  static readonly REFRESH_TOKEN_SUCCESS = "REFRESH_TOKEN_SUCCESS";
  static readonly FORGOT_PASSWORD_INITIATED = "FORGOT_PASSWORD_INITIATED";
  static readonly FORGOT_PASSWORD_SUCCESSFUL = "FORGOT_PASSWORD_SUCCESSFUL";
  static readonly LOGOUT_SUCCESS = "LOGOUT_SUCCESS";
  static readonly GET_CURRENT_USER_SUCCESS = "GET_CURRENT_USER_SUCCESS";
  static readonly UPDATE_CURRENT_USER_SUCCESS = "UPDATE_CURRENT_USER_SUCCESS";
}

class USER_STATUS {
  static readonly ACTIVE = "ACTIVE";
  static readonly BLOCKED = "BLOCKED";
  static readonly DELETED = "DELETED";
}

class USER_ROLE {
  static readonly ADMIN = "ADMIN";
  static readonly USER = "USER";
}

class AUTHENTICATION_METHOD {
  static readonly MAGIC_LINK = "MAGIC_LINK";
  static readonly EMAIL_OTP = "EMAIL_OTP";
  static readonly SMS_OTP = "SMS_OTP";
  static readonly WHATSAPP_OTP = "WHATSAPP_OTP";
  static readonly PASSWORD = "PASSWORD";
}

export {
  ERROR_RESPONSE_CODE,
  ERROR_RESPONSE_MESSAGE,
  SUCCESS_RESPONSE_CODE,
  SUCCESS_RESPONSE_MESSAGE,
  USER_STATUS,
  USER_ROLE,
  AUTHENTICATION_METHOD,
};
