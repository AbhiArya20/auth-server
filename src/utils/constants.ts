class Constants {
  static readonly SERVER_ERROR_MESSAGE = "Something unexpected occurred.";
  static readonly ROUTE_NOT_FOUND_MESSAGE =
    "The requested URL was not found on this server. That’s all we know.";

  // Auth Controller
  static readonly USER_NOT_REGISTER =
    "We couldn't find an account associated with this information. Please make sure you've entered the correct details or create a new account.";
  static readonly INCORRECT_PASSWORD =
    "The password you entered is incorrect. Please try again.";
  static readonly PASSWORD_NOT_SET_MESSAGE =
    "Password has not been set. Please try logging in with another method.";
  static readonly UNVERIFIED_USER_MESSAGE =
    "Your account has not been verified yet. Please check your inbox for the verification link";
  static readonly ACCOUNT_DELETED_MESSAGE =
    "We couldn't find the account you're trying to access. It may have been deleted or never existed.";
  static readonly ACCOUNT_BLOCKED_MESSAGE =
    "Your account has been blocked. Please contact support for assistance.";
  static readonly LOGIN_SUCCESS_MESSAGE = "Login successful. Welcome back!";
  static readonly INVALID_REFRESH_TOKEN_MESSAGE =
    "The refresh token has expired. Please log in again.";
  static readonly INVALID_ACCESS_TOKEN_MESSAGE =
    "The access token has expired. Please log in again.";
  static readonly USER_NOT_FOUND_MESSAGE =
    "We couldn't find an account with the provided information";
  static readonly USER_REGISTERED_MESSAGE =
    "An account is already associated with these details. Please use a different one or log in.";
  static readonly REGISTRATION_SUCCESS_MESSAGE =
    "Registration successful. Please verify your account to complete the setup.";
  static readonly VERIFICATION_LINK_SEND_MESSAGE =
    "A verification link has been sent to your account. Please check your inbox to complete the verification.";
  static readonly EXPIRE_VERIFICATION_LINK_MESSAGE =
    "The verification link has expired. Please request a new one.";
  static readonly OTP_EXPIRED_MESSAGE =
    "The OTP has expired. Please request a new one to continue.";
  static readonly OTP_INVALID_MESSAGE =
    "The OTP you entered is not valid. Please ensure the code is correct and try again.";
  static readonly INVALID_VERIFICATION_LINK_MESSAGE =
    "The token you provided is invalid. Please check the the token and try again.";
  static readonly ALREADY_VERIFIED_MESSAGE =
    "Your account has already been verified. Please log in to proceed.";
  static readonly OTP_SENT_MESSAGE =
    "An OTP has been sent to your account. Please check and enter it to proceed.";
  static readonly OTP_USED_MESSAGE =
    "Whoops! Looks like that OTP has already been used. Request a fresh one and try again";
  static readonly VERIFICATION_SUCCESSFUL_MESSAGE =
    "Your account has been verified successfully";

  // Error Codes
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
  static readonly REQUEST_TIMEOUT = "REQUEST_TIMEOUT";
  static readonly INVALID_LINK = "INVALID_LINK";
  static readonly ALREADY_VERIFIED = "ALREADY_VERIFIED";
  static readonly OTP_SENT = "OTP_SENT";
  static readonly OTP_USED = "OTP_USED";

  // Success Code
  static readonly LOGIN_SUCCESS = "LOGIN_SUCCESS";
  static readonly REGISTRATION_SUCCESS = "REGISTRATION_SUCCESS";
  static readonly VERIFICATION_LINK_SEND = "VERIFICATION_LINK_SEND";
  static readonly VERIFICATION_SUCCESSFUL = "VERIFICATION_SUCCESSFUL";
}

class UserStatus {
  static readonly ACTIVE = "ACTIVE";
  static readonly BLOCKED = "BLOCKED";
  static readonly DELETED = "DELETED";
}

class UserRole {
  static readonly ADMIN = "ADMIN";
  static readonly USER = "USER";
}

class AuthenticationMethod {
  static readonly MAGIC_LINK = "MAGIC_LINK";
  static readonly EMAIL_OTP = "EMAIL_OTP";
  static readonly SMS_OTP = "SMS_OTP";
  static readonly WHATSAPP_OTP = "WHATSAPP_OTP";
  static readonly PASSWORD = "PASSWORD";
}

export { Constants, UserStatus, UserRole, AuthenticationMethod };
export default Constants;
