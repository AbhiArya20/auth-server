import { AUTHENTICATION_METHOD } from "@/utils/constants";

export function isEmailMethod(method: AUTHENTICATION_METHOD) {
  return (
    method === AUTHENTICATION_METHOD.MAGIC_LINK ||
    method === AUTHENTICATION_METHOD.EMAIL_OTP ||
    method === AUTHENTICATION_METHOD.PASSWORD
  );
}

export function isPhoneMethod(method: AUTHENTICATION_METHOD) {
  return (
    method === AUTHENTICATION_METHOD.SMS_OTP ||
    method === AUTHENTICATION_METHOD.WHATSAPP_OTP
  );
}

export function isMethodForOTP(method: AUTHENTICATION_METHOD) {
  return (
    method === AUTHENTICATION_METHOD.SMS_OTP ||
    method === AUTHENTICATION_METHOD.EMAIL_OTP ||
    method === AUTHENTICATION_METHOD.WHATSAPP_OTP
  );
}

export function isMethodForMagicLink(method: AUTHENTICATION_METHOD) {
  return (
    method === AUTHENTICATION_METHOD.MAGIC_LINK ||
    method === AUTHENTICATION_METHOD.PASSWORD
  );
}
