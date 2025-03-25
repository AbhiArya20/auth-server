export class SuccessResponse<T> {
  success: boolean;
  message?: string;
  code?: string;
  data?: T;

  constructor(response: { data?: T; message?: string; code?: string }) {
    this.success = true;
    this.data = response.data;
    this.code = response.code;
    this.message = response.message;
  }
}
