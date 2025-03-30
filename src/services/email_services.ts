import nodemailer, { Transporter } from "nodemailer";
import Config from "@/config/config";
import SMTPTransport from "nodemailer/lib/smtp-transport";
import StringFunction from "@/utils/string_functions";
import { AUTHENTICATION_METHOD } from "@/utils/constants";
import { formatDistanceToNow } from "date-fns";

class EmailService {
  // Static property to hold the instance
  private static instance: EmailService;

  private transporter: Transporter;

  // Private constructor to prevent direct instantiation
  private constructor() {
    const config: SMTPTransport.Options = {
      service: Config.SMTP_SERVICE,
      host: Config.SMTP_HOST,
      port: Config.SMTP_PORT,
      secure: true,
      auth: {
        user: Config.SMTP_EMAIL,
        pass: Config.SMTP_PASSWORD,
      },
    };

    this.transporter = nodemailer.createTransport(config);
  }

  // Public method to get the instance
  public static getInstance(): EmailService {
    if (!EmailService.instance) {
      EmailService.instance = new EmailService(); // Create an instance if it doesn't exist
    }
    return EmailService.instance; // Return the existing instance
  }

  async sendEmailHtml(email: string, html: string, subject: string) {
    this.transporter.sendMail({
      from: `"${Config.APP_NAME}" ${Config.SMTP_EMAIL}`,
      to: email,
      subject: subject,
      html,
    });
  }
}

export class SendEmailService {
  public static async sendVerifyEmail(
    email: string,
    name: string,
    hash: string,
    method: AUTHENTICATION_METHOD,
    forgotPassword: boolean
  ) {
    const emailServiceInstance = EmailService.getInstance();

    const verificationLink = `${Config.FRONTEND_URL}/verify?token=${hash}&email=${email}&method=${method}`;
    // TODO: Fix Send email for every method
    emailServiceInstance.sendEmailHtml(
      email,
      `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Email Verification</title>
    <style>
      /* Reset styles */
      body,
      table,
      td,
      a {
        -webkit-text-size-adjust: 100%;
        -ms-text-size-adjust: 100%;
        margin: 0;
        padding: 0;
      }

      /* Ensure tables work in email clients */
      table,
      td {
        mso-table-lspace: 0pt;
        mso-table-rspace: 0pt;
        border-collapse: collapse;
      }
    </style>
  </head>
  <body
    style="
      margin: 0;
      padding: 0;
      background-color: #f0f7ff;
      font-family: Arial, sans-serif;
    "
  >
    <table
      role="presentation"
      style="width: 100%; background-color: #f0f7ff; padding: 20px"
    >
      <!-- Logo -->
      <tr>
        <td align="center" style="padding: 40px 20px">
          <img
            src="${Config.APP_LOGO_URL}"
            alt="IP2LOCATION"
            style="width: 200px; height: auto"
          />
        </td>
      </tr>
      <tr>
        <td align="center" >
          <!-- Main Container -->
          <table
            role="presentation"
            style="
              display: inline-block;
              padding: 16px 0;
              max-width: 600px;
              width: 100%;
              background-color: #ffffff;
              border-radius: 8px;
              box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            "
          >
            <!-- Illustration -->
            <tr>
              <td align="center" >
                <img
                  src="https://ci3.googleusercontent.com/meips/ADKq_NbcKlZSVHd2ld6roCohFQtyTjK4ccJcZfRVm7Y3ahi4G1x7Fk7YtvCcCydz_fSYtlknaK1AVAUp4iWnx4_YfEx0BR03njxEmCt4ExCVJybVtQ=s0-d-e1-ft#https://cdn.ip2location.com/assets/img/tem-user-account.png"
                  alt="Verify Email Illustration"
                  style="width: 200px; height: auto"
                />
              </td>
            </tr>

            <!-- Content -->
            <tr>
              <td style="padding: 0 40px">
                <h1
                  style="
                    color: #333333;
                    text-align: center;
                    font-size: 28px;
                    margin-bottom: 15px;
                  "
                >
                  Just one more step
                </h1>
                <p
                  style="
                    color: #333333;
                    font-weight: 600;
                    font-size: 14px;
                    line-height: 1.5;
                    margin-bottom: 15px;
                  "
                >
                  Dear ${name ? StringFunction.capitalize(name) : "user" + ","}
                </p>
                ${
                  !forgotPassword
                    ? `<p
                  style="
                    color: #333333;
                    font-weight: 600;
                    font-size: 14px;
                    line-height: 1.5;
                    margin-bottom: 15px;
                  "
                >
                  Thank you for choosing ${Config.APP_NAME}.
                </p>
                <p
                  style="
                    color: #333333;
                    font-size: 14px;
                    font-weight: 600;
                    line-height: 1.5;
                    margin-bottom: 30px;
                  "
                >
                  Before you can login into your account, you need to click on
                  the link below to confirm your email address.
                </p>`
                    : ""
                }

                <!-- CTA Button -->
                <table role="presentation" style="width: 100%; margin: 30px 0">
                  <tr>
                    <td align="center">
                      <a
                        href="${verificationLink}"
                        style="
                          background-color: #696cff;
                          color: #ffffff;
                          padding: 15px 30px;
                          text-decoration: none;
                          border-radius: 5px;
                          font-weight: bold;
                          display: inline-block;
                          text-transform: uppercase;
                          font-size: 14px;
                        "
                      >
                        Confirm & Activate Your Account
                      </a>

                    </td>
                  </tr>
                </table>

                <p
                  style="
                    color: #666666;
                    font-size: 14px;
                    line-height: 1.5;
                    margin-bottom: 15px;
                  "
                >
                  Or, you can manually copy and paste the below link into a
                  browser for verification if the above button not working:
                </p>
                <a
                  href="${verificationLink}"
                  style="
                    color: #0066cc;
                    font-size: 14px;
                    line-height: 1.5;
                    margin-bottom: 30px;
                    word-break: break-all;
                  "
                >
                  ${verificationLink}
                </a>

                 <p
                  style="
                    color:rgb(255, 89, 89);
                    font-size: 14px;
                    line-height: 1.5;
                    margin-bottom: 15px;
                  "
                >
                  <span style="font-weight:600;">Note:</span> The verification link is valid for ${formatDistanceToNow(
                    new Date(
                      Date.now() + Config.VERIFICATION_TOKEN_EXPIRE_TIME * 1000
                    ),

                    { addSuffix: true }
                  )} from the time it is generated.
                </p>

                

                <p
                  style="
                    color: #666666;
                    font-size: 14px;
                    line-height: 1.5;
                    margin-bottom: 15px;
                  "
                >
                  Please visit our commercial web site
                  <a
                    href="${Config.FRONTEND_URL}"
                    style="color: #696cff; text-decoration: none"
                    >${Config.FRONTEND_URL}</a
                  >
                  for other products from us. We believe that our products offer
                  excellent features and are confident that you will agree like
                  many of our customers.
                </p>
              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- Footer -->
      <tr>
        <td align="center" style="padding: 10px">
          <div>
            <p>
              Need help? Feel free to reach out to us at
              <a href="mailto:${Config.APP_SUPPORT_EMAIL}">contact us</a>.
            </p>
            <p>
              &copy; ${new Date().getFullYear()} ${
        Config.APP_NAME
      }. All rights reserved.
            </p>
          </div>
        </td>
      </tr>
    </table>
  </body>
</html>

`,
      `Please verify your email address`
    );
  }

  public static async sendOTPEmail(email: string, name: string, OTP: number) {
    const emailServiceInstance = EmailService.getInstance();
    emailServiceInstance.sendEmailHtml(
      email,
      `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Email Verification</title>
    <style>
      /* Reset styles */
      body,
      table,
      td,
      a {
        -webkit-text-size-adjust: 100%;
        -ms-text-size-adjust: 100%;
        margin: 0;
        padding: 0;
      }

      /* Ensure tables work in email clients */
      table,
      td {
        mso-table-lspace: 0pt;
        mso-table-rspace: 0pt;
        border-collapse: collapse;
      }
    </style>
  </head>
  <body
    style="
      margin: 0;
      padding: 0;
      background-color: #f0f7ff;
      font-family: Arial, sans-serif;
    "
  >
    <table
      role="presentation"
      style="width: 100%; background-color: #f0f7ff; padding: 20px"
    >
      <!-- Logo -->
      <tr>
        <td align="center" style="padding: 40px 20px">
          <img
            src="${Config.APP_LOGO_URL}"
            alt="IP2LOCATION"
            style="width: 200px; height: auto"
          />
        </td>
      </tr>
      <tr>
        <td align="center" >
          <!-- Main Container -->
          <table
            role="presentation"
            style="
              display: inline-block;
              padding: 16px 0;
              max-width: 600px;
              width: 100%;
              background-color: #ffffff;
              border-radius: 8px;
              box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            "
          >
            <!-- Illustration -->
            <tr>
              <td align="center" >
                <img
                  src="https://img.freepik.com/free-vector/two-factor-authentication-concept-illustration_114360-5488.jpg?t=st=1734709842~exp=1734713442~hmac=c939f87009cc4b2064437eecb4649c1ec6c4cd3b0b3a9a18c526a4bbd0df4643&w=740"
                  alt="Verify Email Illustration"
                  style="width: 200px; height: auto"
                />
              </td>
            </tr>

            <!-- Content -->
            <tr>
              <td style="padding: 0 40px">
                <h1
                  style="
                    color: #333333;
                    text-align: center;
                    font-size: 28px;
                    margin-bottom: 15px;
                  "
                >
                  Forgot Password
                </h1>
                <p
                  style="
                    color: #333333;
                    font-weight: 600;
                    font-size: 14px;
                    line-height: 1.5;
                    margin-bottom: 15px;
                  "
                >
                  Dear ${name ? StringFunction.capitalize(name) : "user" + ","}
                </p>
                <p
                  style="
                    color: #333333;
                    font-weight: 600;
                    font-size: 14px;
                    line-height: 1.5;
                    margin-bottom: 15px;
                  "
                >
                  We received a request to reset the password for your account. To proceed, please use the following one-time code:
                </p>
                <p
                  style="
                    color: #ffffff;
                    font-size: 32px;
                    font-weight: 600;
                    line-height: 1.5;
                    margin-bottom: 30px;
                    text-align: center;
                    border-radius: 10px;
                    padding: 14px 0 14px 0;
                    background-color: #696cff;
                  "
                >
                ${OTP}
                </p>
                <p
                  style="
                    color: #333333;
                    font-size: 14px;
                    font-weight: 600;
                    line-height: 1.5;
                    margin-bottom: 30px;
                  "
                >
                This code is valid for 5 minutes. Please enter this code on the verification screen to proceed.
                </p>
   
                 <p
                  style="
                    color:rgb(255, 89, 89);
                    font-size: 14px;
                    line-height: 1.5;
                    margin-bottom: 15px;
                    font-weight: 600;
                  "
                >
                  <span style="font-weight:900;">Note:</span> For your security, do not share this code with anyone. If you did not request this code, please contact our support team immediately at <a href="mailto:${
                    Config.APP_SUPPORT_EMAIL
                  }">contact us</a>.
                </p>

                
              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- Footer -->
      <tr>
        <td align="center" style="padding: 10px">
          <div>
            <p>
              Need help? Feel free to reach out to us at
              <a href="mailto:${Config.APP_SUPPORT_EMAIL}">contact us</a>.
            </p>
            <p>
              &copy; ${new Date().getFullYear()} ${
        Config.APP_NAME
      }. All rights reserved.
            </p>
          </div>
        </td>
      </tr>
    </table>
  </body>
</html>`,
      `Forgot Password: Verify Your Email Address`
    );
  }
}

export default EmailService;
