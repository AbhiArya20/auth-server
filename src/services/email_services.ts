import nodemailer, { Transporter } from "nodemailer";
import Config from "@/config/config.js";
import SMTPTransport from "nodemailer/lib/smtp-transport";
import StringFunction from "@/utils/string_functions.js";
import Constants, { AuthenticationMethod } from "@/utils/constants";
class EmailServices {
  // Static property to hold the instance
  private static instance: EmailServices;

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
  public static getInstance(): EmailServices {
    if (!EmailServices.instance) {
      EmailServices.instance = new EmailServices(); // Create an instance if it doesn't exist
    }
    return EmailServices.instance; // Return the existing instance
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
    hash: string
  ) {
    const emailServiceInstance = EmailServices.getInstance();

    const verificationLink = `${Config.FRONTEND_URL}/verify?hash=${hash}&email=${email}&method=${AuthenticationMethod.MAGIC_LINK}`;

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
                  Dear ${StringFunction.capitalize(name)},
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
                  Thank you for signing up ${Config.APP_NAME}.
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
                </p>

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
                  <span style="font-weight:600;">Note:</span> The verification link is valid for 30 minutes from the time it is generated.
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

      <!-- Social Links -->
      <tr>
        <td align="center" style="padding: 0 0 20px 0">
          <table role="presentation">
            <tr>
              <td style="padding: 0 10px">
                  <a
                    href="${Config.FRONTEND_URL}"
                    style="text-decoration: none"
                  >
                    <img style="width:24px; height: 24px" src='data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz48IS0tIFVwbG9hZGVkIHRvOiBTVkcgUmVwbywgd3d3LnN2Z3JlcG8uY29tLCBHZW5lcmF0b3I6IFNWRyBSZXBvIE1peGVyIFRvb2xzIC0tPgo8c3ZnIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIKYXJpYS1sYWJlbD0iRmFjZWJvb2siIHJvbGU9ImltZyIKdmlld0JveD0iMCAwIDUxMiA1MTIiPjxyZWN0CndpZHRoPSI1MTIiIGhlaWdodD0iNTEyIgpyeD0iMTUlIgpmaWxsPSIjMTg3N2YyIi8+PHBhdGggZD0iTTM1NS42IDMzMGwxMS40LTc0aC03MXYtNDhjMC0yMC4yIDkuOS00MCA0MS43LTQwSDM3MHYtNjNzLTI5LjMtNS01Ny4zLTVjLTU4LjUgMC05Ni43IDM1LjQtOTYuNyA5OS42VjI1NmgtNjV2NzRoNjV2MTgyaDgwVjMzMGg1OS42eiIgZmlsbD0iI2ZmZmZmZiIvPjwvc3ZnPg=='/>
                  </a>           
              </td>
              <td style="padding: 0 10px">
                <a href="${Config.FRONTEND_URL}" style="text-decoration: none">
                  <img style="width:24px; height: 24px" src='data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz48IS0tIFVwbG9hZGVkIHRvOiBTVkcgUmVwbywgd3d3LnN2Z3JlcG8uY29tLCBHZW5lcmF0b3I6IFNWRyBSZXBvIE1peGVyIFRvb2xzIC0tPgo8c3ZnIHdpZHRoPSI4MDBweCIgaGVpZ2h0PSI4MDBweCIgdmlld0JveD0iMCAwIDE2IDE2IiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIGZpbGw9Im5vbmUiPjxwYXRoIGZpbGw9IiMwQTY2QzIiIGQ9Ik0xMi4yMjUgMTIuMjI1aC0xLjc3OFY5LjQ0YzAtLjY2NC0uMDEyLTEuNTE5LS45MjUtMS41MTktLjkyNiAwLTEuMDY4LjcyNC0xLjA2OCAxLjQ3djIuODM0SDYuNjc2VjYuNDk4aDEuNzA3di43ODNoLjAyNGMuMzQ4LS41OTQuOTk2LS45NSAxLjY4NC0uOTI1IDEuODAyIDAgMi4xMzUgMS4xODUgMi4xMzUgMi43MjhsLS4wMDEgMy4xNHpNNC42NyA1LjcxNWExLjAzNyAxLjAzNyAwIDAxLTEuMDMyLTEuMDMxYzAtLjU2Ni40NjYtMS4wMzIgMS4wMzItMS4wMzIuNTY2IDAgMS4wMzEuNDY2IDEuMDMyIDEuMDMyIDAgLjU2Ni0uNDY2IDEuMDMyLTEuMDMyIDEuMDMyem0uODg5IDYuNTFoLTEuNzhWNi40OThoMS43OHY1LjcyN3pNMTMuMTEgMkgyLjg4NUEuODguODggMCAwMDIgMi44NjZ2MTAuMjY4YS44OC44OCAwIDAwLjg4NS44NjZoMTAuMjI2YS44ODIuODgyIDAgMDAuODg5LS44NjZWMi44NjVhLjg4Ljg4IDAgMDAtLjg4OS0uODY0eiIvPjwvc3ZnPg=='/>
                </a>
              </td>
              <td style="padding: 0 10px">
                <a href="${Config.FRONTEND_URL}" style="text-decoration: none">
                  <img style="width:24px; height: 24px" src='data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz48IS0tIFVwbG9hZGVkIHRvOiBTVkcgUmVwbywgd3d3LnN2Z3JlcG8uY29tLCBHZW5lcmF0b3I6IFNWRyBSZXBvIE1peGVyIFRvb2xzIC0tPgo8c3ZnIHdpZHRoPSI4MDBweCIgaGVpZ2h0PSI4MDBweCIgdmlld0JveD0iMCAwIDMyIDMyIiBmaWxsPSJub25lIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPg0KPHJlY3QgeD0iMiIgeT0iMiIgd2lkdGg9IjI4IiBoZWlnaHQ9IjI4IiByeD0iNiIgZmlsbD0idXJsKCNwYWludDBfcmFkaWFsXzg3XzcxNTMpIi8+DQo8cmVjdCB4PSIyIiB5PSIyIiB3aWR0aD0iMjgiIGhlaWdodD0iMjgiIHJ4PSI2IiBmaWxsPSJ1cmwoI3BhaW50MV9yYWRpYWxfODdfNzE1MykiLz4NCjxyZWN0IHg9IjIiIHk9IjIiIHdpZHRoPSIyOCIgaGVpZ2h0PSIyOCIgcng9IjYiIGZpbGw9InVybCgjcGFpbnQyX3JhZGlhbF84N183MTUzKSIvPg0KPHBhdGggZD0iTTIzIDEwLjVDMjMgMTEuMzI4NCAyMi4zMjg0IDEyIDIxLjUgMTJDMjAuNjcxNiAxMiAyMCAxMS4zMjg0IDIwIDEwLjVDMjAgOS42NzE1NyAyMC42NzE2IDkgMjEuNSA5QzIyLjMyODQgOSAyMyA5LjY3MTU3IDIzIDEwLjVaIiBmaWxsPSJ3aGl0ZSIvPg0KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xNiAyMUMxOC43NjE0IDIxIDIxIDE4Ljc2MTQgMjEgMTZDMjEgMTMuMjM4NiAxOC43NjE0IDExIDE2IDExQzEzLjIzODYgMTEgMTEgMTMuMjM4NiAxMSAxNkMxMSAxOC43NjE0IDEzLjIzODYgMjEgMTYgMjFaTTE2IDE5QzE3LjY1NjkgMTkgMTkgMTcuNjU2OSAxOSAxNkMxOSAxNC4zNDMxIDE3LjY1NjkgMTMgMTYgMTNDMTQuMzQzMSAxMyAxMyAxNC4zNDMxIDEzIDE2QzEzIDE3LjY1NjkgMTQuMzQzMSAxOSAxNiAxOVoiIGZpbGw9IndoaXRlIi8+DQo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTYgMTUuNkM2IDEyLjIzOTcgNiAxMC41NTk1IDYuNjUzOTYgOS4yNzYwNkM3LjIyOTIgOC4xNDcwOCA4LjE0NzA4IDcuMjI5MiA5LjI3NjA2IDYuNjUzOTZDMTAuNTU5NSA2IDEyLjIzOTcgNiAxNS42IDZIMTYuNEMxOS43NjAzIDYgMjEuNDQwNSA2IDIyLjcyMzkgNi42NTM5NkMyMy44NTI5IDcuMjI5MiAyNC43NzA4IDguMTQ3MDggMjUuMzQ2IDkuMjc2MDZDMjYgMTAuNTU5NSAyNiAxMi4yMzk3IDI2IDE1LjZWMTYuNEMyNiAxOS43NjAzIDI2IDIxLjQ0MDUgMjUuMzQ2IDIyLjcyMzlDMjQuNzcwOCAyMy44NTI5IDIzLjg1MjkgMjQuNzcwOCAyMi43MjM5IDI1LjM0NkMyMS40NDA1IDI2IDE5Ljc2MDMgMjYgMTYuNCAyNkgxNS42QzEyLjIzOTcgMjYgMTAuNTU5NSAyNiA5LjI3NjA2IDI1LjM0NkM4LjE0NzA4IDI0Ljc3MDggNy4yMjkyIDIzLjg1MjkgNi42NTM5NiAyMi43MjM5QzYgMjEuNDQwNSA2IDE5Ljc2MDMgNiAxNi40VjE1LjZaTTE1LjYgOEgxNi40QzE4LjExMzIgOCAxOS4yNzc3IDguMDAxNTYgMjAuMTc3OSA4LjA3NTFDMjEuMDU0OCA4LjE0Njc0IDIxLjUwMzIgOC4yNzY1OSAyMS44MTYgOC40MzU5N0MyMi41Njg2IDguODE5NDcgMjMuMTgwNSA5LjQzMTM5IDIzLjU2NCAxMC4xODRDMjMuNzIzNCAxMC40OTY4IDIzLjg1MzMgMTAuOTQ1MiAyMy45MjQ5IDExLjgyMjFDMjMuOTk4NCAxMi43MjIzIDI0IDEzLjg4NjggMjQgMTUuNlYxNi40QzI0IDE4LjExMzIgMjMuOTk4NCAxOS4yNzc3IDIzLjkyNDkgMjAuMTc3OUMyMy44NTMzIDIxLjA1NDggMjMuNzIzNCAyMS41MDMyIDIzLjU2NCAyMS44MTZDMjMuMTgwNSAyMi41Njg2IDIyLjU2ODYgMjMuMTgwNSAyMS44MTYgMjMuNTY0QzIxLjUwMzIgMjMuNzIzNCAyMS4wNTQ4IDIzLjg1MzMgMjAuMTc3OSAyMy45MjQ5QzE5LjI3NzcgMjMuOTk4NCAxOC4xMTMyIDI0IDE2LjQgMjRIMTUuNkMxMy44ODY4IDI0IDEyLjcyMjMgMjMuOTk4NCAxMS44MjIxIDIzLjkyNDlDMTAuOTQ1MiAyMy44NTMzIDEwLjQ5NjggMjMuNzIzNCAxMC4xODQgMjMuNTY0QzkuNDMxMzkgMjMuMTgwNSA4LjgxOTQ3IDIyLjU2ODYgOC40MzU5NyAyMS44MTZDOC4yNzY1OSAyMS41MDMyIDguMTQ2NzQgMjEuMDU0OCA4LjA3NTEgMjAuMTc3OUM4LjAwMTU2IDE5LjI3NzcgOCAxOC4xMTMyIDggMTYuNFYxNS42QzggMTMuODg2OCA4LjAwMTU2IDEyLjcyMjMgOC4wNzUxIDExLjgyMjFDOC4xNDY3NCAxMC45NDUyIDguMjc2NTkgMTAuNDk2OCA4LjQzNTk3IDEwLjE4NEM4LjgxOTQ3IDkuNDMxMzkgOS40MzEzOSA4LjgxOTQ3IDEwLjE4NCA4LjQzNTk3QzEwLjQ5NjggOC4yNzY1OSAxMC45NDUyIDguMTQ2NzQgMTEuODIyMSA4LjA3NTFDMTIuNzIyMyA4LjAwMTU2IDEzLjg4NjggOCAxNS42IDhaIiBmaWxsPSJ3aGl0ZSIvPg0KPGRlZnM+DQo8cmFkaWFsR3JhZGllbnQgaWQ9InBhaW50MF9yYWRpYWxfODdfNzE1MyIgY3g9IjAiIGN5PSIwIiByPSIxIiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSIgZ3JhZGllbnRUcmFuc2Zvcm09InRyYW5zbGF0ZSgxMiAyMykgcm90YXRlKC01NS4zNzU4KSBzY2FsZSgyNS41MTk2KSI+DQo8c3RvcCBzdG9wLWNvbG9yPSIjQjEzNTg5Ii8+DQo8c3RvcCBvZmZzZXQ9IjAuNzkzMDkiIHN0b3AtY29sb3I9IiNDNjJGOTQiLz4NCjxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iIzhBM0FDOCIvPg0KPC9yYWRpYWxHcmFkaWVudD4NCjxyYWRpYWxHcmFkaWVudCBpZD0icGFpbnQxX3JhZGlhbF84N183MTUzIiBjeD0iMCIgY3k9IjAiIHI9IjEiIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIiBncmFkaWVudFRyYW5zZm9ybT0idHJhbnNsYXRlKDExIDMxKSByb3RhdGUoLTY1LjEzNjMpIHNjYWxlKDIyLjU5NDIpIj4NCjxzdG9wIHN0b3AtY29sb3I9IiNFMEU4QjciLz4NCjxzdG9wIG9mZnNldD0iMC40NDQ2NjIiIHN0b3AtY29sb3I9IiNGQjhBMkUiLz4NCjxzdG9wIG9mZnNldD0iMC43MTQ3NCIgc3RvcC1jb2xvcj0iI0UyNDI1QyIvPg0KPHN0b3Agb2Zmc2V0PSIxIiBzdG9wLWNvbG9yPSIjRTI0MjVDIiBzdG9wLW9wYWNpdHk9IjAiLz4NCjwvcmFkaWFsR3JhZGllbnQ+DQo8cmFkaWFsR3JhZGllbnQgaWQ9InBhaW50Ml9yYWRpYWxfODdfNzE1MyIgY3g9IjAiIGN5PSIwIiByPSIxIiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSIgZ3JhZGllbnRUcmFuc2Zvcm09InRyYW5zbGF0ZSgwLjUwMDAwMiAzKSByb3RhdGUoLTguMTMwMSkgc2NhbGUoMzguODkwOSA4LjMxODM2KSI+DQo8c3RvcCBvZmZzZXQ9IjAuMTU2NzAxIiBzdG9wLWNvbG9yPSIjNDA2QURDIi8+DQo8c3RvcCBvZmZzZXQ9IjAuNDY3Nzk5IiBzdG9wLWNvbG9yPSIjNkE0NUJFIi8+DQo8c3RvcCBvZmZzZXQ9IjEiIHN0b3AtY29sb3I9IiM2QTQ1QkUiIHN0b3Atb3BhY2l0eT0iMCIvPg0KPC9yYWRpYWxHcmFkaWVudD4NCjwvZGVmcz4NCjwvc3ZnPg=='/>
                </a>
              </td>
              <td style="padding: 0 10px">
                <a href="${Config.FRONTEND_URL}" style="text-decoration: none">
                 <img style="width:24px; height: 24px" src='data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz48IS0tIFVwbG9hZGVkIHRvOiBTVkcgUmVwbywgd3d3LnN2Z3JlcG8uY29tLCBHZW5lcmF0b3I6IFNWRyBSZXBvIE1peGVyIFRvb2xzIC0tPgo8c3ZnIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIKYXJpYS1sYWJlbD0iVHdpdHRlciIgcm9sZT0iaW1nIgp2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PHJlY3QKd2lkdGg9IjUxMiIgaGVpZ2h0PSI1MTIiCnJ4PSIxNSUiCmZpbGw9IiMxZGExZjIiLz48cGF0aCBmaWxsPSIjZmZmZmZmIiBkPSJNNDM3IDE1MmE3MiA3MiAwIDAxLTQwIDEyYTcyIDcyIDAgMDAzMi00MGE3MiA3MiAwIDAxLTQ1IDE3YTcyIDcyIDAgMDAtMTIyIDY1YTIwMCAyMDAgMCAwMS0xNDUtNzRhNzIgNzIgMCAwMDIyIDk0YTcyIDcyIDAgMDEtMzItN2E3MiA3MiAwIDAwNTYgNjlhNzIgNzIgMCAwMS0zMiAxYTcyIDcyIDAgMDA2NyA1MGEyMDAgMjAwIDAgMDEtMTA1IDI5YTIwMCAyMDAgMCAwMDMwOS0xNzlhMjAwIDIwMCAwIDAwMzUtMzciLz48L3N2Zz4='/>
                </a>
              </span>
              </td>
            </tr>
          </table>
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
    const emailServiceInstance = EmailServices.getInstance();
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
                  Hello ${StringFunction.capitalize(name)},
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

      <!-- Social Links -->
      <tr>
        <td align="center" style="padding: 0 0 20px 0">
          <table role="presentation">
            <tr>
              <td style="padding: 0 10px">
                  <a
                    href="${Config.APP_FACEBOOK_URL}"
                    style="text-decoration: none"
                  >
                    <img style="width:24px; height: 24px" src='data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz48IS0tIFVwbG9hZGVkIHRvOiBTVkcgUmVwbywgd3d3LnN2Z3JlcG8uY29tLCBHZW5lcmF0b3I6IFNWRyBSZXBvIE1peGVyIFRvb2xzIC0tPgo8c3ZnIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIKYXJpYS1sYWJlbD0iRmFjZWJvb2siIHJvbGU9ImltZyIKdmlld0JveD0iMCAwIDUxMiA1MTIiPjxyZWN0CndpZHRoPSI1MTIiIGhlaWdodD0iNTEyIgpyeD0iMTUlIgpmaWxsPSIjMTg3N2YyIi8+PHBhdGggZD0iTTM1NS42IDMzMGwxMS40LTc0aC03MXYtNDhjMC0yMC4yIDkuOS00MCA0MS43LTQwSDM3MHYtNjNzLTI5LjMtNS01Ny4zLTVjLTU4LjUgMC05Ni43IDM1LjQtOTYuNyA5OS42VjI1NmgtNjV2NzRoNjV2MTgyaDgwVjMzMGg1OS42eiIgZmlsbD0iI2ZmZmZmZiIvPjwvc3ZnPg=='/>
                  </a>           
              </td>
              <td style="padding: 0 10px">
                <a href="${
                  Config.APP_LINKEDIN_URL
                }" style="text-decoration: none">
                  <img style="width:24px; height: 24px" src='data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz48IS0tIFVwbG9hZGVkIHRvOiBTVkcgUmVwbywgd3d3LnN2Z3JlcG8uY29tLCBHZW5lcmF0b3I6IFNWRyBSZXBvIE1peGVyIFRvb2xzIC0tPgo8c3ZnIHdpZHRoPSI4MDBweCIgaGVpZ2h0PSI4MDBweCIgdmlld0JveD0iMCAwIDE2IDE2IiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIGZpbGw9Im5vbmUiPjxwYXRoIGZpbGw9IiMwQTY2QzIiIGQ9Ik0xMi4yMjUgMTIuMjI1aC0xLjc3OFY5LjQ0YzAtLjY2NC0uMDEyLTEuNTE5LS45MjUtMS41MTktLjkyNiAwLTEuMDY4LjcyNC0xLjA2OCAxLjQ3djIuODM0SDYuNjc2VjYuNDk4aDEuNzA3di43ODNoLjAyNGMuMzQ4LS41OTQuOTk2LS45NSAxLjY4NC0uOTI1IDEuODAyIDAgMi4xMzUgMS4xODUgMi4xMzUgMi43MjhsLS4wMDEgMy4xNHpNNC42NyA1LjcxNWExLjAzNyAxLjAzNyAwIDAxLTEuMDMyLTEuMDMxYzAtLjU2Ni40NjYtMS4wMzIgMS4wMzItMS4wMzIuNTY2IDAgMS4wMzEuNDY2IDEuMDMyIDEuMDMyIDAgLjU2Ni0uNDY2IDEuMDMyLTEuMDMyIDEuMDMyem0uODg5IDYuNTFoLTEuNzhWNi40OThoMS43OHY1LjcyN3pNMTMuMTEgMkgyLjg4NUEuODguODggMCAwMDIgMi44NjZ2MTAuMjY4YS44OC44OCAwIDAwLjg4NS44NjZoMTAuMjI2YS44ODIuODgyIDAgMDAuODg5LS44NjZWMi44NjVhLjg4Ljg4IDAgMDAtLjg4OS0uODY0eiIvPjwvc3ZnPg=='/>
                </a>
              </td>
              <td style="padding: 0 10px">
                <a href="${
                  Config.APP_INSTAGRAM_URL
                }" style="text-decoration: none">
                  <img style="width:24px; height: 24px" src='data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz48IS0tIFVwbG9hZGVkIHRvOiBTVkcgUmVwbywgd3d3LnN2Z3JlcG8uY29tLCBHZW5lcmF0b3I6IFNWRyBSZXBvIE1peGVyIFRvb2xzIC0tPgo8c3ZnIHdpZHRoPSI4MDBweCIgaGVpZ2h0PSI4MDBweCIgdmlld0JveD0iMCAwIDMyIDMyIiBmaWxsPSJub25lIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPg0KPHJlY3QgeD0iMiIgeT0iMiIgd2lkdGg9IjI4IiBoZWlnaHQ9IjI4IiByeD0iNiIgZmlsbD0idXJsKCNwYWludDBfcmFkaWFsXzg3XzcxNTMpIi8+DQo8cmVjdCB4PSIyIiB5PSIyIiB3aWR0aD0iMjgiIGhlaWdodD0iMjgiIHJ4PSI2IiBmaWxsPSJ1cmwoI3BhaW50MV9yYWRpYWxfODdfNzE1MykiLz4NCjxyZWN0IHg9IjIiIHk9IjIiIHdpZHRoPSIyOCIgaGVpZ2h0PSIyOCIgcng9IjYiIGZpbGw9InVybCgjcGFpbnQyX3JhZGlhbF84N183MTUzKSIvPg0KPHBhdGggZD0iTTIzIDEwLjVDMjMgMTEuMzI4NCAyMi4zMjg0IDEyIDIxLjUgMTJDMjAuNjcxNiAxMiAyMCAxMS4zMjg0IDIwIDEwLjVDMjAgOS42NzE1NyAyMC42NzE2IDkgMjEuNSA5QzIyLjMyODQgOSAyMyA5LjY3MTU3IDIzIDEwLjVaIiBmaWxsPSJ3aGl0ZSIvPg0KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xNiAyMUMxOC43NjE0IDIxIDIxIDE4Ljc2MTQgMjEgMTZDMjEgMTMuMjM4NiAxOC43NjE0IDExIDE2IDExQzEzLjIzODYgMTEgMTEgMTMuMjM4NiAxMSAxNkMxMSAxOC43NjE0IDEzLjIzODYgMjEgMTYgMjFaTTE2IDE5QzE3LjY1NjkgMTkgMTkgMTcuNjU2OSAxOSAxNkMxOSAxNC4zNDMxIDE3LjY1NjkgMTMgMTYgMTNDMTQuMzQzMSAxMyAxMyAxNC4zNDMxIDEzIDE2QzEzIDE3LjY1NjkgMTQuMzQzMSAxOSAxNiAxOVoiIGZpbGw9IndoaXRlIi8+DQo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTYgMTUuNkM2IDEyLjIzOTcgNiAxMC41NTk1IDYuNjUzOTYgOS4yNzYwNkM3LjIyOTIgOC4xNDcwOCA4LjE0NzA4IDcuMjI5MiA5LjI3NjA2IDYuNjUzOTZDMTAuNTU5NSA2IDEyLjIzOTcgNiAxNS42IDZIMTYuNEMxOS43NjAzIDYgMjEuNDQwNSA2IDIyLjcyMzkgNi42NTM5NkMyMy44NTI5IDcuMjI5MiAyNC43NzA4IDguMTQ3MDggMjUuMzQ2IDkuMjc2MDZDMjYgMTAuNTU5NSAyNiAxMi4yMzk3IDI2IDE1LjZWMTYuNEMyNiAxOS43NjAzIDI2IDIxLjQ0MDUgMjUuMzQ2IDIyLjcyMzlDMjQuNzcwOCAyMy44NTI5IDIzLjg1MjkgMjQuNzcwOCAyMi43MjM5IDI1LjM0NkMyMS40NDA1IDI2IDE5Ljc2MDMgMjYgMTYuNCAyNkgxNS42QzEyLjIzOTcgMjYgMTAuNTU5NSAyNiA5LjI3NjA2IDI1LjM0NkM4LjE0NzA4IDI0Ljc3MDggNy4yMjkyIDIzLjg1MjkgNi42NTM5NiAyMi43MjM5QzYgMjEuNDQwNSA2IDE5Ljc2MDMgNiAxNi40VjE1LjZaTTE1LjYgOEgxNi40QzE4LjExMzIgOCAxOS4yNzc3IDguMDAxNTYgMjAuMTc3OSA4LjA3NTFDMjEuMDU0OCA4LjE0Njc0IDIxLjUwMzIgOC4yNzY1OSAyMS44MTYgOC40MzU5N0MyMi41Njg2IDguODE5NDcgMjMuMTgwNSA5LjQzMTM5IDIzLjU2NCAxMC4xODRDMjMuNzIzNCAxMC40OTY4IDIzLjg1MzMgMTAuOTQ1MiAyMy45MjQ5IDExLjgyMjFDMjMuOTk4NCAxMi43MjIzIDI0IDEzLjg4NjggMjQgMTUuNlYxNi40QzI0IDE4LjExMzIgMjMuOTk4NCAxOS4yNzc3IDIzLjkyNDkgMjAuMTc3OUMyMy44NTMzIDIxLjA1NDggMjMuNzIzNCAyMS41MDMyIDIzLjU2NCAyMS44MTZDMjMuMTgwNSAyMi41Njg2IDIyLjU2ODYgMjMuMTgwNSAyMS44MTYgMjMuNTY0QzIxLjUwMzIgMjMuNzIzNCAyMS4wNTQ4IDIzLjg1MzMgMjAuMTc3OSAyMy45MjQ5QzE5LjI3NzcgMjMuOTk4NCAxOC4xMTMyIDI0IDE2LjQgMjRIMTUuNkMxMy44ODY4IDI0IDEyLjcyMjMgMjMuOTk4NCAxMS44MjIxIDIzLjkyNDlDMTAuOTQ1MiAyMy44NTMzIDEwLjQ5NjggMjMuNzIzNCAxMC4xODQgMjMuNTY0QzkuNDMxMzkgMjMuMTgwNSA4LjgxOTQ3IDIyLjU2ODYgOC40MzU5NyAyMS44MTZDOC4yNzY1OSAyMS41MDMyIDguMTQ2NzQgMjEuMDU0OCA4LjA3NTEgMjAuMTc3OUM4LjAwMTU2IDE5LjI3NzcgOCAxOC4xMTMyIDggMTYuNFYxNS42QzggMTMuODg2OCA4LjAwMTU2IDEyLjcyMjMgOC4wNzUxIDExLjgyMjFDOC4xNDY3NCAxMC45NDUyIDguMjc2NTkgMTAuNDk2OCA4LjQzNTk3IDEwLjE4NEM4LjgxOTQ3IDkuNDMxMzkgOS40MzEzOSA4LjgxOTQ3IDEwLjE4NCA4LjQzNTk3QzEwLjQ5NjggOC4yNzY1OSAxMC45NDUyIDguMTQ2NzQgMTEuODIyMSA4LjA3NTFDMTIuNzIyMyA4LjAwMTU2IDEzLjg4NjggOCAxNS42IDhaIiBmaWxsPSJ3aGl0ZSIvPg0KPGRlZnM+DQo8cmFkaWFsR3JhZGllbnQgaWQ9InBhaW50MF9yYWRpYWxfODdfNzE1MyIgY3g9IjAiIGN5PSIwIiByPSIxIiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSIgZ3JhZGllbnRUcmFuc2Zvcm09InRyYW5zbGF0ZSgxMiAyMykgcm90YXRlKC01NS4zNzU4KSBzY2FsZSgyNS41MTk2KSI+DQo8c3RvcCBzdG9wLWNvbG9yPSIjQjEzNTg5Ii8+DQo8c3RvcCBvZmZzZXQ9IjAuNzkzMDkiIHN0b3AtY29sb3I9IiNDNjJGOTQiLz4NCjxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iIzhBM0FDOCIvPg0KPC9yYWRpYWxHcmFkaWVudD4NCjxyYWRpYWxHcmFkaWVudCBpZD0icGFpbnQxX3JhZGlhbF84N183MTUzIiBjeD0iMCIgY3k9IjAiIHI9IjEiIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIiBncmFkaWVudFRyYW5zZm9ybT0idHJhbnNsYXRlKDExIDMxKSByb3RhdGUoLTY1LjEzNjMpIHNjYWxlKDIyLjU5NDIpIj4NCjxzdG9wIHN0b3AtY29sb3I9IiNFMEU4QjciLz4NCjxzdG9wIG9mZnNldD0iMC40NDQ2NjIiIHN0b3AtY29sb3I9IiNGQjhBMkUiLz4NCjxzdG9wIG9mZnNldD0iMC43MTQ3NCIgc3RvcC1jb2xvcj0iI0UyNDI1QyIvPg0KPHN0b3Agb2Zmc2V0PSIxIiBzdG9wLWNvbG9yPSIjRTI0MjVDIiBzdG9wLW9wYWNpdHk9IjAiLz4NCjwvcmFkaWFsR3JhZGllbnQ+DQo8cmFkaWFsR3JhZGllbnQgaWQ9InBhaW50Ml9yYWRpYWxfODdfNzE1MyIgY3g9IjAiIGN5PSIwIiByPSIxIiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSIgZ3JhZGllbnRUcmFuc2Zvcm09InRyYW5zbGF0ZSgwLjUwMDAwMiAzKSByb3RhdGUoLTguMTMwMSkgc2NhbGUoMzguODkwOSA4LjMxODM2KSI+DQo8c3RvcCBvZmZzZXQ9IjAuMTU2NzAxIiBzdG9wLWNvbG9yPSIjNDA2QURDIi8+DQo8c3RvcCBvZmZzZXQ9IjAuNDY3Nzk5IiBzdG9wLWNvbG9yPSIjNkE0NUJFIi8+DQo8c3RvcCBvZmZzZXQ9IjEiIHN0b3AtY29sb3I9IiM2QTQ1QkUiIHN0b3Atb3BhY2l0eT0iMCIvPg0KPC9yYWRpYWxHcmFkaWVudD4NCjwvZGVmcz4NCjwvc3ZnPg=='/>
                </a>
              </td>
              <td style="padding: 0 10px">
                <a href="${
                  Config.APP_TWITTER_URL
                }" style="text-decoration: none">
                 <img style="width:24px; height: 24px" src='data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz48IS0tIFVwbG9hZGVkIHRvOiBTVkcgUmVwbywgd3d3LnN2Z3JlcG8uY29tLCBHZW5lcmF0b3I6IFNWRyBSZXBvIE1peGVyIFRvb2xzIC0tPgo8c3ZnIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIKYXJpYS1sYWJlbD0iVHdpdHRlciIgcm9sZT0iaW1nIgp2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PHJlY3QKd2lkdGg9IjUxMiIgaGVpZ2h0PSI1MTIiCnJ4PSIxNSUiCmZpbGw9IiMxZGExZjIiLz48cGF0aCBmaWxsPSIjZmZmZmZmIiBkPSJNNDM3IDE1MmE3MiA3MiAwIDAxLTQwIDEyYTcyIDcyIDAgMDAzMi00MGE3MiA3MiAwIDAxLTQ1IDE3YTcyIDcyIDAgMDAtMTIyIDY1YTIwMCAyMDAgMCAwMS0xNDUtNzRhNzIgNzIgMCAwMDIyIDk0YTcyIDcyIDAgMDEtMzItN2E3MiA3MiAwIDAwNTYgNjlhNzIgNzIgMCAwMS0zMiAxYTcyIDcyIDAgMDA2NyA1MGEyMDAgMjAwIDAgMDEtMTA1IDI5YTIwMCAyMDAgMCAwMDMwOS0xNzlhMjAwIDIwMCAwIDAwMzUtMzciLz48L3N2Zz4='/>
                </a>
              </span>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`,
      `Forgot Password: Verify Your Email Address`
    );
  }
}

export default EmailServices;
