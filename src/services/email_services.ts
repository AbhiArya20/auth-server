import nodemailer, { Transporter } from "nodemailer";
import Config from "@/config/config.js";
import SMTPTransport from "nodemailer/lib/smtp-transport";
import StringFunction from "@/utils/string_functions.js";
import { AuthenticationMethod } from "@/utils/constants";
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
    hash: string
  ) {
    const emailServiceInstance = EmailService.getInstance();

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
                  Dear ${StringFunction.capitalize(name) + ","}
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
                    href="${Config.APP_FACEBOOK_URL}"
                    style="text-decoration: none"
                  >
                    <?xml version="1.0" ?><!DOCTYPE svg  PUBLIC '-//W3C//DTD SVG 1.1//EN'  'http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd'><svg enable-background="new 0 0 128 128" id="Social_Icons" version="1.1" viewBox="0 0 128 128" xml:space="preserve" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><g id="_x31__stroke"><g id="Facebook_1_"><rect fill="none" height="128" width="128"/><path clip-rule="evenodd" d="M68.369,128H7.065C3.162,128,0,124.836,0,120.935    V7.065C0,3.162,3.162,0,7.065,0h113.871C124.837,0,128,3.162,128,7.065v113.87c0,3.902-3.163,7.065-7.064,7.065H88.318V78.431    h16.638l2.491-19.318H88.318V46.78c0-5.593,1.553-9.404,9.573-9.404l10.229-0.004V20.094c-1.769-0.235-7.841-0.761-14.906-0.761    c-14.749,0-24.846,9.003-24.846,25.535v14.246H51.688v19.318h16.681V128z" fill="#4460A0" fill-rule="evenodd" id="Facebook"/></g></g></svg>
                  </a>           
              </td>
              <td style="padding: 0 10px">
                <a href="${
                  Config.APP_LINKEDIN_URL
                }" style="text-decoration: none">
                  <img style="width:24px; height: 24px" src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAAXNSR0IArs4c6QAAA7BJREFUaEPtmV1oHFUUx3/npmjFCvUDrSAK+lCwgg9KpX5QpDubVq1fhCAoiCL6JPRJSnV2ZneLVRFF6wdafBBB7UPqR602O6spaos1KCoV+iL4pkXBaqSJqXuPnW4/EpLde5NJp1PpvM5/zzm/c++ce85d4RR/5BSPn+MA8fbzsOYBMMtBLwY5AK3v0Z63qJeGiwraBoibK7G8DXrutIGKvkg1WAOiRQMRws+WIP8Og5zVPThZR620oXgAUeMdVO7xCGyEkbMv4vnrRz20uUmEMNmHcKGXR8PNxMEOL21OIqGSjAFnevrroxYMeGpzkaUAe4HFXt6MuYZ4xbde2pxEKUAMRE5/yl7qpSuLVomEx748hzNGd2G4qiOEMg5Sol76wgmas+DIOTB0Abb1Ctg+kMmns2UP88wjxCt25Rybl7vJwT7+6WWY1k0gi0D3Y/iOavBN0bbNRLL/US/ktWDFExVoBVRYu20hYuaxYdXvvtu2DRANvon2LOmaX9V3qQfPTtFEyUZUljnXRlo/Uu29/5gujg32hgChH2UZymIEc/i9YhH9BSufI9rg7wWbO7UwbYBKYzfI0u5ByAvUSmumaMLBTxCz0gmAfk2tfF07YY0yynMg3ZN21KjaXxHzJGbny8SxnfoRZwGoND4GWeUNUEnWg66bUq7dBgDZytj8e3nmxpGj8uwrMBMA2ALylFesnUVfYf5YTtw/nkqyA4TJNoRbnEGp/Iykk55349jZpPAS1eDRuQGoJB8BtzoB5lqgsjQddbOvwMkCwA5Q6+3LDhAmWxFum0WC/wT2HC6acAWQbi//Jy211lyaHaDS/BB0tbdn5a9DFajKvoUbef3ag+3fqRAlAZZXEbnc2xZyX3aAMPkA4XY/pzqKElAv75xWHw1dgh0fRswiL3uWTdkBKoPvg7nDyyG6llr56a7asPnwoWr1mp89ducHoDpGzz/nE68+0DW4eGgBrYO/ITLfDWF/yg4QJu8h3Ol0Zu0PrO+92qlLBV6dQfrp6P7sAJXmFtC73IHpMLWyo986YiVKNqP0e9jU7ABhMoBwt4ez482cSxwlb6A86JLNzUl8QgCam1B96DTA5Ax0mAf8v4EZbKF8V8CvCk0caFx7I8oTwPsgmzCRFQrAu5UoKoB3M1dUAO92+jTAtF9O9pPYeyIr7gr4DfXFLaMzvBdyldD0fa7nwGxu5lwQuQJUku1ArysmTugWOhmXu92Iw+QJRNxD0rGbOXf6Cqso0P8Ds8vRf1dj+beuWPKuAAAAAElFTkSuQmCC'/>
                </a>
              </td>
              <td style="padding: 0 10px">
                <a href="${
                  Config.APP_INSTAGRAM_URL
                }" style="text-decoration: none">
                  <img style="width:24px; height: 24px" src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAAXNSR0IArs4c6QAADRJJREFUaEPFWg10VdWV3t8+9+XHQhAMrUhpmbVYw9KQCCQIjlKxBm0YlyiKyoioYC2tiAS1hGGWxmKdYCXAiAJTM1Sov9RVqR0GREclUouQqUkIDiMqAziwREX5C3n3nrOn59x3X25CHglZLn1r3fXufffce79v7/3tve85D9SFz7biFf0M849ITJEwvktEA0Skr3HXMgkhj4iUuH0iASUMoYeAyBDsedJER4ng22sMQIahjfBhe95umvigKNqrBfs0VANB1t9ce+3+zuAh0wChSm4oOfsGIj1bExeD4MZagOG3BRYdw4JOgU2dsyBT4xxIhETSBFK/pQm48XYck7aEQGKI6wxx9e636p+vpMrQXu0+HRLYPuLxEWTkKSKc2zo+BByRsGDS+w5cKyln9TiBNHgLMCQakYq+NXHoGeeNkHBIxBKi97R4U6ZtHr+tUwI7hy29UcjUADgjbvHwwpNJWMu3eiNFJAXEkopAOetHVo797gCD04Ti4Fu9ATKCFs08/bbaa34TJ9HGA+8PXzyZBas7cpUhESJpAOEDEd5DoAPWasymWQufsNcYYnepIXwhENHuSFkL2piHIZzpznP4mzacIwq5NjYCwdkC/p6GDNKEQgOFVjJMOuURw5h866YJT0cY0wT2DF08QoQ2ESQnTkBEDoJ4oXiyamBdeaei6oj86f62vnh1vyCbp2hD92hWfeNEAqCZRH4wZfN1LpxCYU58QX28838bAT63nSg2+iZ5w/cb5x46XRBfxfg/Xvx0b2PoeU081no78kJAaseHmxsKrbAd3gNFj04C5BlEKnXUZGPf3sfH4Y3K4KsA0917vD7mde9I8v/WhSQiUYMCVpOm1E54zhH4rKhqKwglkUts2DDJ4DO/Zsu/PeLXEwLiKwV0SCix9JJ3pnxkMVlPiJH/0aTyIxI+0babNl8/AseGLTgnCPQ+m+ejxCiEirzGuQu6a7XuXFdXsuI+DTwSxrurBV8KecMiEutGPT1Hg6rCtAoKAEmy1x/HhvxyKohqWsGLiOb+33pv3tci2DBVC94dtuxTUdwnHuuGeeHoLVPvtWNeuejZc3wd7DNgRCR8UlORLJhfTUTlYZ20oS/1ascDQ7tjxeiaz4urepGvBwhUfysgEfVxVkLv7VNX8WVH920qqMySnPyjmlQinS5dbeCVF26dNjW6ZsOoVfWauMiNCWtHNYLCX6whMde5QVbFghe97ZXh8Wl8pLiqV0symKYF1xihC4mh4hVXC2lh/pMmfik7J/HkWVtmHo7f/r3hS9ca4Ko2QiW+etS2H6+Nxr028qkXA2BC5CUf/DsEhff/mSAjQwLWnXpRov7h2V3FblOw2dF0lwHPgyC/tY3ouO9xLQPRp4Z4fr/BAx7HmutdvdtVtOzbyYT/r2J4XAA+LOCHh9ZNt9GR/rw5cuUin3hW6CWbVmkLgvPnvU+QQREBkKlQf6nqkoCleE4vrbOeJYOysFGyFrCb61BP6nva9DsWhMG/Z5+R9Q9xb9hwKmiqTHZkwNoLVs4JrJBTNcEX3oVgeMVHIBro+spQyfeougVtmHd0MwveaGwS4qI08DSBiIhVVsdNWtisMWlGQ1Z21uj2IdXRM9++oGa2T1gYeSCA2o2g+N69gO3xU1UMdLfa+ui/nCqEZOJEJR/8zcsCKrMWd/J3lrfJWBpJq5oAeDVLmncTfYeSQfNAMEo10e1CPCQCEOs4//id+qPjkaFljrC8M+LXM33CEivgwG5E+xCUlO8H4+xWAjJDbVn8+KkI6JGzZ5HBopRowi5V0AJCOdflrsgExOqlZcfO6QZcbYCsSLCplvqub9fft/RUz60rWXGnD17qCLhawAcQXDDrE7D0DS+0YSTT1duPrch0Ixf3XvMuEOdHoWPBC6uyxJZHXu+K+P2C+T8MgP8wxFlhSoRNUQdxRs6gU4XSuyXLfuKTWm7HWw/4xAcRjLrrc7D0jggIcLu3eWlNJiD67+6cTcILQ76uctj++KfqnUXLuwI+GpMs+MUMA34snjYNVPlZDfctznSf+pLl0zTRkxa81U9AfAjBRT87DEjPVgJ0m1e7vM1LQ/yGwcU/rYXg4hiBRv5T/tDO4rc9qDD9vlcfQBXYcHDVVbCp9/aKSzIRaBr++K0+eGWoAes1HEEw+o7jIOS6IuaqprnZq33ytx1mntI7eukW+gwE1Rr/PEu99cSS07F+NFYXPFj+1wmB6tbWADo40dLnrF0Ptily0fj/Hv7YZB9qtQMfeqAZwSW3t4AoCykCIJqEN2qe65DAD24tFFYNEoWOgFhQgNoVO7pDoKWocogy1GjrRiRMw1TYs2He9o7uZ193NehZl4GcBpCEvnSqcXMKEQGYiXht1e86JHDpbVcI0fp4/IOye+KNJ452h4AM/nlPnZ1zmAy74hemRnVFj+1zX+nofu8PXTxRs3oh0oAPNtCX3dKWgCAzgbG3XC5GNsTTJ1o4D5v/7Ui3CIx8IE+f0F9a8JaEOE+oy3O2z9vY0f0+tATAjoDzgCNQOrkFkCx3AVxJmoRXnuk4hEpvKhRQQ7zyQlQBXlvZvRAq+cchKghDKPSCsu3FkOwd9zd1RGDPsOobfVJhCJElYEPo8knHAcltJSA3Y/0LGUQ8sZdh9RkAla68hFnY+NvuibjkvnIxqjoCL5q1d4L6IIOI956/cHLgRBx6wBCaoa+4/jCYeqaKGIFwG9atyZxGx03cxAajY0VsO/cKhmLNmnAWpYsf244EH36/gYnPE6OcBsjgTa/hoTGZbrFv6MJbNUVp1In4CHTZtZ+DqXeaAOR2vPxSxkIm464tF6LqeOcJwQxseO6U7Ud7UHrU3TPJqCVp6xsmaDVLNTyU0ZsHin41LWD1pA2f0As4BH3l1Z8A1NfNr4WFdTrWrs3cSpSV5RnO+QBAfhRGYpBkUuOw/rnXuuIAf9RdpSCsg3CCUtYXw5+oYzIIOx/JmBAOnv+rn/jEy2MiPgi56qr9RHJ2lEaJzQz8ft0prSnjx88kQ0tau1C2M7FJJr6HetCyTOFkw8bsP+tOEX40DT6VQkl7M9R/LTjlcz8tfOTOgHlpqg+ipOAAZPyVewny3ZCA2+7G79d32k5T8sRaEvy9a6dTLzHuRUbQxKJqyMhGSprdoUdyBhLU5YFJTGPBeVHYuG8bOgZ/wNYzr+msHTlUtGBmErwkFkL7INeUfUSQgWkCLPdgzcbOX2jKyvIoB7VkuCgEbtOga+xCQaZTY7QfClUc6Ei0br+eVc5obM4cOlFYHiqsmh2AF8ZCaDdkwtj3iWmQm5e1GlBUgWc2du2V8qayPDqOp0n4Svf+mCYS5fXW/J4mZlRI1lo+UC+De9zUFfCWxBeF/zxHg6vSdYB4F2Ri6Z/Jw0hHwE0uyyKsfrXrL/WVlUzvbvkZGb6fwH2jitrGA9biqULlzht8QqQe5Df7L+8sbOJJ4Ujhw4sCqFl+KgslgS2QyWPXkJLrWgnQi6h59fSnVWxIZWEakbqaNC4SUqotaKVF4y1F3kvUwjXdaT+ODXn4RR88IdVG0F9b8TWQW0qrKUHlpFIeADXgiVfP70o6zDRGLBnPG0CS3T9cHEh8TNm5e/CH7vVM0XOOFzxU77MqijSgiashPy6dSh7VpAm4dTrVH4s3fG1Ti10xlgx+4JzmhLdPw4Of7oXUVMgdV/SjXP2xbexbSUgFqv6zS0LuysO/ijG6YP4cH3ACthrwAUEiq3+4wHHvZVtJUUlaBywHyU8ORtVb38jCRnvCUlDZJwB2GuL8sAYo20pvy2/4+YiQQMUPJ5GHZ2IeIILZSAGNQ+Ub3+gCh4yp9PQhfx3pxFgjKnoPsDMZk/o0VIQLHGJTIW3aTh6dm/aCO2M2kgluwNxvxhNyYXkffSzneSKv1L4r2CJorZ8EmvIak0U2BaeXxOShMSXk8SbyKDdd1EJffkqGHiX2V6G89msRthTP6meUN0W0upeMyg9bDltLFCUJzcLe6G81zq2z4Nqs6cnCyyaTJ6tdKEXr8uESPFFgJ66lkZLyAQVqD/my387tUYBmSuIE+URua2GiwHxBPoS0vZEi9y0MMokzHRCdAqQ5h8TLNSHAfhD+npjEIDEYAqNgx7p3hdimmSdnN/7TycuskXBk2ZgbiaWGmN1Ct+vv3KIuQoAWtP1Opo7dfuw4vh97cAik1ZI2JCJgJ5076TpLBCdgvOle0wNPxUXe4V8N5DeXFhOZVQQ+z1nfEnDAU6AtyIhE+313jJBUZGnX/7S1ZAg+JNTeynGL27iHRpMW75asxvkubDolkBb23266gURmU5KK3WxqHFz7fesRZ/2YN+IE2oRCzBMZCIhhG4LbSLha/SX3hUw9U8Z/q8RZyurR/chP/IhapJCSGEAtNICS0teFkfVMEnmUhKKWtGcSlKQecQ8YzUdJPN+FomunPU2aD1t9CHn2t4Ms2Cs6a68INyifNqBucadJ4/8B28XU0n0lpxMAAAAASUVORK5CYII='/>
                </a>
              </td>
              <td style="padding: 0 10px">
                <a href="${
                  Config.APP_TWITTER_URL
                }" style="text-decoration: none">
                 <img style="width:24px; height: 24px" src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAAXNSR0IArs4c6QAABUZJREFUaEPtmXuIVHUUxz/nzvhKXd2duRpqhoqVPSCsKC0yzY1MzdDd2TXDsFAhJImyAkOKIEIolDBKragkm9kHPUisoHwECj2oTFFSMCMfOzPr6u6aqzP31B3bZnZ3Zu6dmbuF4Pw593u+33N+5/zO7yVc5D+5yP3nUgD/dwb/nwzUxSdjWdUIU4GRIIOw5CiG7kOkkQ4aeChwOu/gbIqX2ZiuAXytfqZKotdGtb5pPJasBZmRV0NpwpCVVFW8hYh2wUaabgRWgdQTMj9IB2BH1De5FX//2cwti3seRCQ2DbQepNw1t1jv0mwuxjxRznn/DMR6EJVKlCOUtVzNfeM70gGEo4sRWQ/6De1tlSwac9a1kBOwPnozluwABjhBe3y3s4GaiGRUi8wgFNhqY9N/RmIfAXMuEFhfcNaay8LL2wsW7G7wcXQwHewFuaJkLptAWUlN8KUUV+RURUYA0d9ARqdFrN3QbyahIc0lCUfiq0BfKIkjZaznwXgWHxEsawrKAjA+z8zAmSwpPoSlIWrNH4pywG4KTdHjiBEoyj7TSDmGYADD/6mSRqrNqow5EGtHuCxLDXZgsIK9gXU8L1ZBjkSiU0C2FWTjCmztYkBiOrNHnMnMwEFgXG57u6RkGSHze1caqRqNrgBZ7RrvCig76GfNYo7Z2nUSh+ObEa3Nz6EWqpvw+VZTFdjrqFcXfRWVJxxxbgF2Wx14aqndPjtN0hmoi9aistkVl6oixhZUN3KmdWvOllsXW4vyuCtONyCfjmCeeSwTmlFC2hdiBwtvd3oalU8xZBtJ2c3+8n3/zhWvSyipI5lvHs0eQKpm4/ei1paui4aboemCaQe1W/LvYJX93eomFcyQy+CcDOm+R+q5mYvE1gDLPRP1iihVtsE+hCTZMwPvHR9If/8mkNeh4iuk+WVUn/JK2yOeo4SCI7tzZVnI9CQYv6DWDYgM9UjcAxrZSShwZ54Aonafv9UDpd6hENlAdWBJ7gDCsRcRnusddQ9YVR6lJvB2ngw0j4ak3Ub7eCDnPYXBBKqC+3MHkGqjTa+Bscx79ZIZDxMKjsnG0rWN2t2or/87DK4pWdJLAtU11JhZtyQ914GG+CjOsx1Dx3rpQ2lcMplQYJdzBjoRjacDJM7ZE+b+0oS9sNafCJn2QT7rL/+1Sjg6FZHlKJVZzwpe+OfEobqEGnNDYQGE4/MQnYXSimCfpuz1Ic9ZwcmLYr/rEQa1XJW5fc7fhTq/fnhiHIZxAMRXrLQndiKLqQ5szMeVu4TCsXUIj3niSFEk+jNm8Cani7bcAaQuulLHyAlF6ZdkpEksmURt8FsnmvyTONIyBhJf/uf1r6ymJviMk/P2d+fL3cbjw0j416cvvdzQloKRnZgV05xKp1PBOYBOZF3s7tT5Vpneey1V/8DHLd3PvcVN4lxWW37tR9vQ24B3QLLuT4oaf/sO1MeUbBs2bwMIxx5AeCN9Q1aUu92MNAZaSWjYj4WyuS+hcGw6Yq0A455CRRzwB7CSM6kdfqgYXocuFL8WVbvmHwYmFiOQ30Y+A//CUi6QhbroXagxEaw2lDJEAoiOReUOYIT3TqcY20CfpDq4occLTIGCFzKQKg9dA3JdgfYFwtUCaSDpe5r55YcLNM4KT5fQm9qH8tgikKW9UC5/IlYE9b9CqGKPF47nXwfshzQ1HkGYV3wZ6TmQnSifkPC/z4KhJ7103P1C1nDySpKJ20EngXE9MAo0gDIYwX5BbMUyWjA0jnAAtZ+TdA/odkLD2nrD6UxO9220tz0pkv9SAEUOnGdmF30G/gJnm6TyGAkqJQAAAABJRU5ErkJggg=='/>
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
                  Hello ${StringFunction.capitalize(name) + ","}
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
                    <?xml version="1.0" ?><!DOCTYPE svg  PUBLIC '-//W3C//DTD SVG 1.1//EN'  'http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd'><svg enable-background="new 0 0 128 128" id="Social_Icons" version="1.1" viewBox="0 0 128 128" xml:space="preserve" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><g id="_x31__stroke"><g id="Facebook_1_"><rect fill="none" height="128" width="128"/><path clip-rule="evenodd" d="M68.369,128H7.065C3.162,128,0,124.836,0,120.935    V7.065C0,3.162,3.162,0,7.065,0h113.871C124.837,0,128,3.162,128,7.065v113.87c0,3.902-3.163,7.065-7.064,7.065H88.318V78.431    h16.638l2.491-19.318H88.318V46.78c0-5.593,1.553-9.404,9.573-9.404l10.229-0.004V20.094c-1.769-0.235-7.841-0.761-14.906-0.761    c-14.749,0-24.846,9.003-24.846,25.535v14.246H51.688v19.318h16.681V128z" fill="#4460A0" fill-rule="evenodd" id="Facebook"/></g></g></svg>
                  </a>           
              </td>
              <td style="padding: 0 10px">
                <a href="${
                  Config.APP_LINKEDIN_URL
                }" style="text-decoration: none">
                  <?xml version="1.0" ?><!DOCTYPE svg  PUBLIC '-//W3C//DTD SVG 1.1//EN'  'http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd'><svg enable-background="new 0 0 128 128" id="Social_Icons" version="1.1" viewBox="0 0 128 128" xml:space="preserve" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><g id="_x37__stroke"><g id="Twitter"><rect clip-rule="evenodd" fill="none" fill-rule="evenodd" height="128" width="128"/><path clip-rule="evenodd" d="M128,23.294    c-4.703,2.142-9.767,3.59-15.079,4.237c5.424-3.328,9.587-8.606,11.548-14.892c-5.079,3.082-10.691,5.324-16.687,6.526    c-4.778-5.231-11.608-8.498-19.166-8.498c-14.493,0-26.251,12.057-26.251,26.927c0,2.111,0.225,4.16,0.676,6.133    C41.217,42.601,21.871,31.892,8.91,15.582c-2.261,3.991-3.554,8.621-3.554,13.552c0,9.338,4.636,17.581,11.683,22.412    c-4.297-0.131-8.355-1.356-11.901-3.359v0.331c0,13.051,9.053,23.937,21.074,26.403c-2.201,0.632-4.523,0.948-6.92,0.948    c-1.69,0-3.343-0.162-4.944-0.478c3.343,10.694,13.035,18.483,24.53,18.691c-8.986,7.227-20.315,11.533-32.614,11.533    c-2.119,0-4.215-0.123-6.266-0.37c11.623,7.627,25.432,12.088,40.255,12.088c48.309,0,74.717-41.026,74.717-76.612    c0-1.171-0.023-2.342-0.068-3.49C120.036,33.433,124.491,28.695,128,23.294" fill="#00AAEC" fill-rule="evenodd" id="Twitter_1_"/></g></g></svg>
                </a>
              </td>
              <td style="padding: 0 10px">
                <a href="${
                  Config.APP_INSTAGRAM_URL
                }" style="text-decoration: none">
                  <?xml version="1.0" ?><!DOCTYPE svg  PUBLIC '-//W3C//DTD SVG 1.1//EN'  'http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd'><svg enable-background="new 0 0 128 128" id="Social_Icons" version="1.1" viewBox="0 0 128 128" xml:space="preserve" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><g id="_x37__stroke"><g id="Instagram_1_"><rect clip-rule="evenodd" fill="none" fill-rule="evenodd" height="128" width="128"/><radialGradient cx="19.1111" cy="128.4444" gradientUnits="userSpaceOnUse" id="Instagram_2_" r="163.5519"><stop offset="0" style="stop-color:#FFB140"/><stop offset="0.2559" style="stop-color:#FF5445"/><stop offset="0.599" style="stop-color:#FC2B82"/><stop offset="1" style="stop-color:#8E40B7"/></radialGradient><path clip-rule="evenodd" d="M105.843,29.837    c0,4.242-3.439,7.68-7.68,7.68c-4.241,0-7.68-3.438-7.68-7.68c0-4.242,3.439-7.68,7.68-7.68    C102.405,22.157,105.843,25.595,105.843,29.837z M64,85.333c-11.782,0-21.333-9.551-21.333-21.333    c0-11.782,9.551-21.333,21.333-21.333c11.782,0,21.333,9.551,21.333,21.333C85.333,75.782,75.782,85.333,64,85.333z M64,31.135    c-18.151,0-32.865,14.714-32.865,32.865c0,18.151,14.714,32.865,32.865,32.865c18.151,0,32.865-14.714,32.865-32.865    C96.865,45.849,82.151,31.135,64,31.135z M64,11.532c17.089,0,19.113,0.065,25.861,0.373c6.24,0.285,9.629,1.327,11.884,2.204    c2.987,1.161,5.119,2.548,7.359,4.788c2.24,2.239,3.627,4.371,4.788,7.359c0.876,2.255,1.919,5.644,2.204,11.884    c0.308,6.749,0.373,8.773,0.373,25.862c0,17.089-0.065,19.113-0.373,25.861c-0.285,6.24-1.327,9.629-2.204,11.884    c-1.161,2.987-2.548,5.119-4.788,7.359c-2.239,2.24-4.371,3.627-7.359,4.788c-2.255,0.876-5.644,1.919-11.884,2.204    c-6.748,0.308-8.772,0.373-25.861,0.373c-17.09,0-19.114-0.065-25.862-0.373c-6.24-0.285-9.629-1.327-11.884-2.204    c-2.987-1.161-5.119-2.548-7.359-4.788c-2.239-2.239-3.627-4.371-4.788-7.359c-0.876-2.255-1.919-5.644-2.204-11.884    c-0.308-6.749-0.373-8.773-0.373-25.861c0-17.089,0.065-19.113,0.373-25.862c0.285-6.24,1.327-9.629,2.204-11.884    c1.161-2.987,2.548-5.119,4.788-7.359c2.239-2.24,4.371-3.627,7.359-4.788c2.255-0.876,5.644-1.919,11.884-2.204    C44.887,11.597,46.911,11.532,64,11.532z M64,0C46.619,0,44.439,0.074,37.613,0.385C30.801,0.696,26.148,1.778,22.078,3.36    c-4.209,1.635-7.778,3.824-11.336,7.382C7.184,14.3,4.995,17.869,3.36,22.078c-1.582,4.071-2.664,8.723-2.975,15.535    C0.074,44.439,0,46.619,0,64c0,17.381,0.074,19.561,0.385,26.387c0.311,6.812,1.393,11.464,2.975,15.535    c1.635,4.209,3.824,7.778,7.382,11.336c3.558,3.558,7.127,5.746,11.336,7.382c4.071,1.582,8.723,2.664,15.535,2.975    C44.439,127.926,46.619,128,64,128c17.381,0,19.561-0.074,26.387-0.385c6.812-0.311,11.464-1.393,15.535-2.975    c4.209-1.636,7.778-3.824,11.336-7.382c3.558-3.558,5.746-7.127,7.382-11.336c1.582-4.071,2.664-8.723,2.975-15.535    C127.926,83.561,128,81.381,128,64c0-17.381-0.074-19.561-0.385-26.387c-0.311-6.812-1.393-11.464-2.975-15.535    c-1.636-4.209-3.824-7.778-7.382-11.336c-3.558-3.558-7.127-5.746-11.336-7.382c-4.071-1.582-8.723-2.664-15.535-2.975    C83.561,0.074,81.381,0,64,0z" fill="url(#Instagram_2_)" fill-rule="evenodd" id="Instagram"/></g></g></svg>
                </a>
              </td>
              <td style="padding: 0 10px">
                <a href="${
                  Config.APP_TWITTER_URL
                }" style="text-decoration: none">
                 <?xml version="1.0" ?><!DOCTYPE svg  PUBLIC '-//W3C//DTD SVG 1.1//EN'  'http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd'><svg enable-background="new 0 0 128 128" id="Social_Icons" version="1.1" viewBox="0 0 128 128" xml:space="preserve" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><g id="_x37__stroke"><g id="Twitter"><rect clip-rule="evenodd" fill="none" fill-rule="evenodd" height="128" width="128"/><path clip-rule="evenodd" d="M128,23.294    c-4.703,2.142-9.767,3.59-15.079,4.237c5.424-3.328,9.587-8.606,11.548-14.892c-5.079,3.082-10.691,5.324-16.687,6.526    c-4.778-5.231-11.608-8.498-19.166-8.498c-14.493,0-26.251,12.057-26.251,26.927c0,2.111,0.225,4.16,0.676,6.133    C41.217,42.601,21.871,31.892,8.91,15.582c-2.261,3.991-3.554,8.621-3.554,13.552c0,9.338,4.636,17.581,11.683,22.412    c-4.297-0.131-8.355-1.356-11.901-3.359v0.331c0,13.051,9.053,23.937,21.074,26.403c-2.201,0.632-4.523,0.948-6.92,0.948    c-1.69,0-3.343-0.162-4.944-0.478c3.343,10.694,13.035,18.483,24.53,18.691c-8.986,7.227-20.315,11.533-32.614,11.533    c-2.119,0-4.215-0.123-6.266-0.37c11.623,7.627,25.432,12.088,40.255,12.088c48.309,0,74.717-41.026,74.717-76.612    c0-1.171-0.023-2.342-0.068-3.49C120.036,33.433,124.491,28.695,128,23.294" fill="#00AAEC" fill-rule="evenodd" id="Twitter_1_"/></g></g></svg>
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

export default EmailService;
