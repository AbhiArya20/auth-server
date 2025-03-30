## Auth Server

### Setup locally development

1. Clone the repository

```bash
git clone https://github.com/AbhiArya20/auth-server.git
```

2. Install dependencies

```bash
npm install
```

3. Create a .env file

```bash
cp .env.example .env
```

4. Fill in the .env file

5. Run the server

```bash
npm run dev
```

`OR` Run using docker

```bash
# development
docker-compose -f docker-compose.dev.yml up

# production
docker-compose up
```

### Overview

We provides an overview of the authentication controller, detailing the available endpoints, their expected inputs, and responses.

**Success Response** \
Every successful response will have the following structure:

```js
{
  "success": true,
  "code": "SUCCESS",
  "message": "Successful",
  "data": {
    // data returned by the endpoint in the response like user, token, etc.
  }
```

**Error Response** \
Every error response will have the following structure:

```js
{
  "success": false,
  "code": "ERROR_CODE",
  "message": "Error Message",
  "error": zodError || Error // optional
}
```

### Endpoints

#### 1. Register

**Endpoint:** `/v1/register` \
**Method:** `POST` \
**Description:** Registers a new user.

#### Request Body

```js
{
  "firstName": "Abhishek",  // optional
  "lastName": "Kumar"       // optional

  // email or phone either one is required
  "email": "github.abhiarya@gmail.com",
  // "phone": "9162388695",

  "password": "Abhishek@123",
  "method": "PASSWORD",  // enum { "MAGIC_LINK", "PASSWORD", "EMAIL_OTP", "SMS_OTP" , "WHATSAPP_OTP" }
}
```

#### Response

**Success (200 Created):**

```js
{
  "success": true,
  "code": "REGISTRATION_SUCCESSFUL",
  "message": "User registered successfully.",
  "data": {
    "email": "github.abhiarya@gmail.com",
    // OR
    "phone": "9162388695",

    "method": "PASSWORD",

    // verificationToken: "123456789", // if method is "SMS_OTP" or "WHATSAPP_OTP" or "EMAIL_OTP"

    "user": {
      "_id": "243sfsdfsdf32434",
      "firstName": "Abhishek",
      "lastName": "Kumar",
      "email": "github.abhiarya@gmail.com",
      "role": "USER",
      "status": "ACTIVE",
      "createdAt": "2023-01-01T00:00:00.000Z",
      "updatedAt": "2023-01-01T00:00:00.000Z"
    }
  }
}
```

**Failure (400 Bad Request):**

```js
{
  "success": false,
  "code": "USER_ALREADY_REGISTERED",
  "message": "Email is already registered.",
  "error": zodError || Error // optional
}
```

---

### 2. Login

**Endpoint:** `/v1/login` \
**Method:** `POST \
**Description:** Authenticates a user.

if method === "PASSWORD" and user registered with password, then we will authenticate user with password.

otherwise, we try to authenticate with magic link or otp based on the method.

#### Request Body

```js
{
  "email": "github.abhiarya@gmail.com",
  // OR
  // "phone": "9162388695",
  "password": "Abhishek@123",
  "remember": true, // default = true
  "method": "PASSWORD"
}
```

#### Response

**Success (200 OK):**

```js
{
  // ... success response ...
  "data": {
    "accessToken": "jwt_token",
    "refreshToken": "jwt_refresh_token",
    "user": {
      // user data
    }
  }
}
```

**Failure (401 Unauthorized):**

```js
{
  "success": false,
  "code": "INVALID_CREDENTIALS",
  "message": "Invalid email or password."
  "error": zodError || Error // optional
}
```

---

### 3. Verify Account

**Endpoint:** `/v1/verify` \
**Method:** `POST` \
**Description:** Verifies the user's email or phone via OTP or verification link.

#### Request Body

```js
{
  "email": "github.abhiarya@gmail.com",
  // OR
  // "phone": "9162388695",
  "method": "PASSWORD"
  "verificationToken": "verification_token",
  "otp": "123456", // optional
}
```

#### Response

**Success (200 OK):**

```js
{
  // ... success response ...
  "data": {
    "accessToken": "jwt_token",
    "refreshToken": "jwt_refresh_token",
    "user": {
      // user data
    }
  }
}
```

**Failure (400 Bad Request):**

```js
{
  "code": "INVALID_VERIFICATION_TOKEN",
  "message": "Verification token is invalid or expired."
}
```

---

### 4. Refresh Token

**Endpoint:** `/v1/refresh-token`
**Method:** `GET`
**Description:** Refreshes the user's authentication token either from cookie or Authorization header.

#### Request Headers

```js
{
  "Authorization": "Bearer refresh_token"
}
```

#### Response

**Success (200 OK):**

```js
{
  "code": "REFRESH_TOKEN_SUCCESS",
  "message": "Token refreshed successfully.",
  "data": {
    "accessToken": "new_jwt_token",
    "refreshToken": "new_jwt_refresh_token"
  }
}
```

**Failure (401 Unauthorized):**

```js
{
  "code": "INVALID_REFRESH_TOKEN",
  "message": "Invalid or expired refresh token."
}
```

I really recommend you to go through the code and understand the flow of the authentication controller, and if you find any issue, feel free to open an issue.

For that reason, I have not mentioned the request body and response in the below endpoints, you can start from the `index.ts`

---

### 5. Forgot Password

**Endpoint:** `/v1/forgot-password` \
**Method:** `POST` \
**Description:** Initiates the password reset process.

---

### 6. Forgot Password Verify

**Endpoint:** `/v1/forgot-password-verify` \
**Method:** `POST` \
**Description:** Verifies the password reset token and updates the password.

---

### 7. Logout

**Endpoint:** `/v1/logout` \
**Method:** `POST` \
**Description:** Logs out the user and clears authentication cookies.

---

### 8. Get Current User

**Endpoint:** `/v1/me` \
**Method:** `GET` \
**Description:** Retrieves the currently authenticated user's details.

---

### 9. Update Current User

**Endpoint:** `/v1/me`
**Method:** `PUT`
**Description:** Updates the currently authenticated user's profile.

## Conclusion

This authentication controller provides secure user authentication, including registration, login, verification, password reset, and session management.

This auth-server project covers both web and device(mobile/desktop) Authentication using.
Email OTP
SMS OTP
WhatsApp OTP
Magic Link
PASSWORD

Built using the following technologies:

- Node.js
- Express.js
- MongoDB
- Redis
- Zod
- JWT
- nodemailer
