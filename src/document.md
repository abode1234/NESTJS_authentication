# First day of the project

# UsersService

The `UsersService` class is responsible for handling user-related operations, such as user registration and retrieval of all registered users.

## Dependencies

The `UsersService` class has the following dependencies:

1. `@InjectModel(User.name) private userModel: Model<UserDocument>`: This injects the Mongoose model for the `User` schema, allowing the service to interact with the MongoDB database.

## Methods

### `registerUser(registerUserDto: RegisterUserDto): Promise<User>`

The `registerUser` method is responsible for registering a new user in the system.

**Parameters:**
- `registerUserDto: RegisterUserDto`: A data transfer object (DTO) containing the necessary information to register a user, including `userName`, `email`, and `password`.

**Return Value:**
- `Promise<User>`: The newly created `User` document.

**Functionality:**
1. Extracts the `userName`, `email`, and `password` values from the `registerUserDto`.
2. Checks if a user with the provided `email` already exists in the database using the `findOne` method.
3. If a user with the provided email already exists, it throws a `ConflictException` with the message "Email already in use".
4. If the email is not already in use, it generates a salt using `bcrypt.genSalt(14)` and then hashes the password using `bcrypt.hash(password, salt)`.
5. It creates a new `User` document with the provided `userName`, `email`, and hashed `password`.
6. Finally, it saves the new `User` document to the database and returns it.

### `findAll(): Promise<User[]>`

The `findAll` method is responsible for retrieving all registered users.

**Return Value:**
- `Promise<User[]>`: An array of all `User` documents.

**Functionality:**
1. It uses the `find` method of the `userModel` to retrieve all `User` documents from the database.
2. It executes the query and returns the resulting array of `User` documents.

## Error Handling

The `UsersService` class handles the following exception:

- `ConflictException`: Thrown when a user with the provided email already exists in the database.

## Usage

To use the `UsersService` in your NestJS application, you can inject it into your controllers or other services as follows:

```typescript
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private usersService: UsersService) {}

  @Post('register')
  async registerUser(@Body() registerUserDto: RegisterUserDto) {
    return this.usersService.registerUser(registerUserDto);
  }

  @Get()
  async getAllUsers() {
    return this.usersService.findAll();
  }
}
```
# Day 2
Create a simple Nginx server.

```Nginx
# create a server
server {
    listen 80;
    server_name localhost;
# add the proxy server
    location / {
# set the proxy server
        proxy_pass http://127.0.0.1:3000/users;
# set the http version
        proxy_http_version 1.1;
# set the upgrade header
        proxy_set_header Upgrade $http_upgrade;
# set the connection header
        proxy_set_header Connection 'upgrade';
# set the host header
        proxy_set_header Host $host;
# set the X-Forwarded-For header
        proxy_cache_bypass $http_upgrade;
    }

# set the error page
    error_page 404 /404.html;
    location = /404.html {
        root /usr/share/nginx/html;
        internal;
    }

    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root /usr/share/nginx/html;
    }
}
```
---
# Day 3: Implementing Authentication with Strategies, AuthService, and Controller

In this section, we'll delve into the `AuthService` class, which manages user and admin authentication, and the corresponding controller. We'll provide detailed explanations for each function, discuss common issues, and show how everything ties together.

---

#### 1. Authentication Strategies

Strategies in Passport define how authentication is performed. In this implementation, we use two strategies:

**LocalUserStrategy**

```typescript
import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalUserStrategy extends PassportStrategy(Strategy, 'local-user') {
  constructor(private authService: AuthService) {
    super({
      usernameField: 'email',
      passwordField: 'password',
    });
  }

  async validate(email: string, password: string): Promise<any> {
    console.log(`LocalUserStrategy validating: ${email}`);
    const user = await this.authService.validateUserCredentials(email, password);
    if (!user) {
      console.log(`User validation failed for email: ${email}`);
      throw new UnauthorizedException('Invalid email or password');
    }
    console.log(`User validation successful for email: ${email}`);
    return user;
  }
}
```

- **Purpose:** Authenticate users based on their email and password.
- **Constructor:**
  - `usernameField: 'email'`: Specifies that email is used as the username for authentication.
  - `passwordField: 'password'`: Specifies the password field for authentication.
- **`validate` Method:**
  - **Parameters:**
    - `email`: User’s email.
    - `password`: User’s password.
  - **Functionality:**
    1. Logs the email being validated.
    2. Calls `AuthService.validateUserCredentials` to check if the user exists and if the password is correct.
    3. Throws `UnauthorizedException` if validation fails.
    4. Returns the user if validation is successful.

**LocalAdminStrategy**

```typescript
import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalAdminStrategy extends PassportStrategy(Strategy, 'local-admin') {
    constructor(private readonly authService: AuthService) {
        super({
            usernameField: 'email',
            passwordField: 'password',
        });
    }

    async validate(email: string, password: string): Promise<any> {
        console.log(`LocalAdminStrategy validating: ${email}`);
        const admin = await this.authService.validateAdminCredentials(email, password);
        if (!admin) {
            console.log(`Admin validation failed for email: ${email}`);
            throw new UnauthorizedException('Invalid email or password for admin');
        }
        console.log(`Admin validation successful for email: ${email}`);
        return admin;
    }
}
```

- **Purpose:** Authenticate admins based on their email and password.
- **Constructor:**
  - `usernameField: 'email'`: Specifies that email is used as the username for authentication.
  - `passwordField: 'password'`: Specifies the password field for authentication.
- **`validate` Method:**
  - **Parameters:**
    - `email`: Admin’s email.
    - `password`: Admin’s password.
  - **Functionality:**
    1. Logs the email being validated.
    2. Calls `AuthService.validateAdminCredentials` to check if the admin exists and if the password is correct.
    3. Throws `UnauthorizedException` if validation fails.
    4. Returns the admin if validation is successful.

---
### Detailed Explanation of AuthService with Function Code

The `AuthService` class in NestJS is essential for handling authentication tasks, such as validating user credentials and generating JWT tokens. Here's a breakdown of each method within the `AuthService` class:

---

#### **1. validateUserCredentials**

**Purpose:**
Validates a user's credentials by checking if the provided email and password match a record in the database.

**Function Code:**

```typescript
async validateUserCredentials(email: string, password: string): Promise<UserDocument | null> {
    console.log(`Validating user credentials for email: ${email}`);
    const user = await this.userModel.findOne({ email, role: 'User' });
    if (!user) {
        console.log(`User not found for email: ${email}`);
        return null;
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log(`Password validation result: ${isPasswordValid}`);
    if (isPasswordValid) {
        return user;
    }
    return null;
}
```

**Explanation:**

1. **Logging:**
   - Logs the email being validated for debugging purposes.

2. **Query Database:**
   - Uses `findOne` method to query the database for a user with the provided email and role 'User'.

3. **Check User Existence:**
   - If no user is found, logs the event and returns `null`.

4. **Password Validation:**
   - Uses `bcrypt.compare` to check if the provided password matches the stored hashed password.

5. **Return User:**
   - Returns the user if the password is valid; otherwise, returns `null`.

---

#### **2. validateAdminCredentials**

**Purpose:**
Validates an admin's credentials by checking if the provided email and password match a record in the database.

**Function Code:**

```typescript
async validateAdminCredentials(email: string, password: string): Promise<UserDocument | null> {
    console.log(`Validating admin credentials for email: ${email}`);
    const admin = await this.userModel.findOne({ email, role: 'Admin' });
    if (!admin) {
        console.log(`Admin not found for email: ${email}`);
        return null;
    }
    const isPasswordValid = await bcrypt.compare(password, admin.password);
    console.log(`Password validation result: ${isPasswordValid}`);
    if (isPasswordValid) {
        return admin;
    }
    return null;
}
```

**Explanation:**

1. **Logging:**
   - Logs the email being validated for debugging purposes.

2. **Query Database:**
   - Uses `findOne` method to query the database for an admin with the provided email and role 'Admin'.

3. **Check Admin Existence:**
   - If no admin is found, logs the event and returns `null`.

4. **Password Validation:**
   - Uses `bcrypt.compare` to check if the provided password matches the stored hashed password.

5. **Return Admin:**
   - Returns the admin if the password is valid; otherwise, returns `null`.

---

#### **3. loginUser**

**Purpose:**
Generates a JWT token for a successfully authenticated user.

**Function Code:**

```typescript
async loginUser(user: UserDocument): Promise<any> {
    console.log(`User login successful for email: ${user.email}`);
    const payload = { email: user.email, sub: user._id, role: user.role };
    const accessToken = this.jwtService.sign(payload, {
        secret: this.configService.get<string>('JWT_SECRET_USER'),
    });
    const { password, ...result } = user.toJSON();
    return { ...result, accessToken };
}
```

**Explanation:**

1. **Logging:**
   - Logs the successful login event for debugging purposes.

2. **JWT Payload:**
   - Constructs a payload with user details, including email, user ID, and role.

3. **Generate JWT Token:**
   - Uses `jwtService.sign` to create a JWT token with a secret key specific to users.

4. **Prepare Response:**
   - Removes the password from the user document and returns the user details along with the access token.

---

#### **4. loginAdmin**

**Purpose:**
Generates a JWT token for a successfully authenticated admin.

**Function Code:**

```typescript
async loginAdmin(admin: UserDocument): Promise<any> {
    console.log(`Admin login successful for email: ${admin.email}`);
    const payload = { email: admin.email, sub: admin._id, role: admin.role };
    const accessToken = this.jwtService.sign(payload, {
        secret: this.configService.get<string>('JWT_SECRET_ADMIN'),
    });
    const { password, ...result } = admin.toJSON();
    return { ...result, accessToken };
}
```

**Explanation:**

1. **Logging:**
   - Logs the successful login event for debugging purposes.

2. **JWT Payload:**
   - Constructs a payload with admin details, including email, admin ID, and role.

3. **Generate JWT Token:**
   - Uses `jwtService.sign` to create a JWT token with a secret key specific to admins.

4. **Prepare Response:**
   - Removes the password from the admin document and returns the admin details along with the access token.

---

---

**Common Issues and Solutions**

1. **Duplicate Validation:**
   - **Issue:** Both `LocalUserStrategy` and `LocalAdminStrategy` perform authentication checks, leading to redundant validations and potential failures if not correctly handled.
   - **Solution:** Ensure that the `AuthService` performs validation once and that strategies (`LocalUserStrategy` and `LocalAdminStrategy`) only validate the credentials once, avoiding redundant checks.

2. **Increased Security with Separate Secrets:**
   - **Issue:** Using the same JWT secret for both user and admin authentication can lead to security vulnerabilities.
   - **Solution:** Use separate JWT secrets for users and admins (`JWT_SECRET_USER` and `JWT_SECRET_ADMIN`) to enhance security and avoid potential conflicts.

3. **Error Handling for Multiple Validations:**
   - **Issue:** When both user and admin validation methods are checked separately, error handling might become complex and inconsistent.
   - **Solution:** Consolidate validation logic where possible and handle errors gracefully to ensure consistent and reliable authentication results.

---

---

#### **AuthController Class**

**Purpose:**
Handles authentication endpoints for logging in users and admins, using the `AuthService` to manage authentication logic.

**Code:**

```typescript
import { Controller, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @UseGuards(AuthGuard('local-user'))
    @Post('login-user')
    async loginUser(@Req() req) {
        console.log(req.user);
        return this.authService.loginUser(req.user);
    }

    @UseGuards(AuthGuard('local-admin'))
    @Post('login-admin')
    async loginAdmin(@Req() req) {
        console.log(req.user);
        return this.authService.loginAdmin(req.user);
    }
}
```

**Explanation:**

1. **Controller Decorator:**
   - `@Controller('auth')`: This decorator defines the base route for all endpoints within this controller. In this case, all routes will start with `/auth`.

2. **Constructor:**
   - The constructor injects the `AuthService` which provides methods for handling authentication logic.

3. **loginUser Method:**
   - **Decorators:**
     - `@UseGuards(AuthGuard('local-user'))`: Applies the `local-user` strategy guard to this route. This means that the request will be authenticated using the `LocalUserStrategy` before proceeding to the method.
     - `@Post('login-user')`: Maps this method to HTTP POST requests sent to `/auth/login-user`.

   - **Method Logic:**
     - `@Req() req`: The `req` parameter contains the request object, including user details that were authenticated by the `LocalUserStrategy`.
     - `console.log(req.user)`: Logs the authenticated user object for debugging purposes.
     - `return this.authService.loginUser(req.user)`: Calls `loginUser` from the `AuthService` to generate a JWT token for the authenticated user and returns it as the response.

4. **loginAdmin Method:**
   - **Decorators:**
     - `@UseGuards(AuthGuard('local-admin'))`: Applies the `local-admin` strategy guard to this route. This means that the request will be authenticated using the `LocalAdminStrategy` before proceeding to the method.
     - `@Post('login-admin')`: Maps this method to HTTP POST requests sent to `/auth/login-admin`.

   - **Method Logic:**
     - `@Req() req`: The `req` parameter contains the request object, including admin details that were authenticated by the `LocalAdminStrategy`.
     - `console.log(req.user)`: Logs the authenticated admin object for debugging purposes.
     - `return this.authService.loginAdmin(req.user)`: Calls `loginAdmin` from the `AuthService` to generate a JWT token for the authenticated admin and returns it as the response.

---
