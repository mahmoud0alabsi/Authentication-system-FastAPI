# FastAPI User Authentication and Authorization System

![Python](https://img.shields.io/badge/python-v3.9+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.65.2-green.svg)
![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-1.4.23-red.svg)
![MySQL](https://img.shields.io/badge/MySQL-8.0.25-orange.svg)
![Postman](https://img.shields.io/badge/Postman-v8.0+-yellow.svg)
![VSCode](https://img.shields.io/badge/VSCode-1.58.0-lightgrey.svg)

## :ledger: Table of Contents

- [Brief Description and Technologies Used](#beginner-description)
- [Project Structure](#file_folder-project-structure)
- [Project Components](#package-project-components)
- [Serving the Project Files](#zap-how-to-navigate-the-project)
- [Endpoints](#rocket-endpoints)
   - [Authentication](#authentication-endpoints)
   - [Admin](#admin-endpoints)
   - [Users](#user-endpoints)
- [Models](#page_facing_up-models)
- [How to Run the Project](#electric_plug-how-to-run-the-project)
- [More Explanations](#notebook-more-explanations)
   - [JWT Authentication](#jwt-authentication)
   - [Middlewares](#middleware)
   - [Roles and Permissions](#roles-and-permissions)
- [Contact Information](#contact-information)

---

## :beginner: Description

This project implements an authentication and authorization system using **FastAPI**, **SQLAlchemy**, and **MySQL**. It includes JWT-based authentication, role-based access control, and middleware to manage authentication state. The project can be tested with **Postman** and developed in **VSCode**.

<p align="center">
  <img src="https://learnersgalaxy.ai/wp-content/uploads/2024/01/Python-Symbol.png" alt="Logo 1" style="width: 16%; max-width: 100px; height: auto;"/>
  <img src="https://d1.awsstatic.com/asset-repository/products/amazon-rds/1024px-MySQL.ff87215b43fd7292af172e2a5d9b844217262571.png" alt="Logo 4" style="width: 14%; max-width: 100px; height: auto;"/>
  <img src="https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png" alt="Logo 2" style="width: 16%; max-width: 100px; height: auto;"/>
  <img src="https://seeklogo.com/images/J/jwt-logo-11B708E375-seeklogo.com.png" alt="Logo 2" style="width: 16%; max-width: 100px; height: auto;"/>
  <img src="https://www.sqlalchemy.org/img/sqla_logo.png" alt="Logo 3" style="width: 16%; max-width: 100px; height: auto;"/>
  <img src="https://uxwing.com/wp-content/themes/uxwing/download/brands-and-social-media/postman-icon.png" alt="Logo 5" style="width: 6%; max-width: 100px; height: auto;"/>
  <img src="https://tidalcycles.org/assets/images/vscodeicon-42dc264fde2adb74cc197fe6d02b183c.png" alt="Logo 6" style="width: 6%; max-width: 100px; height: auto;"/>
</p>

## :file_folder: Project Structure

```
.
auth_app/
├── pycache/
├── utils/
│ ├── pycache/
│ ├── exceptions.py
│ ├── middleware.py
│ ├── password_hashing.py
│ └── init.py
├── admin.py
├── auth.py
├── config.py
├── database.py
├── dependencies.py
├── main.py
├── models.py
├── roles.py
├── schemas.py
├── users.py
.env
requirements.txt
```


## :package: Project Components

- **main.py**: The entry point of the project where the FastAPI application is initialized and configured.

- **database.py**: Establishes the database connection using SQLAlchemy and connects to the MySQL server.

- **models.py**: Defines the database models for `User`, `BlackListToken`, `Role`, and `Permission`.

- **schemas.py**: Contains Pydantic schemas for data validation, such as `register`, `login`, `userInfo`, and others.

- **auth.py**: Contains authentication-related endpoints, including `login`, `register`, and `logout`.

- **users.py**: Includes endpoints related to user operations, such as `/users/me`.

- **admin.py**: Defines admin-related endpoints, particularly for managing users, such as `/admin`.

- **roles.py**: Sets up default roles and permissions, and includes a classes to handle role-based checks and permissions checks.

- **dependencies.py**: Contains dependency functions for JWT encoding, decoding, access token generation, etc.

- **utils**: Provides utility functions and files:
  - **middlewares.py**: Defines middleware for handling request authentication.
  - **exceptions.py**: Contains custom exception handling logic.
  - **password_hashing.py**: Manages password hashing and verification.

## :zap: How to Navigate the Project

1. **Start from the `main.py` file**: This is where the FastAPI app is instantiated and all the routers are registered.

2. **Examine the `database.py` file**: Understand how the database connection is set up and configured.

3. **Explore the `models.py` and `schemas.py` files**: Review the data models and schemas that define the structure of the data being handled.

4. **Look into the `roles.py` file**: This file initializes roles and permissions.

5. **Check out the `dependencies.py` file**: See how dependencies are managed, especially those related to authentication.

6. **Review the `auth.py`, `users.py`, and `admin.py` files**: Explore the API endpoints for authentication and user management.

7. **Investigate the `middleware.py` file**: Understand the middleware that handles authentication logic.

## :rocket: Endpoints

### Authentication Endpoints

- `POST /register`: Register a new user, request body:
  
  ```json
    {
      "username" : "mahmoud",
      "email" : "mahmoud@example.com",
      "password" : "password"
    }
  ```
  
- `POST /login`: Log in a user and obtain access and refresh tokens, request body:

  ```json
    {
      "email" : "mahmoud@example.com",
      "password" : "password"
    }
  ```
  
- `POST /logout`: Log out the user.
- `POST /auth/refresh`: Refresh the access token using a refresh token manually.

### Admin Endpoints

- `GET /admin`: Retrieve all users in the database.

### User Endpoints

- `GET /users/me`: Retrieve the current user's information.

## :page_facing_up: Models

###  User
- Defines user attributes.
### BlackListed
- Manages blacklisted tokens.
### Role
- Defines roles and their permissions.
### Permission
- Defines various permissions.

## :electric_plug: How to Run the Project

1. **Clone the Project**:

   ```bash
   git clone https://github.com/mahmoud0alabsi/Authentication-system-FastAPI.git
   cd Authentication-system-FastAPI
   ```

2. **Install FastAPI and other dependencies**: Use the requirements.txt to install all necessary packages.

    ```bash
    pip install -r requirements.txt
    ```

3. **Run MySQL Server**: I recommend using XAMPP for setting up the MySQL server.

4. **Update the .env File**: Add your database server configurations and modify JWT token expiration times as needed.
   ```python
    DB_USER=
    DB_PASSWORD=
    DB_HOST=
    DB_NAME=
    DB_PORT=
    
    JWT_SECRET=1ce89dac276525d9a464aff95a4f64ce71cc47b732e457097888cff56737bf2a
    ALGORITHM=HS256
    ACCESS_TOKEN_EXPIRES_MINUTES=15
    REFRESH_TOKEN_EXPIRES_MINUTES=10080

6. **Start the FastAPI application**:

    ```bash
    uvicorn auth_app.main:app --reload
    ```

7. **Test Endpoints with Postman**:

    - Register a new user and log in to receive an access token.
    - Add the access token to the request headers in Postman as a Bearer token for protected routes.
    - Refresh the access token as needed and update the Postman headers accordingly.

   ![Postman Screenshot](screenshot_placeholder.png)

## :notebook: More Explanations

### JWT Authentication

This project utilizes JWT for authentication, with both access and refresh tokens. When the access token expires, the middleware automatically generates a new one using the refresh token (if valid).

### Middleware

The middleware is designed to authenticate users before allowing access to protected routes:

- It verifies the access token.
- If the access token is expired, it checks the refresh token.
- If the refresh token is valid, it issues a new access token.
- If both tokens are expired, it logs the user out by clearing the refresh token from the cookies.

### Roles and Permissions

The **initialize_roles** function initializes roles and permissions tables in the database with default values at startup. We have two main roles, admin and user, each with specific permissions used for authorization.


## Contact Information
- **Author:** Mahmoud Alabsi
- **Email:** [malabsi034@gmail.com](mailto:malabsi034@gmail.com)
- **LinkedIn:** [Mahmoud Alabsi](https://linkedin.com/in/mahmoud-alabsi)
- **GitHub:** [mahmoud0alabsi](https://github.com/mahmoud0alabsi)
