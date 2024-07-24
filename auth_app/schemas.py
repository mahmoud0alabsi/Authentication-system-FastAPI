from pydantic import BaseModel, Field, EmailStr
from datetime import datetime

class UserBase(BaseModel):
    username: str
    email: EmailStr

# schema for the register endpoint   
class RegisterSchema(UserBase):
    password: str = Field(
        min_length=8,
    )

    class Config:
        hidden = ["password"]
        json_schema_extra = {
            "example": {
                "username": "Mahmoud",
                "email": "email@example.com",
                "password": "password"
            }
        }

# schema for the login endpoint
class LoginSchema(BaseModel):
    email: EmailStr
    password: str

    class Config:
        json_schema_extra = {
            "example": {
                "email": "email@example.com",
                "password": "password"
            }
        }

# schema for the response of the register endpoint
class RegisterResponse(UserBase):
    message: str

    class Config:
        from_attributes = True

# schema for the response of the login endpoint
class LoginResponse(BaseModel):
    token: str
    message: str

# schema for the jwt token
class JwtTokenSchema(BaseModel):
    token: str
    payload: dict
    expire: datetime

# schema for the token pair (access and refresh)
class TokenPair(BaseModel):
    access: JwtTokenSchema
    refresh: JwtTokenSchema

# schema for the token data
class TokenData(BaseModel):
    user_id: str | None = None

# schema for the blacklisted token
class BlackListToken(BaseModel):
    id: int
    expire: datetime

    class Config:
        from_attributes = True

# schema for the success response (e.g. logout success)
class SuccessResponseSchema(BaseModel):
    message: str | None = None

class UserInfoSchema(BaseModel):
    username: str
    email: EmailStr
    role: str

    class Config:
        json_schema_extra = {
            "example": {
                "username": "Mahmoud",
                "email": "email@example.com",
                "role": "user",
            }
        }

class AdminUserInfoSchema(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: str

    class Config:
        json_schema_extra = {
            "example": {
                "username": "Mahmoud",
                "email": "email@example.com",
                "role": "user",
            }
        }
