from fastapi import APIRouter, Depends, HTTPException, status, Cookie, Request, Response
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer
from typing import Annotated
from .models import User, Role
from .schemas import RegisterSchema, LoginSchema, RegisterResponse, LoginResponse, SuccessResponseSchema
from .database import get_db
from .dependencies import *
from .utils.exceptions import BadRequestException, ForbiddenException
from .utils.password_hashing import get_password_hash

auth_router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


@auth_router.post("/register", response_model=RegisterResponse, tags=["auth"], response_description="User registered successfully")
def register(user: RegisterSchema,
             db: Session = Depends(get_db)):
    try:
        # check if user already registered
        get_user = User.find_by_email(db=db, email=user.email)
        if get_user:
            raise BadRequestException(detail="User already registered")

        # hashing password
        hashed_password = get_password_hash(user.password)

        # get user role
        role = Role.find_by_role(role="user", db=db)

        # create new user instance
        new_user = User(username=user.username,
                        email=user.email,
                        password=hashed_password,
                        role=role
                        )

        # save user to db
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return RegisterResponse(
            username=new_user.username,
            email=new_user.email,
            message="User registered successfully"
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@auth_router.post("/login", response_model=LoginResponse, tags=["auth"], response_description="User logged in successfully")
def login(user: LoginSchema,
          request: Request,
          response: Response,
          db: Session = Depends(get_db)):

    try:
        # check if user logged in by check refresh token
        refresh_token = get_refresh_token_from_cookie(request=request)
        if refresh_token:
            raise ForbiddenException(detail="User already logged in")

        user = User.authenticate(
            db=db, email=user.email, password=user.password)

        if not user:
            raise AuthFailedException(detail="Incorrect email or password")

        # create token pair (access token and refresh token)
        token_pair = create_token_pair(user=user)

        # add refresh token to cookie
        add_refresh_token_cookie(
            response=response, token=token_pair.refresh.token)

        return LoginResponse(
            token=token_pair.access.token,
            message="Successfully logged in",
        )
    except Exception as e:
        raise BadRequestException(detail=str(e))


@auth_router.post("/logout", response_model=SuccessResponseSchema, tags=["auth"], response_description="User logged out successfully")
def logout(
        response: Response,
        token: Annotated[str, Depends(oauth2_scheme)],
        db: Session = Depends(get_db)):
    try:
        payload = decode_access_token(token=token, db=db)
        # check if token is blacklisted
        if BlackListToken.find_by_id(payload[JTI], db):
            raise ForbiddenException(detail="Token already blacklisted")

        black_listed = BlackListToken(
            id=payload[JTI], expire=datetime.utcfromtimestamp(payload[EXP])
        )

        # save blacklisted token to db
        db.add(black_listed)
        db.commit()

        # Delete refresh token cookie
        response.set_cookie(key="refresh_token", value="", expires=0)

        return SuccessResponseSchema(message="Successfully logged out")
    except ForbiddenException as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e) + ', user not logged in')


@auth_router.post("/auth/refresh", tags=["auth"], response_description="Token refreshed successfully")
def refresh(refresh_token: Annotated[str | None, Cookie()] = None):
    if not refresh_token:
        raise BadRequestException(detail="refresh token required")
    return refresh_token_state(token=refresh_token)
