import jwt
import uuid
from datetime import datetime, timedelta, timezone
from fastapi import Depends, Response, Request, HTTPException, status
from sqlalchemy.orm import Session
from typing import Annotated
from fastapi.security import OAuth2PasswordBearer
from .config import settings
from .utils.exceptions import AuthFailedException, AuthTokenExpiredException, ForbiddenException
from .database import get_db
from .models import User, BlackListToken
from .schemas import JwtTokenSchema, TokenPair, TokenData


SUB = "sub"  # SUB is the subject of the token
EXP = "exp"  # EXP is the expiration time of the token
IAT = "iat"  # IAT is the time the token was issued
JTI = "jti"  # JTI is a unique identifier for the token

JWT_SECRET = settings.JWT_SECRET
JWT_ALGORITHM = settings.ALGORITHM
ACCESS_TOKEN_EXPIRES_MINUTES = settings.ACCESS_TOKEN_EXPIRES_MINUTES
REFRESH_TOKEN_EXPIRES_MINUTES = settings.REFRESH_TOKEN_EXPIRES_MINUTES

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


def _create_access_token(payload: dict):
    expire = datetime.utcnow() + timedelta(
        minutes=ACCESS_TOKEN_EXPIRES_MINUTES
    )

    # Add the expiration time to the payload
    payload[EXP] = expire

    # Create the JWT token
    token = JwtTokenSchema(
        token=jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM),
        payload=payload,
        expire=expire,
    )

    return token


def _create_refresh_token(payload: dict):
    expire = datetime.utcnow() + timedelta(minutes=REFRESH_TOKEN_EXPIRES_MINUTES)

    payload[EXP] = expire

    token = JwtTokenSchema(
        token=jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM),
        expire=expire,
        payload=payload,
    )

    return token


def create_token_pair(user: User):
    payload = {SUB: str(user.id), JTI: str(
        uuid.uuid4()), IAT: datetime.utcnow()}

    return TokenPair(
        access=_create_access_token(payload={**payload}),
        refresh=_create_refresh_token(payload={**payload}),
    )

# decode the token and check if it is blacklisted or expired
def decode_access_token(token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        black_list_token = BlackListToken.find_by_id(payload[JTI], db)
        if black_list_token:
            raise AuthTokenExpiredException()
        elif payload.get("exp") < datetime.utcnow().timestamp():
            raise AuthTokenExpiredException()
    except jwt.exceptions.PyJWTError:
        raise AuthFailedException()
    return payload

# decode the token without checking if it is blacklisted
def only_decode_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("exp") < datetime.utcnow().timestamp():
            raise jwt.exceptions.PyJWTError
    except jwt.exceptions.PyJWTError:
        raise jwt.exceptions.PyJWTError
    return payload

# refresh token state by creating a new access token
def refresh_token_state(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.exceptions.PyJWTError:
        raise AuthFailedException()

    payload[JTI] = str(uuid.uuid4())
    return {"token": _create_access_token(payload=payload).token}

def add_refresh_token_cookie(response: Response, token: str):
    exp = datetime.utcnow() + timedelta(minutes=REFRESH_TOKEN_EXPIRES_MINUTES)
    exp.replace(tzinfo=timezone.utc)

    response.set_cookie(
        key="refresh_token",
        value=token,
        expires=int(exp.timestamp()),
        httponly=True,
    )

# this function is used when the user need to refresh the token
def get_refresh_token_from_cookie(request: Request):
    return request.cookies.get("refresh_token")

# get the current user from the token
# this function is used as a dependency in the end-points that require the user to be logged in
def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_access_token(token, db)
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        token_data = TokenData(user_id=user_id)

    except jwt.exceptions.PyJWTError:
        raise ForbiddenException()
    except Exception as e:
        raise ForbiddenException(detail=str(e))

    user = db.query(User).filter(User.id == token_data.user_id).first()
    if user is None:
        raise credentials_exception
    return user
