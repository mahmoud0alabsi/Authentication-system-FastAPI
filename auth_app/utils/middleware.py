import jwt
from fastapi import Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.exceptions import HTTPException
from datetime import datetime, timedelta
from ..roles import RoleChecker
from ..dependencies import *
from .exceptions import ForbiddenException
from ..database import get_db
from ..models import User, BlackListToken

# Middleware to authenticate user before accessing protected routes
# This middleware checks if the user is authenticated by verifying the access token
# If the access token is valid, the user is allowed to access the route
# If the access token is expired, the middleware checks if the refresh token is valid
# If the refresh token is valid, a new access token is generated and returned to the user
# If the refresh token is expired, the user is logged out by clearing the refresh token from the cookie
async def authenticate_user_middleware(request: Request, call_next):
    authenticated_routes = ["/admin", "/users", "/logout"]

    if request.url.path.startswith(tuple(authenticated_routes)):
        db = next(get_db())
        try:
            # Extract access token from Authorization header
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return JSONResponse(status_code=401, content={"detail": "Authorization header missing or malformed"})

            access_token = auth_header.split(" ")[1]

            # Decode the access token
            try:
                payload = only_decode_token(access_token)
                user_id = payload.get("sub")
                user = User.find_by_id(user_id, db)
                if user is None:
                    return JSONResponse(status_code=401, content={"detail": "Invalid credentials"})
            except jwt.exceptions.PyJWTError:
                # Access token expired, try refreshing it
                refresh_token = get_refresh_token_from_cookie(request)
                if not refresh_token:
                    return JSONResponse(status_code=401, content={"detail": "User not logged in"})
                # Decode refresh token
                try:
                    refresh_payload = only_decode_token(refresh_token)

                    # Generate a new access token
                    new_access_token = refresh_token_state(refresh_token)[
                        "token"]

                    return JSONResponse(
                        status_code=200,
                        content={"message": "Access token refreshed, continue using it",
                                 "access_token": new_access_token,
                                 "token_type": "bearer"}
                    )
                # If refresh token is expired or invalid, clear it from cookie
                except jwt.exceptions.PyJWTError as e:
                    # clear refresh token from cookie (logout)
                    response = await call_next(request)
                    response.delete_cookie("refresh_token")
                    return response
                except AuthFailedException as e:
                    return JSONResponse(status_code=401, content={"detail": str(e) + ", Auth error"})
            except AuthFailedException as e:
                return JSONResponse(status_code=401, content={"detail": str(e)})
        except Exception as e:
            return JSONResponse(status_code=500, content={"detail": str(e)})

    response = await call_next(request)
    return response
