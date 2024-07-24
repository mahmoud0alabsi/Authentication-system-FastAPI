from fastapi import APIRouter, Depends
from typing import Annotated
from .schemas import UserInfoSchema
from .models import User
from .dependencies import get_current_user
from .roles import PermissionsChecker
user_router = APIRouter()

@user_router.get("/users/me", dependencies=[Depends(PermissionsChecker(required_permissions=["view_own_profile"]))], response_model=UserInfoSchema, tags=["users"], response_description="Get user information")
def read_users_me(user: Annotated[User, Depends(get_current_user)]):
    return UserInfoSchema(
        username=user.username,
        email=user.email,
        role=user.role.role
    )
