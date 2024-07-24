from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Annotated
from .models import User
from .dependencies import get_current_user
from .roles import RoleChecker, PermissionsChecker
from .database import get_db

admin_router = APIRouter()

# get all users information in database
# this end-point requires:
# - user to be logged in
# - user to have admin role
@admin_router.get("/admin", dependencies=[Depends(PermissionsChecker(required_permissions=["view_users"]))], tags=["admin"], response_description="Get users information")
def get_users(user: Annotated[User, Depends(get_current_user)], db: Session = Depends(get_db)):
    try:
        return User.get_all_users(db)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
