from typing import Annotated
from fastapi import Depends, HTTPException, status
from .dependencies import get_current_user
from .models import User, Role, Permission
from .database import SessionLocal
from .utils.exceptions import ForbiddenException

# initialize roles and permissions tables in the database with default values at startup
def initialize_roles():
    with SessionLocal() as db:
        roles = ["user", "admin"]

        # default permissions
        permissions = [
            {"name": "view_users", "description": "View user details"},
            {"name": "edit_users", "description": "Edit user details"},
            {"name": "delete_users", "description": "Delete user accounts"},
            {"name": "view_own_profile", "description": "View own profile"},
            {"name": "edit_own_profile", "description": "Edit own profile"},
        ]

        # Add roles if they don't exist
        for role_name in roles:
            if not db.query(Role).filter_by(role=role_name).first():
                new_role = Role(role=role_name)
                db.add(new_role)

        db.commit()

        # Add permissions if they don't exist
        for perm_data in permissions:
            if not db.query(Permission).filter_by(name=perm_data["name"]).first():
                new_permission = Permission(
                    name=perm_data["name"], description=perm_data["description"])
                db.add(new_permission)

        db.commit()

        # Assign permissions to roles
        user_role = db.query(Role).filter_by(role="user").first()
        admin_role = db.query(Role).filter_by(role="admin").first()

        if user_role and admin_role:
            # Assign user permissions
            user_permissions = ["view_own_profile", "edit_own_profile"]
            for perm_name in user_permissions:
                permission = db.query(Permission).filter_by(
                    name=perm_name).first()
                if permission and permission not in user_role.permissions:
                    user_role.permissions.append(permission)

            # Assign admin permissions
            admin_permissions = ["view_users", "edit_users",
                                 "delete_users", "view_own_profile", "edit_own_profile"]
            for perm_name in admin_permissions:
                permission = db.query(Permission).filter_by(
                    name=perm_name).first()
                if permission and permission not in admin_role.permissions:
                    admin_role.permissions.append(permission)

            db.commit()


class RoleChecker:
    def __init__(self, allowed_roles):
        self.allowed_roles = allowed_roles

    def __call__(self, user: Annotated[User, Depends(get_current_user)]):
        if user.role.role in self.allowed_roles:
            return True
        raise ForbiddenException(
            detail="You don't have permission to access this resource")

class PermissionsChecker:
    def __init__(self, required_permissions):
        self.required_permissions = required_permissions

    def __call__(self, user: Annotated[User, Depends(get_current_user)]):
        user_permissions = [perm.name for perm in user.role.permissions]
        for perm in self.required_permissions:
            if perm not in user_permissions:
                raise ForbiddenException(
                    detail="You don't have permission to access this resource")
        return True
