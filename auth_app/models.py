from fastapi import Depends
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Table
from sqlalchemy.sql import func
from sqlalchemy.orm import Session, relationship
from datetime import datetime
from .database import Base, get_db
from .utils.password_hashing import verify_password
from .schemas import UserInfoSchema, AdminUserInfoSchema


# Association table for many-to-many relationship between roles and permissions
role_permissions = Table(
    'role_permissions',
    Base.metadata,
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True),
    Column('permission_id', Integer, ForeignKey('permissions.id'), primary_key=True)
)

class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    role = Column(String(length=50), unique=True, index=True)
    permissions = relationship('Permission', secondary=role_permissions, back_populates='roles')

    __table_args__ = {"extend_existing": True}

    @classmethod
    def find_by_id(self, id: str, db: Session = Depends(get_db)):
        query = db.query(self).filter(self.id == id)
        role = query.first()
        return role

    @classmethod
    def find_by_role(self, role: str, db: Session = Depends(get_db)):
        query = db.query(self).filter(self.role == role)
        role = query.first()
        return role

class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(length=100), index=True)
    description = Column(String(length=255), nullable=True)
    roles = relationship('Role', secondary=role_permissions, back_populates='permissions')

    __table_args__ = {"extend_existing": True}

    @classmethod
    def find_by_id(self, id: str, db: Session = Depends(get_db)):
        query = db.query(self).filter(self.id == id)
        permission = query.first()
        return permission

    @classmethod
    def find_by_name(self, name: str, db: Session = Depends(get_db)):
        query = db.query(self).filter(self.name == name)
        permission = query.first()
        return permission

    @classmethod
    def get_permissions_by_role(self, role: str, db: Session = Depends(get_db)):
        role = Role.find_by_role(role, db)
        permissions = db.query(self).filter(self.role_id == role.id).all()
        all_permissions = []
        for permission in permissions:
            all_permissions.append(permission.permission)

        return list(all_permissions)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(length=50), unique=False, index=True)
    email = Column(String(length=100), unique=True, index=True)
    password = Column(String(length=128))
    role_id = Column(Integer, ForeignKey("roles.id"))

    role = relationship("Role", back_populates="users")

    __table_args__ = {"extend_existing": True}

    @classmethod
    def find_by_id(self, id: str, db: Session = Depends(get_db)):
        query = db.query(self).filter(self.id == id)
        user = query.first()
        return user

    @classmethod
    def find_by_email(self, email: str, db: Session = Depends(get_db)):
        query = db.query(self).filter(self.email == email)
        user = query.first()
        return user

    @classmethod
    def authenticate(self, email: str, password: str, db: Session = Depends(get_db)):
        user = self.find_by_email(email, db)
        if not user or not verify_password(password, user.password):
            return False
        return user

    @classmethod
    def get_all_users(self, db: Session = Depends(get_db)):
        users = db.query(self).all()
        all_users = []
        for user in users:
            all_users.append(AdminUserInfoSchema(
                id=user.id,
                username=user.username,
                email=user.email,
                role=user.role.role
            ))

        return list(all_users)

    @classmethod
    def assign_role(self, role: str, db: Session = Depends(get_db)):
        role = Role.find_by_role(role, db)
        self.role = role.id
        db.commit()

Role.users = relationship("User", order_by=User.id, back_populates="role")

class BlackListToken(Base):
    __tablename__ = "blacklist_tokens"

    id = Column(String(36), primary_key=True, index=True)
    expire = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = {"extend_existing": True}

    @classmethod
    def find_by_id(self, id: str, db: Session = Depends(get_db)):
        query = db.query(self).filter(self.id == id)
        token = query.first()
        return token
