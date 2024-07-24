from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from .database import engine, get_db
from .models import Base, Role
from .auth import auth_router
from .admin import admin_router
from .users import user_router
from .roles import initialize_roles
from .utils.middleware import authenticate_user_middleware

app = FastAPI()

# Create the database tables
Base.metadata.create_all(bind=engine)
initialize_roles()

# middleware
# This middleware checks if the user is authenticated before accessing the protected routes
app.middleware("http")(authenticate_user_middleware)

# Include routers in the app
app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(user_router)


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port="8000")
