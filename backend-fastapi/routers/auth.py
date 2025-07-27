# routers/auth.py
# Authentication endpoints

import datetime
import logging
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm

from auth.models import Token, User
from auth.security import authenticate_user, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
from auth.dependencies import get_current_active_user

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/token", response_model=Token, tags=["authentication"])
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    """Login endpoint to get access token"""
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    logger.info(f"User {user.username} logged in successfully")
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/users/me/", response_model=User, tags=["authentication"])
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    """Get current user information"""
    return current_user