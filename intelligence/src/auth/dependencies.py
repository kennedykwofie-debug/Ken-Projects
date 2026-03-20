"""FastAPI auth dependencies."""
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from jose import JWTError
from src.db.database import get_db
from src.db.models import User, UserRole
from src.auth.security import decode_token

bearer_scheme = HTTPBearer(auto_error=False)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme), db: AsyncSession = Depends(get_db)) -> User:
    exc = HTTPException(status_code=401, detail="Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    if not credentials: raise exc
    try:
        payload = decode_token(credentials.credentials)
        if payload.get("type") != "access": raise exc
        user_id = payload.get("sub")
        if not user_id: raise exc
    except JWTError: raise exc
    result = await db.execute(select(User).where(User.id == user_id, User.is_active == True))
    user = result.scalar_one_or_none()
    if not user: raise exc
    return user

def require_roles(*roles: UserRole):
    async def _check(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles and current_user.role != UserRole.SUPERADMIN:
            raise HTTPException(status_code=403, detail=f"Required roles: {[r.value for r in roles]}")
        return current_user
    return _check

require_admin = require_roles(UserRole.ADMIN)
require_analyst = require_roles(UserRole.ADMIN, UserRole.ANALYST)
require_any = require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.USER)
require_superadmin = require_roles(UserRole.SUPERADMIN)
