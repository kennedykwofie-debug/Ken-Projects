"""Organisation and user management endpoints."""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel
from src.db.database import get_db
from src.db.models import Organisation, User, UserRole, OrgPlan
from src.auth.dependencies import get_current_user, require_admin, require_superadmin
from src.auth.security import hash_password

router = APIRouter(prefix="/orgs", tags=["Organisations"])
users_router = APIRouter(prefix="/users", tags=["Users"])

class OrgResponse(BaseModel):
    id: str; name: str; slug: str; plan: str
    industry: Optional[str]; country: Optional[str]; is_active: bool
    user_count: int = 0; asset_count: int = 0

class UpdateOrgRequest(BaseModel):
    name: Optional[str] = None; industry: Optional[str] = None
    country: Optional[str] = None; settings: Optional[dict] = None

class CreateUserRequest(BaseModel):
    email: str; password: str; full_name: Optional[str] = None
    role: UserRole = UserRole.USER

class UpdateUserRequest(BaseModel):
    full_name: Optional[str] = None; role: Optional[UserRole] = None; is_active: Optional[bool] = None

class UserListResponse(BaseModel):
    id: str; email: str; full_name: Optional[str]; role: str; is_active: bool; last_login: Optional[str]

@router.get("/me", response_model=OrgResponse)
async def get_my_org(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(Organisation).where(Organisation.id == current_user.org_id))
    org = r.scalar_one_or_none()
    if not org: raise HTTPException(status_code=404, detail="Org not found")
    uc = await db.execute(select(func.count(User.id)).where(User.org_id == org.id))
    return OrgResponse(id=org.id, name=org.name, slug=org.slug, plan=org.plan.value,
        industry=org.industry, country=org.country, is_active=org.is_active, user_count=uc.scalar() or 0)

@router.patch("/me", response_model=OrgResponse)
async def update_my_org(body: UpdateOrgRequest, current_user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(Organisation).where(Organisation.id == current_user.org_id))
    org = r.scalar_one_or_none()
    if not org: raise HTTPException(status_code=404, detail="Not found")
    if body.name: org.name = body.name
    if body.industry is not None: org.industry = body.industry
    if body.country is not None: org.country = body.country
    if body.settings is not None: org.settings = {**(org.settings or {}), **body.settings}
    return OrgResponse(id=org.id, name=org.name, slug=org.slug, plan=org.plan.value,
        industry=org.industry, country=org.country, is_active=org.is_active)

@router.get("/all", response_model=List[OrgResponse])
async def list_all_orgs(current_user: User = Depends(require_superadmin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(Organisation).order_by(Organisation.created_at.desc()))
    return [OrgResponse(id=o.id, name=o.name, slug=o.slug, plan=o.plan.value,
        industry=o.industry, country=o.country, is_active=o.is_active) for o in r.scalars().all()]

@router.patch("/{org_id}/suspend")
async def suspend_org(org_id: str, current_user: User = Depends(require_superadmin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(Organisation).where(Organisation.id == org_id))
    org = r.scalar_one_or_none()
    if not org: raise HTTPException(status_code=404, detail="Not found")
    org.is_active = False
    return {"message": f"Org {org.name} suspended"}

@users_router.get("/", response_model=List[UserListResponse])
async def list_users(current_user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(User).where(User.org_id == current_user.org_id).order_by(User.created_at))
    return [UserListResponse(id=u.id, email=u.email, full_name=u.full_name, role=u.role.value,
        is_active=u.is_active, last_login=u.last_login.isoformat() if u.last_login else None) for u in r.scalars().all()]

@users_router.post("/", response_model=UserListResponse, status_code=201)
async def create_user(body: CreateUserRequest, current_user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(User).where(User.email == body.email.lower(), User.org_id == current_user.org_id))
    if r.scalar_one_or_none(): raise HTTPException(status_code=400, detail="Email already exists")
    if body.role == UserRole.SUPERADMIN: raise HTTPException(status_code=403, detail="Cannot assign superadmin")
    user = User(org_id=current_user.org_id, email=body.email.lower(), full_name=body.full_name,
        password_hash=hash_password(body.password), role=body.role, is_verified=True)
    db.add(user); await db.flush()
    return UserListResponse(id=user.id, email=user.email, full_name=user.full_name,
        role=user.role.value, is_active=user.is_active, last_login=None)

@users_router.patch("/{user_id}", response_model=UserListResponse)
async def update_user(user_id: str, body: UpdateUserRequest, current_user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(User).where(User.id == user_id, User.org_id == current_user.org_id))
    user = r.scalar_one_or_none()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_user.id: raise HTTPException(status_code=400, detail="Cannot modify own account")
    if body.role == UserRole.SUPERADMIN: raise HTTPException(status_code=403, detail="Cannot assign superadmin")
    if body.full_name is not None: user.full_name = body.full_name
    if body.role is not None: user.role = body.role
    if body.is_active is not None: user.is_active = body.is_active
    return UserListResponse(id=user.id, email=user.email, full_name=user.full_name,
        role=user.role.value, is_active=user.is_active,
        last_login=user.last_login.isoformat() if user.last_login else None)

@users_router.delete("/{user_id}")
async def delete_user(user_id: str, current_user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(User).where(User.id == user_id, User.org_id == current_user.org_id))
    user = r.scalar_one_or_none()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_user.id: raise HTTPException(status_code=400, detail="Cannot delete yourself")
    await db.delete(user)
    return {"message": "User removed"}
