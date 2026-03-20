"""Auth router: register, login, refresh, me, logout."""
import re
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, field_validator
from src.db.database import get_db
from src.db.models import Organisation, User, UserSession, UserRole, OrgPlan
from src.auth.security import hash_password,verify_password,create_access_token,create_refresh_token,decode_token,hash_token
from src.auth.dependencies import get_current_user

router=APIRouter(prefix="/auth",tags=["Auth"])

class RegisterRequest(BaseModel):
    org_name:str;org_industry:Optional[str]=None;email:str;password:str;full_name:Optional[str]=None
    @field_validator("password")
    @classmethod
    def pw(cls,v):
        if len(v)<8:raise ValueError("Password must be at least 8 characters")
        return v
    @field_validator("org_name")
    @classmethod
    def on(cls,v):
        if len(v.strip())<2:raise ValueError("Org name too short")
        return v.strip()

class LoginRequest(BaseModel):
    email:str;password:str

class TokenResponse(BaseModel):
    access_token:str;refresh_token:str;token_type:str="bearer";user:dict;org:dict

class RefreshRequest(BaseModel):
    refresh_token:str

class UserResponse(BaseModel):
    id:str;email:str;full_name:Optional[str];role:str;org_id:str;org_name:str;org_plan:str;is_verified:bool

def _slug(n):return re.sub(r"[^a-z0-9]+","-",n.lower()).strip("-")[:50]

async def _unique_slug(db,base):
    slug=_slug(base);suffix=0
    while True:
        c=slug if suffix==0 else f"{slug}-{suffix}"
        r=await db.execute(select(Organisation).where(Organisation.slug==c))
        if not r.scalar_one_or_none():return c
        suffix+=1

@router.post("/register",response_model=TokenResponse,status_code=201)
async def register(body:RegisterRequest,request:Request,db:AsyncSession=Depends(get_db)):
    r=await db.execute(select(User).where(User.email==body.email.lower()))
    if r.scalar_one_or_none():raise HTTPException(400,"Email already registered")
    slug=await _unique_slug(db,body.org_name)
    org=Organisation(name=body.org_name,slug=slug,plan=OrgPlan.FREE,industry=body.org_industry)
    db.add(org);await db.flush()
    user=User(org_id=org.id,email=body.email.lower(),full_name=body.full_name,password_hash=hash_password(body.password),role=UserRole.ADMIN,is_verified=True)
    db.add(user);await db.flush()
    access=create_access_token({"sub":user.id,"org":org.id,"role":user.role.value})
    refresh=create_refresh_token(user.id)
    db.add(UserSession(user_id=user.id,token_hash=hash_token(refresh),expires_at=datetime.now(timezone.utc).replace(tzinfo=None),ip_address=request.client.host if request.client else None))
    return TokenResponse(access_token=access,refresh_token=refresh,user={"id":user.id,"email":user.email,"full_name":user.full_name,"role":user.role.value},org={"id":org.id,"name":org.name,"slug":org.slug,"plan":org.plan.value})

@router.post("/login",response_model=TokenResponse)
async def login(body:LoginRequest,request:Request,db:AsyncSession=Depends(get_db)):
    r=await db.execute(select(User).where(User.email==body.email.lower(),User.is_active==True))
    user=r.scalar_one_or_none()
    if not user or not verify_password(body.password,user.password_hash):raise HTTPException(401,"Invalid email or password")
    org_r=await db.execute(select(Organisation).where(Organisation.id==user.org_id))
    org=org_r.scalar_one_or_none()
    if not org or not org.is_active:raise HTTPException(403,"Org suspended")
    user.last_login=datetime.now(timezone.utc).replace(tzinfo=None)
    access=create_access_token({"sub":user.id,"org":org.id,"role":user.role.value})
    refresh=create_refresh_token(user.id)
    db.add(UserSession(user_id=user.id,token_hash=hash_token(refresh),expires_at=datetime.now(timezone.utc).replace(tzinfo=None),ip_address=request.client.host if request.client else None))
    return TokenResponse(access_token=access,refresh_token=refresh,user={"id":user.id,"email":user.email,"full_name":user.full_name,"role":user.role.value},org={"id":org.id,"name":org.name,"slug":org.slug,"plan":org.plan.value})

@router.post("/refresh",response_model=TokenResponse)
async def refresh_token(body:RefreshRequest,db:AsyncSession=Depends(get_db)):
    try:
        payload=decode_token(body.refresh_token)
        if payload.get("type")!="refresh":raise ValueError
        user_id=payload["sub"]
    except:raise HTTPException(401,"Invalid refresh token")
    r=await db.execute(select(UserSession).where(UserSession.token_hash==hash_token(body.refresh_token),UserSession.user_id==user_id))
    session=r.scalar_one_or_none()
    if not session:raise HTTPException(401,"Session not found")
    user_r=await db.execute(select(User).where(User.id==user_id,User.is_active==True))
    user=user_r.scalar_one_or_none()
    if not user:raise HTTPException(401,"User not found")
    org_r=await db.execute(select(Organisation).where(Organisation.id==user.org_id))
    org=org_r.scalar_one_or_none()
    access=create_access_token({"sub":user.id,"org":user.org_id,"role":user.role.value})
    new_refresh=create_refresh_token(user.id)
    await db.delete(session)
    db.add(UserSession(user_id=user.id,token_hash=hash_token(new_refresh),expires_at=datetime.now(timezone.utc).replace(tzinfo=None)))
    return TokenResponse(access_token=access,refresh_token=new_refresh,user={"id":user.id,"email":user.email,"full_name":user.full_name,"role":user.role.value},org={"id":org.id,"name":org.name,"slug":org.slug,"plan":org.plan.value} if org else {})

@router.get("/me",response_model=UserResponse)
async def me(current_user:User=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    org_r=await db.execute(select(Organisation).where(Organisation.id==current_user.org_id))
    org=org_r.scalar_one_or_none()
    return UserResponse(id=current_user.id,email=current_user.email,full_name=current_user.full_name,role=current_user.role.value,org_id=current_user.org_id,org_name=org.name if org else "",org_plan=org.plan.value if org else "free",is_verified=current_user.is_verified)

@router.post("/logout")
async def logout(body:RefreshRequest,current_user:User=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    r=await db.execute(select(UserSession).where(UserSession.token_hash==hash_token(body.refresh_token),UserSession.user_id==current_user.id))
    session=r.scalar_one_or_none()
    if session:await db.delete(session)
    return{"message":"Logged out"}
