"""Asset management endpoints."""
from typing import List,Optional
from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from src.db.database import get_db
from src.db.models import Asset,AssetType,User
from src.auth.dependencies import get_current_user,require_analyst
router=APIRouter(prefix="/assets",tags=["Assets"])
class AssetCreate(BaseModel):
    type:AssetType;value:str;label:Optional[str]=None;tags:Optional[List[str]]=[]
class AssetResponse(BaseModel):
    id:str;type:str;value:str;label:Optional[str];tags:List[str];is_active:bool;last_scanned:Optional[str];scan_data:dict
@router.get("/",response_model=List[AssetResponse])
async def list_assets(current_user:User=Depends(get_current_user),db:AsyncSession=Depends(get_db)):
    r=await db.execute(select(Asset).where(Asset.org_id==current_user.org_id,Asset.is_active==True).order_by(Asset.created_at.desc()))
    return [AssetResponse(id=a.id,type=a.type.value,value=a.value,label=a.label,tags=a.tags or [],is_active=a.is_active,last_scanned=a.last_scanned.isoformat() if a.last_scanned else None,scan_data=a.scan_data or {}) for a in r.scalars().all()]
@router.post("/",response_model=AssetResponse,status_code=201)
async def add_asset(body:AssetCreate,current_user:User=Depends(require_analyst),db:AsyncSession=Depends(get_db)):
    r=await db.execute(select(Asset).where(Asset.org_id==current_user.org_id,Asset.type==body.type,Asset.value==body.value.strip().lower()))
    if r.scalar_one_or_none():raise HTTPException(400,"Asset already exists")
    asset=Asset(org_id=current_user.org_id,type=body.type,value=body.value.strip().lower(),label=body.label,tags=body.tags or [],created_by=current_user.id)
    db.add(asset);await db.flush()
    return AssetResponse(id=asset.id,type=asset.type.value,value=asset.value,label=asset.label,tags=asset.tags or [],is_active=asset.is_active,last_scanned=None,scan_data={})
@router.delete("/{asset_id}")
async def delete_asset(asset_id:str,current_user:User=Depends(require_analyst),db:AsyncSession=Depends(get_db)):
    r=await db.execute(select(Asset).where(Asset.id==asset_id,Asset.org_id==current_user.org_id))
    asset=r.scalar_one_or_none()
    if not asset:raise HTTPException(404,"Asset not found")
    asset.is_active=False;return{"message":"Asset removed"}
