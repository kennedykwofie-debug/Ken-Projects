"""JWT and password security utilities."""
import os,secrets,hashlib
from datetime import datetime,timedelta,timezone
from jose import JWTError,jwt
from passlib.context import CryptContext
SECRET_KEY=os.getenv("JWT_SECRET_KEY",secrets.token_hex(32))
ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES=60*8
REFRESH_TOKEN_EXPIRE_DAYS=30
pwd_context=CryptContext(schemes=["bcrypt"],deprecated="auto")
def hash_password(p):return pwd_context.hash(p)
def verify_password(p,h):return pwd_context.verify(p,h)
def create_access_token(data,expires_delta=None):
    to_encode=data.copy()
    expire=datetime.now(timezone.utc)+(expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp":expire,"type":"access"})
    return jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)
def create_refresh_token(user_id):
    expire=datetime.now(timezone.utc)+timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    return jwt.encode({"sub":user_id,"exp":expire,"type":"refresh"},SECRET_KEY,algorithm=ALGORITHM)
def decode_token(token):return jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
def hash_token(token):return hashlib.sha256(token.encode()).hexdigest()
def generate_api_key():
    raw="dw_"+secrets.token_urlsafe(40)
    return raw,raw[:10],hashlib.sha256(raw.encode()).hexdigest()
