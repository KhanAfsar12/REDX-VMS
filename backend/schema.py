from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

class CameraConfig(BaseModel):
    name: str
    resolution: str
    fps: int = Field(15, ge=1, le=60)
    codec: str
    record_hour: int = Field(1, ge=1, le=24)
    retention_days: int = Field(30, ge=1)
    qty: int = Field(1, ge=1)
    bitrate_kbps: Optional[int] = Field(None, ge=100)
    
class RequirementRequest(BaseModel):
    customer_name: str
    project_name: str
    location: Optional[str] = None
    assigned_person: Optional[str] = None
    camera_configs: List[CameraConfig] = Field(..., min_items=1)

class RequirementResponse(RequirementRequest):
    id: str
    created_at: datetime
    bandwidth: float
    storage_tb: float
    server_spec: dict

class UserCreate(BaseModel):
    username: str
    password: str
    email: str
    full_name: Optional[str] = None
    role: str = "user"

class UserLogin(BaseModel):
    username: str
    password: str

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled : Optional[bool] = False
    role : str = 'user'

class UserInDB(User):
    hashed_password : str

class Token(BaseModel):
    access_token : str
    token_type : str

class TokenData(BaseModel):
    username : Optional[str] = None
    role : Optional[str] = None

class AdminUserCreate(BaseModel):
    username: str
    email: str
    full_name: str
    password: str
    role: str = "user"
    disabled: bool = False

class UserListResponse(BaseModel):
    users: List[User]

class UserBase(BaseModel):
    username: str
    email : str
    role : str

class UserCreate(UserBase):
    password : str
    is_active : bool = False
    created_by : Optional[str] = None

class UserUpdate(BaseModel):
    email : Optional[str] = None
    password : Optional[str] = None
    role : Optional[str] = None
    is_active: bool

class UserOut(UserBase):
    is_active: bool