from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List, Dict, Any

class IOCMetadataBase(BaseModel):
    country: Optional[str] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    class Config:
        from_attributes = True

class IOCBase(BaseModel):
    indicator_value: str
    indicator_type: str  # IP, DOMAIN, URL, HASH_MD5, HASH_SHA1, HASH_SHA256, EMAIL
    confidence_score: Optional[int] = 50
    severity: Optional[str] = "INFO"  # LOW, MEDIUM, HIGH, CRITICAL, INFO
    status: Optional[str] = "ACTIVE"

class IOCCreate(IOCBase):
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    source_feed_id: Optional[int] = None
    metadata: Optional[IOCMetadataBase] = None

class IOCResponse(IOCBase):
    id: int
    first_seen: datetime
    last_seen: datetime
    source_feed_id: Optional[int] = None
    normalized_indicator: str
    search_text: str
    created_at: datetime
    metadata: Optional[IOCMetadataBase] = None

    class Config:
        from_attributes = True
        
class IOCFingerprintResponse(BaseModel):
    id: int
    ioc_id: int
    sha256_fingerprint: str
    created_at: datetime

    class Config:
        from_attributes = True
