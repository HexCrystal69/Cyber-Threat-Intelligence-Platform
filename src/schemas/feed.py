from pydantic import BaseModel, HttpUrl
from datetime import datetime
from typing import Optional

class FeedBase(BaseModel):
    name: str
    source_url: str
    provider: str
    feed_type: str  # CSV, JSON, TXT

class FeedCreate(FeedBase):
    enabled: Optional[bool] = True

class FeedUpdate(BaseModel):
    name: Optional[str] = None
    source_url: Optional[str] = None
    provider: Optional[str] = None
    feed_type: Optional[str] = None
    enabled: Optional[bool] = None

class FeedResponse(FeedBase):
    id: int
    enabled: bool
    success_count: int
    failure_count: int
    last_success_at: Optional[datetime] = None
    last_failure_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True

class FeedExecutionLogResponse(BaseModel):
    id: int
    feed_id: int
    job_id: str
    status: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float
    records_processed: int
    records_failed: int

    class Config:
        from_attributes = True
