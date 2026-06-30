from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class JobResponse(BaseModel):
    id: str
    feed_id: Optional[int] = None
    status: str
    records_processed: int
    records_failed: int
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None

    class Config:
        from_attributes = True
