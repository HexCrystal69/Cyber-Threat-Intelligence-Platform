from sqlalchemy.orm import Session
from src.models.ioc import IOC
from src.models.dedup import DuplicateIOCGroup
import logging

logger = logging.getLogger(__name__)

class DeduplicationEngine:
    def __init__(self, db: Session):
        self.db = db

    def process_ioc(self, ioc: IOC) -> IOC:
        """
        Check if the IOC is a duplicate.
        If a duplicate is found, groups it under the canonical IOC and updates duplicate count.
        Returns the canonical IOC.
        """
        normalized_val = ioc.indicator_value.strip().lower()
        normalized_type = ioc.indicator_type.strip().upper()

        # Find if there is an existing canonical IOC (the first created IOC with the same value and type)
        canonical = self.db.query(IOC).filter(
            IOC.normalized_indicator == normalized_val,
            IOC.indicator_type == normalized_type,
            IOC.id != ioc.id
        ).order_by(IOC.created_at.asc()).first()

        if canonical:
            # Check if canonical already has a duplicate group
            group = self.db.query(DuplicateIOCGroup).filter(
                DuplicateIOCGroup.canonical_ioc_id == canonical.id
            ).first()

            if group:
                group.duplicate_count += 1
            else:
                group = DuplicateIOCGroup(
                    canonical_ioc_id=canonical.id,
                    duplicate_count=2  # canonical + this duplicate
                )
                self.db.add(group)
            
            self.db.commit()
            logger.info(f"Deduplicated IOC {ioc.id} under canonical IOC {canonical.id}")
            return canonical

        return ioc
