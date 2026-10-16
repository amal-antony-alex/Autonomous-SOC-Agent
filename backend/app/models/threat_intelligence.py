from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime
from app.db import Base


class ThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"

    id = Column(Integer, primary_key=True, index=True)

    ioc_type = Column(String(50), index=True)
    ioc_value = Column(String(255), index=True)

    source = Column(String(100))
    reputation = Column(String(50))
    details = Column(Text)

    first_seen = Column(DateTime)
    last_seen = Column(DateTime)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
