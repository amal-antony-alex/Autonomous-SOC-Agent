from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime
from app.db import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)

    incident_number = Column(String(50), unique=True, index=True)

    title = Column(String(255))
    description = Column(Text)

    severity = Column(String(20), index=True)
    status = Column(String(30), index=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
        onupdate=lambda: datetime.now(timezone.utc).replace(tzinfo=None)
    )
