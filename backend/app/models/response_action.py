from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from app.db import Base


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id = Column(Integer, primary_key=True, index=True)

    incident_id = Column(
        Integer,
        ForeignKey("incidents.id"),
        index=True
    )

    action_type = Column(String(100))
    target = Column(String(255))

    status = Column(String(50))

    approved_by = Column(String(100))
    approved_at = Column(DateTime)

    executed_at = Column(DateTime)
    result = Column(Text)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
