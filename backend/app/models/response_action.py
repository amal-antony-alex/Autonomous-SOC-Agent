
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
)

from app.db import Base


def utc_now_naive():
    """Return UTC time compatible with PostgreSQL TIMESTAMP WITHOUT TIME ZONE."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id = Column(Integer, primary_key=True, index=True)

    incident_id = Column(
        Integer,
        ForeignKey("incidents.id"),
        index=True,
    )

    action_type = Column(String(100))
    target = Column(String(255))
    status = Column(String(50))

    # Approval audit
    approved_by = Column(String(100))
    approved_at = Column(DateTime)

    # Rejection audit
    rejected_by = Column(String(100))
    rejected_at = Column(DateTime)
    rejection_reason = Column(Text)

    # Execution audit
    executed_at = Column(DateTime)
    result = Column(Text)

    created_at = Column(DateTime, default=utc_now_naive)
