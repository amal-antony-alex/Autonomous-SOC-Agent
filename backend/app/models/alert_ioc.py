from sqlalchemy import Column, Integer, String, ForeignKey
from app.db import Base


class AlertIOC(Base):
    __tablename__ = "alert_iocs"

    id = Column(Integer, primary_key=True, index=True)

    alert_id = Column(
        Integer,
        ForeignKey("alerts.id"),
        index=True
    )

    ioc_type = Column(String(50))
    ioc_value = Column(String(255))
    confidence = Column(String(20))
