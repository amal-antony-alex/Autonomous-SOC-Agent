from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON
from app.db import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)

    wazuh_alert_id = Column(String(100), unique=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    rule_id = Column(String(50), index=True)
    rule_level = Column(Integer)
    rule_description = Column(Text)

    agent_id = Column(String(50))
    agent_name = Column(String(100))

    source_ip = Column(String(45))
    destination_ip = Column(String(45))

    username = Column(String(100))

    full_log = Column(Text)
    decoder = Column(String(100))

    mitre_attack = Column(JSON)

    raw_json = Column(JSON)
