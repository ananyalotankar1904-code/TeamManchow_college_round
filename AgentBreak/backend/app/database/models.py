from sqlalchemy import String, JSON, ForeignKey, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func
from app.database.connection import Base
import datetime
from typing import Any, Optional

class AgentModel(Base):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String, index=True)
    description: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class ScanModel(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String, primary_key=True, index=True)
    agent_id: Mapped[str] = mapped_column(String, ForeignKey("agents.id"))
    status: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class TraceModel(Base):
    __tablename__ = "traces"
    id: Mapped[str] = mapped_column(String, primary_key=True, index=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"))
    test_id: Mapped[str] = mapped_column(String)
    events: Mapped[Any] = mapped_column(JSON)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class FindingModel(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String, primary_key=True, index=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"))
    test_id: Mapped[str] = mapped_column(String)
    category: Mapped[str] = mapped_column(String)
    execution_status: Mapped[str] = mapped_column(String)
    outcome: Mapped[str] = mapped_column(String)
    expected_behavior: Mapped[str] = mapped_column(String)
    observed_behavior: Mapped[str] = mapped_column(String)
    evidence: Mapped[str] = mapped_column(String)
    trace_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("traces.id"), nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
