import os
import json
import hashlib
from datetime import datetime
from uuid import uuid4
from typing import List, Literal, Optional, Dict, Any

import httpx
from dotenv import load_dotenv

from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel

from sqlalchemy import create_engine, Column, String, DateTime, JSON, Text, Boolean, Integer, Float
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import SQLAlchemyError

load_dotenv()

# --- Database Configuration ---
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./guardrailos.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Database Models ---
class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow)
    agent_id = Column(String, nullable=False)
    action = Column(String, nullable=False)
    target_resource = Column(String, nullable=True)
    input_payload_hash = Column(String, nullable=False)
    llm_response_hash = Column(String, nullable=True)
    decision = Column(String, nullable=False)
    policy_id = Column(String, nullable=True)
    lobster_trap_score = Column(Float, nullable=True)
    hash_chain = Column(String, nullable=False)
    details = Column(JSON, nullable=True)

class AgentActionRequest(BaseModel):
    agent_id: str
    agent_name: str
    agent_capabilities: List[str]
    agent_risk_level: int
    action: str
    target_resource: Optional[str] = None
    payload: Dict[str, Any]

class PolicyEvaluationResult(BaseModel):
    allowed: bool
    reason: str
    policy_id: Optional[str] = None
    action_modified_payload: Optional[Dict[str, Any]] = None

class LobsterTrapResponse(BaseModel):
    success: bool
    blocked: bool = False
    score: Optional[float] = None
    reason: Optional[str] = None
    message: Optional[str] = None

class AgentActionResponse(BaseModel):
    status: Literal["approved", "denied", "blocked", "pending_approval"]
    message: str
    original_request: AgentActionRequest
    policy_result: PolicyEvaluationResult
    lobster_trap_result: Optional[LobsterTrapResponse] = None
    audit_event_id: str

class AuditLogEntry(BaseModel):
    id: str
    timestamp: datetime
    agent_id: str
    action: str
    target_resource: Optional[str]
    decision: str
    policy_id: Optional[str]
    lobster_trap_score: Optional[float]
    hash_chain: str
    details: Optional[Dict[str, Any]]

app = FastAPI(
    title="GuardrailOS Policy Engine",
    description="Multi-agent permission and audit trail layer for enterprise AI agents.",
    version="0.1.0",
)

@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

LOBSTER_TRAP_URL = os.getenv("LOBSTER_TRAP_URL", "http://localhost:8080")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

def calculate_hash(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

async def get_last_audit_hash(db) -> str:
    last_event = db.query(AuditEvent).order_by(AuditEvent.timestamp.desc()).first()
    return last_event.hash_chain if last_event else "initial_hash"

async def call_lobster_trap(prompt: str) -> LobsterTrapResponse:
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{LOBSTER_TRAP_URL}/scan",
                json={"prompt": prompt},
                timeout=5
            )
            response.raise_for_status()
            return LobsterTrapResponse.parse_obj(response.json())
    except Exception as e:
        return LobsterTrapResponse(success=False, blocked=False, reason=str(e))

async def evaluate_policy(agent_request: AgentActionRequest) -> PolicyEvaluationResult:
    if agent_request.action == "call_tool:payment_api" and agent_request.agent_risk_level > 3:
        return PolicyEvaluationResult(allowed=False, reason="Denied: High-risk agent cannot call payment API.", policy_id="RISK_PAYMENT_001")
    if agent_request.action == "call_tool:read_docs" and "read_docs" in agent_request.agent_capabilities:
        return PolicyEvaluationResult(allowed=True, reason="Allowed: Agent has read_docs capability.", policy_id="CAP_READ_001")
    return PolicyEvaluationResult(allowed=True, reason="Allowed by default policy.", policy_id="DEFAULT_ALLOW")

@app.post("/agent-action", response_model=AgentActionResponse)
async def handle_agent_action(request: AgentActionRequest, db: Depends(get_db)):
    policy_result = await evaluate_policy(request)
    lobster_trap_result = None
    action_decision = "allow"
    action_status = "approved"
    message = "Action approved."
    llm_response_content = None

    if not policy_result.allowed:
        action_decision = "deny_policy"
        action_status = "denied"
        message = policy_result.reason
    else:
        prompt_to_scan = request.payload.get("llm_prompt") or json.dumps(request.payload)
        lobster_trap_result = await call_lobster_trap(prompt_to_scan)
        if lobster_trap_result.blocked:
            action_decision = "blocked_lobstertrap"
            action_status = "blocked"
            message = f"Blocked by Lobster Trap: {lobster_trap_result.reason}"
            policy_result.allowed = False

    if policy_result.allowed:
        llm_response_content = f"Simulated success for {request.action}."

    audit_payload = {
        "agent_id": request.agent_id,
        "action": request.action,
        "target_resource": request.target_resource,
        "input_payload_hash": calculate_hash(json.dumps(request.payload, sort_keys=True)),
        "llm_response_hash": calculate_hash(llm_response_content) if llm_response_content else None,
        "decision": action_decision,
        "policy_id": policy_result.policy_id,
        "lobster_trap_score": lobster_trap_result.score if lobster_trap_result else None,
        "details": {"policy_reason": policy_result.reason}
    }
    last_hash = await get_last_audit_hash(db)
    audit_payload["hash_chain"] = calculate_hash(last_hash + json.dumps(audit_payload, sort_keys=True))
    new_audit_event = AuditEvent(**audit_payload)
    db.add(new_audit_event)
    db.commit()
    db.refresh(new_audit_event)

    return AgentActionResponse(
        status=action_status,
        message=message,
        original_request=request,
        policy_result=policy_result,
        lobster_trap_result=lobster_trap_result,
        audit_event_id=new_audit_event.id
    )

@app.get("/audit-logs", response_model=List[AuditLogEntry])
async def get_audit_logs(db: Depends(get_db)):
    logs = db.query(AuditEvent).order_by(AuditEvent.timestamp.desc()).limit(100).all()
    return logs
