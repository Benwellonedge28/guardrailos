
import os
import json
import hashlib
from datetime import datetime, timedelta
from uuid import uuid4
from typing import List, Literal, Optional, Dict, Any

import httpx
from dotenv import load_dotenv

from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel

from sqlalchemy import create_engine, Column, String, DateTime, JSON, Text, Boolean, Integer, Float
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import SQLAlchemyError

# Presidio for PII Redaction
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine


load_dotenv()

# --- Presidio Initialization ---
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

def redact_pii(text: str) -> str:
    """
    Redacts Personally Identifiable Information (PII) from the given text
    using Presidio.
    """
    # For production, you might want to configure specific entities and operators
    # or handle different data types (e.g., JSON vs plain text).
    results = analyzer.analyze(text=text, language='en')
    # Use 'replace' operator to mask detected entities
    anonymized_text = anonymizer.anonymize(
        text=text,
        analyzer_results=results,
        operators={
            "DEFAULT": {"operator_name": "replace", "masking_char": "#", "chars_to_mask": 5},
            "EMAIL_ADDRESS": {"operator_name": "replace", "new_value": "[EMAIL]"},
            "PHONE_NUMBER": {"operator_name": "replace", "new_value": "[PHONE]"},
            "CREDIT_CARD": {"operator_name": "replace", "new_value": "[CREDIT_CARD]"},
            "SSN": {"operator_name": "replace", "new_value": "[SSN]"},
            "LOCATION": {"operator_name": "replace", "new_value": "[LOCATION]"}
        }
    )
    return anonymized_text.text


# --- Database Configuration ---
# The docker-compose.yml sets up PostgreSQL.
# If you run locally without Docker, you can use SQLite: "sqlite:///./guardrailos.db"
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./guardrailos.db")

# Only check_same_thread for SQLite
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
    target_resource = Column(String, nullable=True) # e.g., "payment_api"
    input_payload_hash = Column(String, nullable=False) # Hash of the redacted payload
    llm_response_hash = Column(String, nullable=True) # Hash of the redacted LLM response
    decision = Column(String, nullable=False) # "allow", "deny_policy", "blocked_lobstertrap", "pending_approval_policy", "lobstertrap_operational_error"
    policy_id = Column(String, nullable=True)
    lobster_trap_score = Column(Float, nullable=True)
    hash_chain = Column(String, nullable=False) # Hash of previous event for tamper evidence
    details = Column(JSON, nullable=True) # Any extra details, e.g., policy conditions met/failed

    def __repr__(self):
        return f"<AuditEvent(id='{self.id}', agent='{self.agent_id}', action='{self.action}', decision='{self.decision}')>"

# --- New Database Model for Approval Requests ---
class ApprovalRequest(Base):
    __tablename__ = "approval_requests"
    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow)
    agent_id = Column(String, nullable=False)
    action_type = Column(String, nullable=False) # e.g., "call_tool:payment_api"
    payload_hash = Column(String, nullable=False) # Hash of the original redacted payload
    status = Column(String, default="pending") # pending, approved, denied
    approver_id = Column(String, nullable=True)
    approval_reason = Column(String, nullable=True)
    expires_at = Column(DateTime, nullable=True) # Optional expiry for approval
    audit_event_id = Column(String, nullable=True) # Link to the AuditEvent that triggered it

    def __repr__(self):
        return f"<ApprovalRequest(id='{self.id}', agent='{self.agent_id}', status='{self.status}')>"


# --- Pydantic Models ---
class AgentActionRequest(BaseModel):
    agent_id: str
    agent_name: str
    agent_capabilities: List[str] # e.g., ["read_docs", "call_api_sales"]
    agent_risk_level: int # 1-5 (1=low, 5=high)
    action: str # e.g., "call_tool:payment_api", "query_llm", "call_tool:access_phi_data"
    target_resource: Optional[str] = None # e.g., "payment_api", "customer_db", "LLM"
    payload: Dict[str, Any] # The actual data payload for the action, includes context like "amount", "origin_country", "llm_prompt"

class PolicyEvaluationResult(BaseModel):
    allowed: bool
    reason: str
    policy_id: Optional[str] = None
    action_modified_payload: Optional[Dict[str, Any]] = None # If policy modifies payload

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
    approval_request_id: Optional[str] = None # Added field

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

class ApprovalRequestResponse(BaseModel):
    id: str
    timestamp: datetime
    agent_id: str
    action_type: str
    payload_hash: str
    status: str
    approver_id: Optional[str]
    approval_reason: Optional[str]
    expires_at: Optional[datetime]
    audit_event_id: Optional[str]

class ApproveRequest(BaseModel):
    approver_id: str
    approval_reason: Optional[str] = None
    status: Literal["approved", "denied"] = "approved"


# --- FastAPI App ---
app = FastAPI(
    title="GuardrailOS Policy Engine",
    description="Multi-agent permission and audit trail layer for enterprise AI agents.",
    version="0.1.0",
)

# Create database tables (this will run on startup if the DB is empty)
@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Configuration ---
LOBSTER_TRAP_URL = os.getenv("LOBSTER_TRAP_URL", "http://localhost:8080")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY") # Example for LLM calls

# --- Helper Functions ---
def calculate_hash(data: str) -> str:
    """Calculates SHA256 hash of a string."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

async def get_last_audit_hash(db) -> str:
    """Retrieves the hash_chain of the most recent audit event for tamper-proofing."""
    last_event = db.query(AuditEvent).order_by(AuditEvent.timestamp.desc()).first()
    return last_event.hash_chain if last_event else "initial_hash"

async def call_lobster_trap(prompt: str) -> LobsterTrapResponse:
    """Calls the Lobster Trap service to scan a prompt for injections/PII."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{LOBSTER_TRAP_URL}/scan", # Assuming a /scan endpoint exists on Lobster Trap
                json={"prompt": prompt},
                timeout=5
            )
            response.raise_for_status() # Raise an exception for 4xx or 5xx responses
            return LobsterTrapResponse.parse_obj(response.json())
    except httpx.HTTPStatusError as e:
        print(f"Lobster Trap HTTP error: {e.response.status_code} - {e.response.text}")
        return LobsterTrapResponse(success=False, blocked=False, reason=f"HTTP error: {e.response.status_code}")
    except httpx.RequestError as e:
        print(f"Lobster Trap request error: {e}")
        return LobsterTrapResponse(success=False, blocked=False, reason=f"Request error: {e}")
    except Exception as e:
        print(f"Unexpected error calling Lobster Trap: {e}")
        return LobsterTrapResponse(success=False, blocked=False, reason=f"Unexpected error: {e}")

# --- Policy Engine (enhanced) ---
async def evaluate_policy(agent_request: AgentActionRequest) -> PolicyEvaluationResult:
    """
    Evaluates agent action against defined security and governance policies.
    Returns whether the action is allowed, denied, or requires approval.
    """
    current_time_utc = datetime.utcnow()
    
    # Policy 1: Deny payment_api if agent risk level is high (risk_level 4 or 5)
    if agent_request.action == "call_tool:payment_api" and agent_request.agent_risk_level >= 4:
        return PolicyEvaluationResult(allowed=False, reason="Denied: High-risk agent cannot call payment API.", policy_id="RISK_PAYMENT_001")

    # Policy 2: Allow read_docs for any agent with 'read_docs' capability
    if agent_request.action == "call_tool:read_docs" and "read_docs" in agent_request.agent_capabilities:
        return PolicyEvaluationResult(allowed=True, reason="Allowed: Agent has read_docs capability.", policy_id="CAP_READ_001")

    # Policy 3: High-value payment (>= $1000) requires manager approval
    # Assumes 'amount' is present in the action payload for payment_api calls
    if agent_request.action == "call_tool:payment_api" and agent_request.payload.get("amount", 0) >= 1000:
        return PolicyEvaluationResult(allowed=False, reason="Requires approval: High-value payment needs manager sign-off.", policy_id="HIGH_VALUE_PAYMENT_002")

    # Policy 4: Sensitive data access (PHI) requires specific capability
    if agent_request.action == "call_tool:access_phi_data" and "access_phi" not in agent_request.agent_capabilities:
        return PolicyEvaluationResult(allowed=False, reason="Denied: Agent lacks capability to access PHI data.", policy_id="PHI_ACCESS_003")

    # Policy 5: Time-based restriction (e.g., sensitive actions only within business hours 9 AM - 5 PM UTC)
    # This ensures consistency regardless of server's local time.
    if (
        agent_request.action.startswith("call_tool:sensitive_") or
        "financial" in agent_request.action or # Generic sensitive action
        agent_request.action == "call_tool:payment_api"
    ):
        if not (9 <= current_time_utc.hour < 17): # 9 AM to 5 PM UTC
            return PolicyEvaluationResult(allowed=False, reason="Denied: Sensitive action attempted outside allowed business hours (9 AM - 5 PM UTC).", policy_id="TIME_RESTRICTION_004")

    # Policy 6: Simulated geographical restriction for 'customer_data' access
    # This assumes 'origin_country' is passed in the agent_request.payload for contextual checks
    if agent_request.action == "call_tool:access_customer_data" and \
       agent_request.payload.get("origin_country") == "RestrictedLand": # Example restricted country
        return PolicyEvaluationResult(allowed=False, reason="Denied: Access to customer data from restricted geographical region.", policy_id="GEO_RESTRICTION_005")

    # Policy 7: Block any agent without 'certified' capability from production deployments
    if agent_request.action == "deploy_to_production" and "certified" not in agent_request.agent_capabilities:
        return PolicyEvaluationResult(allowed=False, reason="Denied: Only certified agents can deploy to production.", policy_id="PROD_DEPLOY_006")


    # Default allow if no specific deny or approval-requiring policy is hit
    return PolicyEvaluationResult(allowed=True, reason="Allowed by default policy.", policy_id="DEFAULT_ALLOW")


# --- API Endpoints ---
@app.post("/agent-action", response_model=AgentActionResponse)
async def handle_agent_action(request: AgentActionRequest, db: Depends(get_db)):
    # 1. PII Redaction for logging and hashing before policy evaluation
    redacted_payload_str = redact_pii(json.dumps(request.payload, sort_keys=True))
    input_payload_hash_val = calculate_hash(redacted_payload_str)

    policy_result = await evaluate_policy(request)
    lobster_trap_result: Optional[LobsterTrapResponse] = None
    action_decision: str = "allow"
    action_status: Literal["approved", "denied", "blocked", "pending_approval"] = "approved"
    message: str = "Action approved by Policy Engine."
    llm_response_content = None # This would be populated by the actual LLM/tool call
    approval_request_id: Optional[str] = None


    # 2. Handle Policy Evaluation Outcome
    if not policy_result.allowed:
        if policy_result.policy_id == "HIGH_VALUE_PAYMENT_002": # This policy triggers approval flow
            action_decision = "pending_approval_policy"
            action_status = "pending_approval"
            message = policy_result.reason
            # Skip Lobster Trap and LLM/Tool call for pending approvals
        else: # Any other denial policy
            action_decision = "deny_policy"
            action_status = "denied"
            message = policy_result.reason
            # Skip Lobster Trap and LLM/Tool call for denied actions

    # 3. Lobster Trap Integration (only if allowed by policy AND relevant action, and not pending approval)
    is_llm_action = (
        request.action == "query_llm" or
        "llm_prompt" in request.payload or
        "generate_response" in request.action or
        "ai_prompt" in request.payload # General key for AI prompts
    )

    if policy_result.allowed and action_status == "approved" and is_llm_action:
        # Construct the prompt to send to Lobster Trap for scanning.
        # Prioritize 'llm_prompt' if available, otherwise use the redacted payload.
        prompt_to_scan = request.payload.get("llm_prompt") or redacted_payload_str

        lobster_trap_result = await call_lobster_trap(prompt_to_scan)

        if not lobster_trap_result.success:
            action_decision = "lobstertrap_operational_error"
            action_status = "blocked"
            message = f"Operational error with Lobster Trap: {lobster_trap_result.reason}. Action blocked."
            policy_result.allowed = False
        elif lobster_trap_result.blocked:
            action_decision = "blocked_lobstertrap"
            action_status = "blocked"
            message = f"Action blocked by Lobster Trap: {lobster_trap_result.reason}"
            policy_result.allowed = False

    # 4. Simulate LLM / Tool call ONLY if explicitly allowed by ALL previous checks
    if policy_result.allowed and action_status == "approved":
        # This is where the actual LLM call or tool execution would happen.
        # For this minimal example, we just simulate a response.
        # In a real system, `httpx` would be used to call the LLM API (e.g., OpenAI, Anthropic).
        llm_response_raw = f"Simulated success for action '{request.action}' by agent '{request.agent_name}'. Policy ID: {policy_result.policy_id}. Processed payload: {redacted_payload_str}"
        llm_response_content = redact_pii(llm_response_raw) # Redact PII from simulated LLM response
        message = f"Action '{request.action}' successfully processed."
    elif action_status != "pending_approval": # If denied/blocked and not pending approval
        llm_response_content = "Action blocked/denied, no LLM/tool call performed."
    # If action_status is "pending_approval", llm_response_content remains None as no LLM call happened

    # 5. Audit Logging
    audit_payload = {
        "agent_id": request.agent_id,
        "action": request.action,
        "target_resource": request.target_resource,
        "input_payload_hash": input_payload_hash_val, # Use hash of redacted payload
        "llm_response_hash": calculate_hash(llm_response_content) if llm_response_content else None, # Hash of redacted LLM response
        "decision": action_decision,
        "policy_id": policy_result.policy_id,
        "lobster_trap_score": lobster_trap_result.score if lobster_trap_result else None,
        "details": {
            "policy_reason": policy_result.reason,
            "lobster_trap_message": lobster_trap_result.message if lobster_trap_result and not lobster_trap_result.success else (lobster_trap_result.reason if lobster_trap_result else None),
            "original_message": message,
            "agent_risk_level": request.agent_risk_level,
            "agent_capabilities": request.agent_capabilities
            # In a real system, you might include obfuscated parts of the original payload here for context
        }
    }

    last_hash = await get_last_audit_hash(db)
    audit_payload["hash_chain"] = calculate_hash(last_hash + json.dumps(audit_payload, sort_keys=True))

    try:
        new_audit_event = AuditEvent(**audit_payload)
        db.add(new_audit_event)
        db.flush() # Ensure new_audit_event.id is populated before commit or linking

        # If action is pending approval, create an ApprovalRequest record
        if action_status == "pending_approval":
            new_approval_req = ApprovalRequest(
                agent_id=request.agent_id,
                action_type=request.action,
                payload_hash=input_payload_hash_val, # Link to the redacted payload hash
                status="pending",
                audit_event_id=new_audit_event.id,
                expires_at=datetime.utcnow() + timedelta(hours=24) # Example: approval request expires in 24 hours
            )
            db.add(new_approval_req)
            db.flush() # Populate new_approval_req.id
            approval_request_id = new_approval_req.id

        db.commit()
        db.refresh(new_audit_event)
        if approval_request_id:
            db.refresh(new_approval_req) # Refresh to get latest state including ID

    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to log audit/approval event: {e}")

    return AgentActionResponse(
        status=action_status,
        message=message,
        original_request=request,
        policy_result=policy_result,
        lobster_trap_result=lobster_trap_result,
        audit_event_id=new_audit_event.id,
        approval_request_id=approval_request_id
    )

@app.get("/audit-logs", response_model=List[AuditLogEntry])
async def get_audit_logs(db: Depends(get_db)):
    """Retrieves a list of recent audit log entries."""
    try:
        # Limit to 100 recent logs for practical display in a dashboard
        logs = db.query(AuditEvent).order_by(AuditEvent.timestamp.desc()).limit(100).all()
        return [AuditLogEntry(**log.__dict__) for log in logs]
    except SQLAlchemyError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Database error: {e}")

@app.get("/approvals", response_model=List[ApprovalRequestResponse])
async def get_approval_requests(db: Depends(get_db)):
    """Retrieves a list of pending and recently handled approval requests."""
    try:
        # Order by pending first, then by timestamp
        requests = db.query(ApprovalRequest).order_by(ApprovalRequest.status.asc(), ApprovalRequest.timestamp.desc()).all()
        return [ApprovalRequestResponse(**req.__dict__) for req in requests]
    except SQLAlchemyError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Database error: {e}")

@app.post("/approvals/{request_id}/approve", response_model=ApprovalRequestResponse)
async def approve_or_deny_request(request_id: str, approval_data: ApproveRequest, db: Depends(get_db)):
    """Allows an authorized approver to approve or deny a pending agent action."""
    approval_req = db.query(ApprovalRequest).filter(ApprovalRequest.id == request_id).first()
    if not approval_req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval request not found.")

    if approval_req.status != "pending":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Request already {approval_req.status}.")

    approval_req.status = approval_data.status
    approval_req.approver_id = approval_data.approver_id
    approval_req.approval_reason = approval_data.approval_reason
    db.commit()
    db.refresh(approval_req)

    # Log the approval/denial action itself to the audit trail
    audit_payload = {
        "agent_id": approval_data.approver_id, # The approver is acting here
        "action": f"handle_approval_request:{approval_req.status}",
        "target_resource": approval_req.id,
        "input_payload_hash": calculate_hash(json.dumps(approval_data.dict(), sort_keys=True)),
        "llm_response_hash": None, # No direct LLM response for an approval action
        "decision": approval_req.status, # The decision of the approver
        "policy_id": "APPROVAL_FLOW_001", # Policy ID for the approval flow itself
        "lobster_trap_score": None,
        "details": {
            "approved_or_denied_agent_id": approval_req.agent_id,
            "original_action_type": approval_req.action_type,
            "original_action_payload_hash": approval_req.payload_hash,
            "reason_from_approver": approval_data.approval_reason
        }
    }
    last_hash = await get_last_audit_hash(db)
    audit_payload["hash_chain"] = calculate_hash(last_hash + json.dumps(audit_payload, sort_keys=True))
    new_audit_event = AuditEvent(**audit_payload)
    db.add(new_audit_event)
    db.commit()
    db.refresh(new_audit_event)

    # In a full system, after approval, you might re-trigger the original agent action
    # or notify the originating agent. For this minimal example, we just update the status.

    return ApprovalRequestResponse(**approval_req.__dict__)
