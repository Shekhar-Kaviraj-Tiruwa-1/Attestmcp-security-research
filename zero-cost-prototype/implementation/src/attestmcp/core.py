"""
FILE 1: src/attestmcp/core.py
=============================
WHAT: The core AttestMCP security layer implementation
WHY: This provides the actual security mechanisms that protect against attacks

This implements all 5 security features from the paper:
1. Capability Certificates - Cryptographic proof of server permissions
2. Message Authentication - HMAC-SHA256 signatures
3. Origin Tagging - Track true message source
4. Replay Protection - Nonce + timestamp validation  
5. Cross-Server Isolation - Block unauthorized server-to-server access
"""

import hashlib
import hmac
import json
import time
import uuid
import secrets
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Set, Any, Tuple
from enum import Enum
from datetime import datetime


# =============================================================================
# ENUMS - Define the types of things in our system
# =============================================================================

class Capability(Enum):
    """
    What a server is allowed to do.
    
    Think of these like permissions on your phone:
    - RESOURCES_READ = Can read files (like photo access)
    - RESOURCES_WRITE = Can save files
    - TOOLS_EXECUTE = Can run programs
    - SAMPLING = Can send prompts to LLM (DANGEROUS!)
    - PROMPTS = Can provide prompt templates
    """
    RESOURCES_READ = "resources:read"
    RESOURCES_WRITE = "resources:write"
    TOOLS_EXECUTE = "tools:execute"
    SAMPLING = "sampling"
    PROMPTS = "prompts"


class SecurityMode(Enum):
    """
    How strict should security be?
    
    PERMISSIVE = Allow everything, just warn (for testing)
    PROMPT = Ask user before allowing risky things
    STRICT = Block anything without proper certificate
    """
    PERMISSIVE = "permissive"
    PROMPT = "prompt"
    STRICT = "strict"


class ThreatType(Enum):
    """Types of attacks we can detect"""
    CAPABILITY_VIOLATION = "capability_violation"
    ORIGIN_SPOOFING = "origin_spoofing"
    CROSS_SERVER_ATTACK = "cross_server_attack"
    REPLAY_ATTACK = "replay_attack"
    INVALID_SIGNATURE = "invalid_signature"
    EXPIRED_CERTIFICATE = "expired_certificate"


# =============================================================================
# DATA STRUCTURES - Templates for our data
# =============================================================================

@dataclass
class CapabilityCertificate:
    """
    A digital certificate proving what a server can do.
    
    Like a driver's license:
    - server_id = Your name
    - capabilities = What you're licensed to do (drive car, motorcycle, etc.)
    - issued_by = Who issued it (the DMV / Certificate Authority)
    - signature = The official stamp that proves it's real
    """
    server_id: str
    capabilities: List[Capability]
    issued_by: str
    issued_at: float  # Unix timestamp
    expires_at: float
    public_key: str
    signature: str = ""
    
    def is_expired(self) -> bool:
        """Check if certificate has expired"""
        return time.time() > self.expires_at
    
    def has_capability(self, cap: Capability) -> bool:
        """Check if this certificate grants a specific capability"""
        return cap in self.capabilities
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "server_id": self.server_id,
            "capabilities": [c.value for c in self.capabilities],
            "issued_by": self.issued_by,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "public_key": self.public_key,
            "signature": self.signature
        }


@dataclass
class AuthenticatedMessage:
    """
    A message with security information attached.
    
    Original MCP message:
        {"method": "read_file", "params": {"path": "/data"}}
    
    AttestMCP message:
        {"method": "read_file", "params": {"path": "/data"},
         "mcpsec": {"origin": "file-server", "timestamp": 123456,
                    "nonce": "abc123", "hmac": "xyz789"}}
    
    The mcpsec part proves:
    - WHO sent it (origin)
    - WHEN it was sent (timestamp)
    - It's UNIQUE (nonce - prevents replay)
    - It's UNMODIFIED (hmac signature)
    """
    jsonrpc: str = "2.0"
    method: str = ""
    params: dict = field(default_factory=dict)
    id: Optional[str] = None
    
    # Security fields
    origin: str = ""
    timestamp: float = 0.0
    nonce: str = ""
    hmac_signature: str = ""
    
    def get_signing_payload(self) -> str:
        """
        Create the string that gets signed.
        Must be deterministic (same input = same output).
        """
        payload = {
            "method": self.method,
            "params": self.params,
            "origin": self.origin,
            "timestamp": self.timestamp,
            "nonce": self.nonce
        }
        # sort_keys ensures same order every time
        return json.dumps(payload, sort_keys=True, separators=(',', ':'))


@dataclass
class SecurityEvent:
    """Record of something security-related that happened"""
    event_type: ThreatType
    timestamp: float
    server_id: str
    details: str
    blocked: bool


# =============================================================================
# CERTIFICATE AUTHORITY - Issues and verifies certificates
# =============================================================================

class CertificateAuthority:
    """
    The trusted entity that issues certificates.
    
    Like a government passport office:
    - Only it can issue valid certificates
    - It can verify if a certificate is real
    - It can revoke certificates if compromised
    
    In production: Would be run by Anthropic, OpenAI, etc.
    In this prototype: We simulate it locally.
    """
    
    def __init__(self, ca_id: str, ca_secret: str):
        """
        Initialize the CA.
        
        Args:
            ca_id: Name of this CA (e.g., "anthropic-ca")
            ca_secret: Secret key for signing (NEVER expose this!)
        """
        self.ca_id = ca_id
        self.ca_secret = ca_secret
        self.issued_certs: Dict[str, CapabilityCertificate] = {}
        self.revoked_certs: Set[str] = set()
    
    def issue_certificate(
        self,
        server_id: str,
        capabilities: List[Capability],
        validity_days: int = 365
    ) -> CapabilityCertificate:
        """
        Issue a new certificate to a server.
        
        Args:
            server_id: Who is this for
            capabilities: What can they do
            validity_days: How long until it expires
        
        Returns:
            A signed certificate
        """
        now = time.time()
        
        cert = CapabilityCertificate(
            server_id=server_id,
            capabilities=capabilities,
            issued_by=self.ca_id,
            issued_at=now,
            expires_at=now + (validity_days * 24 * 60 * 60),
            public_key=self._generate_key(server_id)
        )
        
        # Sign the certificate
        cert.signature = self._sign(cert)
        
        # Track it
        self.issued_certs[server_id] = cert
        
        return cert
    
    def verify_certificate(self, cert: CapabilityCertificate) -> Tuple[bool, str]:
        """
        Verify a certificate is valid.
        
        Checks:
        1. Not revoked
        2. Not expired
        3. Issued by us
        4. Signature is valid (not tampered)
        
        Returns:
            (is_valid, reason_message)
        """
        # Check 1: Revoked?
        if cert.server_id in self.revoked_certs:
            return False, "Certificate has been revoked"
        
        # Check 2: Expired?
        if cert.is_expired():
            return False, "Certificate has expired"
        
        # Check 3: Issued by us?
        if cert.issued_by != self.ca_id:
            return False, f"Not issued by this CA (issued by {cert.issued_by})"
        
        # Check 4: Signature valid?
        expected = self._sign(cert)
        if not hmac.compare_digest(cert.signature, expected):
            return False, "Invalid signature - certificate may be tampered"
        
        return True, "Certificate is valid"
    
    def revoke_certificate(self, server_id: str):
        """Revoke a certificate (e.g., if server is compromised)"""
        self.revoked_certs.add(server_id)
    
    def _generate_key(self, server_id: str) -> str:
        """Generate a public key for a server"""
        data = f"{server_id}:{self.ca_secret}:key"
        return hashlib.sha256(data.encode()).hexdigest()[:32]
    
    def _sign(self, cert: CapabilityCertificate) -> str:
        """Sign a certificate with our secret"""
        data = f"{cert.server_id}:{','.join(c.value for c in cert.capabilities)}:{cert.issued_at}:{cert.expires_at}"
        return hmac.new(
            self.ca_secret.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()


# =============================================================================
# SECURE SERVER - MCP server with security features
# =============================================================================

class SecureMCPServer:
    """
    An MCP server that uses AttestMCP security.
    
    Every message it sends:
    1. Is tagged with its identity (origin)
    2. Has a timestamp (when sent)
    3. Has a unique nonce (prevents replay)
    4. Is signed with HMAC (proves authenticity)
    """
    
    def __init__(
        self,
        server_id: str,
        certificate: Optional[CapabilityCertificate] = None,
        shared_secret: Optional[str] = None
    ):
        self.server_id = server_id
        self.certificate = certificate
        # Secret used for signing messages
        self.shared_secret = shared_secret or secrets.token_hex(32)
    
    def create_message(
        self,
        method: str,
        params: dict
    ) -> AuthenticatedMessage:
        """
        Create a signed message.
        
        Args:
            method: What action (e.g., "resources/read")
            params: Parameters for the action
        
        Returns:
            A fully authenticated message
        """
        msg = AuthenticatedMessage(
            jsonrpc="2.0",
            method=method,
            params=params,
            id=str(uuid.uuid4()),
            origin=self.server_id,
            timestamp=time.time(),
            nonce=secrets.token_hex(16)  # Random unique value
        )
        
        # Sign it
        msg.hmac_signature = self._sign_message(msg)
        
        return msg
    
    def _sign_message(self, msg: AuthenticatedMessage) -> str:
        """Sign a message with our shared secret"""
        return hmac.new(
            self.shared_secret.encode(),
            msg.get_signing_payload().encode(),
            hashlib.sha256
        ).hexdigest()


# =============================================================================
# ATTESTMCP CLIENT - The security validation layer
# =============================================================================

class AttestMCPClient:
    """
    The main security layer that validates everything.
    
    This sits between the LLM and the MCP servers.
    Every message must pass through here and be validated.
    
    It checks:
    1. Is the server connected and known?
    2. Is the message signature valid?
    3. Is this a replay attack?
    4. Does the server have permission for this action?
    5. Is this a cross-server attack?
    """
    
    def __init__(
        self,
        ca: CertificateAuthority,
        mode: SecurityMode = SecurityMode.STRICT,
        nonce_window_seconds: int = 30
    ):
        self.ca = ca
        self.mode = mode
        self.nonce_window = nonce_window_seconds
        
        # Track connected servers
        self.servers: Dict[str, SecureMCPServer] = {}
        self.certificates: Dict[str, CapabilityCertificate] = {}
        self.shared_secrets: Dict[str, str] = {}
        
        # Replay protection: Track seen nonces
        self.seen_nonces: Dict[str, List[Tuple[str, float]]] = {}
        
        # Security logging
        self.security_events: List[SecurityEvent] = []
        
        # Statistics for your portfolio!
        self.stats = {
            "messages_processed": 0,
            "messages_allowed": 0,
            "messages_blocked": 0,
            "attacks_detected": 0,
            "capability_violations": 0,
            "replay_attacks": 0,
            "signature_failures": 0,
            "cross_server_blocks": 0
        }
    
    def connect_server(
        self,
        server: SecureMCPServer,
        user_approved: bool = False
    ) -> Tuple[bool, str]:
        """
        Connect a server after validating its certificate.
        
        Args:
            server: The server to connect
            user_approved: If True, allow legacy servers without cert
        
        Returns:
            (success, message)
        """
        cert = server.certificate
        
        # No certificate = legacy server
        if cert is None:
            if self.mode == SecurityMode.STRICT:
                self._log_event(ThreatType.CAPABILITY_VIOLATION, server.server_id,
                              "Legacy server rejected (strict mode)", blocked=True)
                return False, "Strict mode: Certificate required"
            
            if self.mode == SecurityMode.PROMPT and not user_approved:
                return False, f"User approval required for '{server.server_id}'"
            
            # Allow with warning
            self.servers[server.server_id] = server
            self.shared_secrets[server.server_id] = server.shared_secret
            self.seen_nonces[server.server_id] = []
            return True, f"⚠️ WARNING: '{server.server_id}' connected WITHOUT certificate"
        
        # Verify certificate
        valid, msg = self.ca.verify_certificate(cert)
        if not valid:
            self._log_event(ThreatType.INVALID_SIGNATURE, server.server_id,
                          f"Certificate invalid: {msg}", blocked=True)
            return False, f"Certificate rejected: {msg}"
        
        # All good - connect
        self.servers[server.server_id] = server
        self.certificates[server.server_id] = cert
        self.shared_secrets[server.server_id] = server.shared_secret
        self.seen_nonces[server.server_id] = []
        
        caps = [c.value for c in cert.capabilities]
        return True, f"✓ '{server.server_id}' connected with capabilities: {caps}"
    
    def validate_message(
        self,
        msg: AuthenticatedMessage,
        target_server: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Validate an incoming message.
        
        This is the CORE of AttestMCP!
        
        Args:
            msg: The message to validate
            target_server: If set, check for cross-server attack
        
        Returns:
            (is_valid, reason)
        """
        self.stats["messages_processed"] += 1
        origin = msg.origin
        
        # === CHECK 1: Known server? ===
        if origin not in self.servers:
            self._log_event(ThreatType.ORIGIN_SPOOFING, origin,
                          "Message from unknown server", blocked=True)
            self.stats["messages_blocked"] += 1
            return False, "Unknown server"
        
        # === CHECK 2: Valid signature? ===
        expected_sig = hmac.new(
            self.shared_secrets[origin].encode(),
            msg.get_signing_payload().encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(msg.hmac_signature, expected_sig):
            self._log_event(ThreatType.INVALID_SIGNATURE, origin,
                          "Signature mismatch - message tampered!", blocked=True)
            self.stats["messages_blocked"] += 1
            self.stats["signature_failures"] += 1
            self.stats["attacks_detected"] += 1
            return False, "Invalid signature"
        
        # === CHECK 3: Replay attack? ===
        if not self._check_nonce(origin, msg.nonce, msg.timestamp):
            self._log_event(ThreatType.REPLAY_ATTACK, origin,
                          "Duplicate nonce - replay attack!", blocked=True)
            self.stats["messages_blocked"] += 1
            self.stats["replay_attacks"] += 1
            self.stats["attacks_detected"] += 1
            return False, "Replay attack detected"
        
        # === CHECK 4: Has capability? ===
        if origin in self.certificates:
            if not self._check_capability(origin, msg.method):
                self._log_event(ThreatType.CAPABILITY_VIOLATION, origin,
                              f"Unauthorized method: {msg.method}", blocked=True)
                self.stats["messages_blocked"] += 1
                self.stats["capability_violations"] += 1
                self.stats["attacks_detected"] += 1
                return False, f"Capability violation: {msg.method}"
        
        # === CHECK 5: Cross-server attack? ===
        if target_server and target_server != origin:
            self._log_event(ThreatType.CROSS_SERVER_ATTACK, origin,
                          f"Cross-server access to {target_server}", blocked=True)
            self.stats["messages_blocked"] += 1
            self.stats["cross_server_blocks"] += 1
            self.stats["attacks_detected"] += 1
            return False, f"Cross-server access blocked (needs approval)"
        
        # All checks passed!
        self.stats["messages_allowed"] += 1
        return True, "Message validated"
    
    def _check_nonce(self, server_id: str, nonce: str, timestamp: float) -> bool:
        """Check if nonce is fresh (not a replay)"""
        now = time.time()
        
        # Timestamp too old?
        if abs(now - timestamp) > self.nonce_window:
            return False
        
        # Get existing nonces, clean old ones
        nonces = self.seen_nonces.get(server_id, [])
        cutoff = now - self.nonce_window
        nonces = [(n, t) for n, t in nonces if t > cutoff]
        
        # Already seen this nonce?
        if any(n == nonce for n, _ in nonces):
            return False
        
        # Add new nonce
        nonces.append((nonce, timestamp))
        self.seen_nonces[server_id] = nonces
        return True
    
    def _check_capability(self, server_id: str, method: str) -> bool:
        """Check if server can perform this method"""
        cert = self.certificates.get(server_id)
        if not cert:
            return self.mode != SecurityMode.STRICT
        
        # Map methods to required capabilities
        method_to_cap = {
            "resources/read": Capability.RESOURCES_READ,
            "resources/write": Capability.RESOURCES_WRITE,
            "tools/call": Capability.TOOLS_EXECUTE,
            "sampling/createMessage": Capability.SAMPLING,
        }
        
        required = method_to_cap.get(method)
        if required is None:
            return True  # Unknown method, allow
        
        return cert.has_capability(required)
    
    def _log_event(self, event_type: ThreatType, server_id: str, 
                   details: str, blocked: bool):
        """Log a security event"""
        self.security_events.append(SecurityEvent(
            event_type=event_type,
            timestamp=time.time(),
            server_id=server_id,
            details=details,
            blocked=blocked
        ))
    
    def get_statistics(self) -> dict:
        """Get statistics for your portfolio!"""
        total = self.stats["messages_processed"]
        return {
            **self.stats,
            "block_rate": self.stats["messages_blocked"] / total if total > 0 else 0,
            "attack_detection_rate": self.stats["attacks_detected"] / total if total > 0 else 0,
        }
    
    def get_security_report(self) -> dict:
        """Generate a full security report"""
        return {
            "timestamp": datetime.now().isoformat(),
            "mode": self.mode.value,
            "servers_connected": len(self.servers),
            "servers_with_certificates": len(self.certificates),
            "statistics": self.get_statistics(),
            "recent_events": [
                {
                    "type": e.event_type.value,
                    "server": e.server_id,
                    "details": e.details,
                    "blocked": e.blocked,
                    "time": datetime.fromtimestamp(e.timestamp).isoformat()
                }
                for e in self.security_events[-20:]
            ]
        }
