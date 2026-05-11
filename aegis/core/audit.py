import time
import json
from typing import Dict, List, Any

class AuditEntry:
    def __init__(self, action: str, details: Dict[str, Any], initial_hash: str, result_hash: str):
        self.timestamp = time.time()
        self.action = action
        self.details = details
        self.initial_hash = initial_hash
        self.result_hash = result_hash

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "action": self.action,
            "details": self.details,
            "initial_hash": self.initial_hash,
            "result_hash": self.result_hash
        }

class AuditSystem:
    """
    Maintains a chain-of-custody and processing history.
    """
    def __init__(self, initial_source: str = "memory", initial_hash: str = ""):
        self.entries: List[AuditEntry] = []
        self.origin = initial_source
        self.origin_hash = initial_hash
        self.created_at = time.time()
        
    def log_operation(self, action: str, details: Dict[str, Any], initial_hash: str, result_hash: str):
        """Record a transformation or analysis operation."""
        entry = AuditEntry(action, details, initial_hash, result_hash)
        self.entries.append(entry)

    def get_history(self) -> List[Dict[str, Any]]:
        return [entry.to_dict() for entry in self.entries]

    def export_json(self) -> str:
        data = {
            "origin": self.origin,
            "origin_hash": self.origin_hash,
            "created_at": self.created_at,
            "history": self.get_history()
        }
        return json.dumps(data, indent=2)

    def copy(self) -> 'AuditSystem':
        """Create a deep copy of the audit system (for immutable operations)."""
        new_audit = AuditSystem(self.origin, self.origin_hash)
        new_audit.created_at = self.created_at
        new_audit.entries = self.entries.copy()
        return new_audit
