export interface CodeSample {
  id: string;
  name: string;
  category: string;
  cwe: string;
  filename: string;
  code: string;
  description: string;
}

export const SAMPLES: CodeSample[] = [
  {
    id: "toctou_race",
    name: "TOCTOU Concurrency Race Condition",
    category: "RACE_CONDITION_TOCTOU",
    cwe: "CWE-367",
    filename: "wallet_service.py",
    description: "Account balance verified before deduction without atomic database lock, allowing concurrent double-spend.",
    code: `import time

# Simulation of account wallet balances
accounts = {
    "alice": 1000.0,
    "bob": 500.0
}

def withdraw_balance(user_id: str, amount: float) -> bool:
    """
    VULNERABILITY: Time-of-Check to Time-of-Use (TOCTOU) Concurrency Race Condition (CWE-367).
    State invariant (balance >= amount) is checked without holding a thread synchronization
    lock or database row lock (SELECT FOR UPDATE).
    """
    if accounts.get(user_id, 0) >= amount:
        # Artificial race window: network latency or I/O delay
        time.sleep(0.05)
        accounts[user_id] -= amount
        return True
    return False
`,
  },
  {
    id: "sql_injection",
    name: "SQL Injection & Auth Bypass",
    category: "INJECTION",
    cwe: "CWE-89",
    filename: "auth_service.py",
    description: "Untrusted user credentials interpolated directly into a dynamic f-string query without parameter binding.",
    code: `class AuthService:
    def __init__(self, db_connection):
        self.conn = db_connection

    def authenticate_user(self, username: str, password_hash: str):
        """
        VULNERABILITY: SQL Injection & Authentication Bypass (CWE-89).
        Untrusted user inputs propagate into a raw f-string SQL query, allowing
        an attacker to inject "' OR 1=1 --" to bypass credentials entirely.
        """
        cursor = self.conn.cursor()
        
        # Taint propagation: untrusted parameters directly interpolated into SQL
        query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password_hash}'"
        
        # SINK: Execution of unparameterized dynamic query
        cursor.execute(query)
        user = cursor.fetchone()
        return user
`,
  },
  {
    id: "unsafe_deserialization",
    name: "Insecure Object Deserialization (RCE)",
    category: "TAINT_PROPAGATION",
    cwe: "CWE-502",
    filename: "session_manager.py",
    description: "Untrusted authentication token unpickled directly, leading to remote code execution (RCE) via __reduce__.",
    code: `import base64
import pickle

class SessionManager:
    def restore_session(self, raw_session_token: str):
        """
        VULNERABILITY: Insecure Deserialization via pickle.loads (CWE-502).
        Untrusted token string from HTTP cookie or header is unpickled directly,
        allowing arbitrary opcode execution (__reduce__) and remote code execution (RCE).
        """
        payload = base64.b64decode(raw_session_token)
        # SINK: Critical deserialization flaw
        session_data = pickle.loads(payload)
        return session_data
`,
  },
  {
    id: "mass_assignment",
    name: "Mass-Assignment / State Pollution",
    category: "MASS_ASSIGNMENT",
    cwe: "CWE-915",
    filename: "user_controller.py",
    description: "Iterating through user-provided dictionary keys without an attribute whitelist, allowing privilege escalation.",
    code: `class UserProfile:
    def __init__(self, username: str, email: str):
        self.username = username
        self.email = email
        self.is_admin = False
        self.role = "member"

def update_user_profile(user: UserProfile, payload_dict: dict):
    """
    VULNERABILITY: Object State Pollution / Mass-Assignment (CWE-915).
    Iterates through caller-provided dictionary keys without an attribute whitelist,
    allowing an attacker to tamper with 'is_admin' or 'role'.
    """
    for key, value in payload_dict.items():
        # SINK: Unvalidated attribute mutation
        setattr(user, key, value)
    return user
`,
  },
];
