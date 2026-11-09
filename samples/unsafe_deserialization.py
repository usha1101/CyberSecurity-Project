import base64
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

