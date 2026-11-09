class AuthService:
    def __init__(self, db_connection):
        self.conn = db_connection

    def authenticate_user(self, username: str, password_hash: str):
        """
        VULNERABILITY: SQL Injection & Authentication Bypass (CWE-89).
        Untrusted user inputs propagate into a raw f-string SQL query, allowing
        an attacker to inject `' OR 1=1 --` to bypass credentials entirely.
        """
        cursor = self.conn.cursor()
        
        # Taint propagation: untrusted parameters directly interpolated into SQL
        query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password_hash}'"
        
        # SINK: Execution of unparameterized dynamic query
        cursor.execute(query)
        user = cursor.fetchone()
        return user

