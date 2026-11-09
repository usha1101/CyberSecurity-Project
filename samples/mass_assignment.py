class UserProfile:
    def __init__(self, username: str, email: str):
        self.username = username
        self.email = email
        self.is_admin = False
        self.role = "member"

def update_user_profile(user: UserProfile, payload_dict: dict):
    """
    VULNERABILITY: Object State Pollution / Mass-Assignment (CWE-915).
    Iterates through caller-provided dictionary keys without an attribute whitelist,
    allowing an attacker to tamper with `is_admin` or `role`.
    """
    for key, value in payload_dict.items():
        # SINK: Unvalidated attribute mutation
        setattr(user, key, value)
    return user

