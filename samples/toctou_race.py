import time

# Simulation of in-memory banking balances
accounts = {
    "alice": 100.0,
    "bob": 50.0
}

def withdraw_balance(user_id: str, amount: float) -> bool:
    """
    VULNERABILITY: Time-of-Check to Time-of-Use (TOCTOU) Concurrency Race Condition.
    State invariant (balance >= amount) is checked without holding a thread synchronization
    lock or database row lock (SELECT FOR UPDATE).
    """
    if accounts.get(user_id, 0) >= amount:
        # Artificial race window: I/O latency or network delays
        time.sleep(0.05)
        accounts[user_id] -= amount
        return True
    return False

