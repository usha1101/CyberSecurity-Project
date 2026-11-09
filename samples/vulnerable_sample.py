import time
import sqlite3

class BankVault:
    def __init__(self, db_conn):
        self.conn = db_conn
        self.balances = {"alice": 1000.0, "bob": 500.0}

    def transfer_funds(self, source_user: str, target_user: str, amount: float):
        """
        VULNERABILITY: Time-of-Check to Time-of-Use (TOCTOU) Concurrency Race Condition (CWE-367)
        and Dynamic SQL Injection (CWE-89).
        The balance check is performed without acquiring a thread lock or database transaction row lock.
        Additionally, the transaction record is inserted using raw dynamic string interpolation.
        """
        current_balance = self.balances.get(source_user, 0.0)

        # 1. State check without atomic lock
        if current_balance >= amount:
            # Simulated network latency/race window
            time.sleep(0.05)

            # 2. State mutation
            self.balances[source_user] -= amount
            self.balances[target_user] = self.balances.get(target_user, 0.0) + amount

            # 3. Dynamic SQL Injection Sink
            cursor = self.conn.cursor()
            query = f"INSERT INTO audit_logs (src, dst, amt) VALUES ('{source_user}', '{target_user}', {amount})"
            cursor.execute(query)
            return True
        return False

