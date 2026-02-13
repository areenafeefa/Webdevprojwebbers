from main import app
from helpers import get_db

def check_requests():
    with app.app_context():
        conn = get_db()
        print("--- FRIENDSHIPS ---")
        rows = conn.execute("""
            SELECT f.status, u1.username as req, u2.username as addr
            FROM friends f
            JOIN users u1 ON f.requester_id = u1.user_id
            JOIN users u2 ON f.addressee_id = u2.user_id
        """).fetchall()
        
        if not rows:
            print("No rows in friends table.")
            return

        for r in rows:
            print(f"[{r['status'].upper()}] {r['req']} <-> {r['addr']}")

if __name__ == "__main__":
    check_requests()
