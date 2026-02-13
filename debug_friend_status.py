from main import app
from helpers import get_db

def dump_friends():
    with app.app_context():
        conn = get_db()
        print("--- ALL USERS ---")
        users = conn.execute("SELECT user_id, username FROM users").fetchall()
        for u in users:
            print(f"ID: {u['user_id']} | User: {u['username']}")

        print("\n--- FRIENDS TABLE RECOVERY ---")
        rows = conn.execute("SELECT * FROM friends").fetchall()
        if not rows:
            print(">> FRIENDS TABLE IS EMPTY <<")
        else:
            for r in rows:
                print(f"ID: {r['friendship_id']} | Req: {r['requester_id']} | Addr: {r['addressee_id']} | Status: {r['status']}")

if __name__ == "__main__":
    dump_friends()
