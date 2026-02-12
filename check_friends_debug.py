from main import app # Import the app to get the context
import sqlite3
from helpers import get_friends, get_db

def check_friends():
    with app.app_context(): # CRITICAL: Push context for g.db access
        conn = get_db()
        
        print("--- Users ---")
        users = conn.execute("SELECT user_id, username FROM users").fetchall()
        for u in users:
            print(f"ID: {u['user_id']}, Username: {u['username']}")
        
        print("\n--- Friendships (All) ---")
        friends = conn.execute("SELECT * FROM friends").fetchall()
        if not friends:
            print("No friends rows found in DB.")
        for f in friends:
            print(f"Requester: {f['requester_id']}, Addressee: {f['addressee_id']}, Status: {f['status']}")

        print("\n--- Testing get_friends() helper ---")
        for u in users:
            f_list = get_friends(u['user_id'])
            friend_names = [f['username'] for f in f_list]
            print(f"User {u['username']} (ID {u['user_id']}) has {len(f_list)} friends: {friend_names}")

if __name__ == "__main__":
    check_friends()
