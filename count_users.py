import sqlite3

def count_users():
    try:
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        users = cursor.execute("SELECT username FROM users").fetchall()
        print(f"Total Users: {len(users)}")
        for u in users:
            print(f"- {u['username']}")
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    count_users()
