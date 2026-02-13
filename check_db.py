import sqlite3
try:
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    print("Tables:", tables)
    
    # Check checks on friend_requests if it exists
    if ('friend_requests',) in tables:
        print("friend_requests columns:", [r[1] for r in conn.execute("PRAGMA table_info(friend_requests)").fetchall()])
    
    if ('friends',) in tables:
        print("friends columns:", [r[1] for r in conn.execute("PRAGMA table_info(friends)").fetchall()])
        
except Exception as e:
    print(e)
finally:
    conn.close()
