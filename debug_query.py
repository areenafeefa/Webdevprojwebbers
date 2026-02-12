import sqlite3

def debug_query():
    current_username = 'test_search'
    
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    
    # Get ID
    curr = conn.execute("SELECT user_id FROM users WHERE username = ?", (current_username,)).fetchone()
    if not curr:
        print(f"User {current_username} not found in DB!")
        return
        
    current_uid = curr['user_id']
    print(f"Debug: User {current_username} ID = {current_uid}")
    
    # Run the exact query from main.py (Empty Query)
    print("\n--- Testing Empty Query (Suggestions) ---")
    query = """
            SELECT u.username, COALESCE(up.display_name, u.username) as display_name,
                   (SELECT status FROM friends f WHERE (f.requester_id = ? AND f.addressee_id = u.user_id) OR (f.requester_id = u.user_id AND f.addressee_id = ?) ) as friend_status,
                   (SELECT requester_id FROM friends f WHERE (f.requester_id = ? AND f.addressee_id = u.user_id) OR (f.requester_id = u.user_id AND f.addressee_id = ?) ) as last_requester_id
            FROM users u
            LEFT JOIN user_profiles up ON u.user_id = up.user_id
            WHERE u.username != ?
            ORDER BY RANDOM()
            LIMIT 10
    """
    params = (current_uid, current_uid, current_uid, current_uid, current_username)
    
    cursor = conn.execute(query, params)
    rows = cursor.fetchall()
    print(f"Returned {len(rows)} rows.")
    for r in rows:
        print(dict(r))

    # Run specific query
    print("\n--- Testing Specific Query '1ucky' ---")
    q_str = '1ucky'
    query2 = """
            SELECT u.username, COALESCE(up.display_name, u.username) as display_name,
                   (SELECT status FROM friends f WHERE (f.requester_id = ? AND f.addressee_id = u.user_id) OR (f.requester_id = u.user_id AND f.addressee_id = ?) ) as friend_status,
                   (SELECT requester_id FROM friends f WHERE (f.requester_id = ? AND f.addressee_id = u.user_id) OR (f.requester_id = u.user_id AND f.addressee_id = ?) ) as last_requester_id
            FROM users u
            LEFT JOIN user_profiles up ON u.user_id = up.user_id
            WHERE (u.username LIKE ? OR COALESCE(up.display_name, u.username) LIKE ?)
            AND u.username != ?
            LIMIT 10
        """
    params2 = (current_uid, current_uid, current_uid, current_uid, f'%{q_str}%', f'%{q_str}%', current_username)
    cursor = conn.execute(query2, params2)
    rows = cursor.fetchall()
    print(f"Returned {len(rows)} rows.")
    for r in rows:
        print(dict(r))

if __name__ == "__main__":
    debug_query()
