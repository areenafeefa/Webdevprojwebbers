import sqlite3
from helpers import *
DATABASE = "database.db"   # <-- change this

def get_friends(conn, user_id):
    friends = conn.execute("""
        SELECT u.user_id, u.username, 
               COALESCE(p.display_name, u.username) as display_name
        FROM users u
        LEFT JOIN user_profiles p ON u.user_id = p.user_id
        WHERE u.user_id IN (
            SELECT requester_id FROM friends 
            WHERE addressee_id = ? AND status='accepted'
            UNION
            SELECT addressee_id FROM friends 
            WHERE requester_id = ? AND status='accepted'
        )
        ORDER BY display_name ASC
    """, (user_id, user_id)).fetchall()

    return [dict(f) for f in friends]


def test(user_id, community_id):
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    print("\n=== TESTING ===")
    print("User ID:", user_id)
    print("Community ID:", community_id)

    # 1️⃣ Get all friends
    all_friends = get_friends(conn, user_id)
    print("\nAll Friends:")
    print(all_friends)

    # 2️⃣ Get community member IDs
    rows = conn.execute(
        "SELECT user_id FROM community_members WHERE community_id = ?",
        (community_id,)
    ).fetchall()

    community_member_ids = [row["user_id"] for row in rows]
    print("\nCommunity Member IDs:")
    print(community_member_ids)

    # 3️⃣ Filter
    community_friends = [
        f for f in all_friends
        if f["user_id"] in community_member_ids
    ]

    print("\nCommunity Friends (INTERSECTION):")
    print(community_friends)

    conn.close()


# 🔹 CHANGE THESE TO REAL VALUES
test(user_id=1, community_id=1)
