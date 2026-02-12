import sqlite3

DATABASE = 'database.db'

def fix_table():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    print("Dropping old comment_likes table...")
    try:
        cursor.execute("DROP TABLE IF EXISTS comment_likes")
        print("Table dropped.")
    except Exception as e:
        print(f"Error dropping table: {e}")

    print("Creating new comment_likes table with correct schema...")
    try:
        cursor.execute("""
            CREATE TABLE comment_likes (
                like_id INTEGER PRIMARY KEY AUTOINCREMENT,
                comment_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(comment_id) REFERENCES comments(comment_id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                UNIQUE(comment_id, user_id)
            )
        """)
        print("Table created successfully.")
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Error creating table: {e}")
        
    conn.close()

if __name__ == "__main__":
    fix_table()
