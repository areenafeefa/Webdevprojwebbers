import sqlite3

DATABASE = 'database.db'

def inspect_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Get info about the comment_likes table
    print("Inspecting comment_likes table...")
    cursor.execute("PRAGMA table_info(comment_likes)")
    columns = cursor.fetchall()
    
    for col in columns:
        print(col)
        
    conn.close()

if __name__ == "__main__":
    inspect_db()
