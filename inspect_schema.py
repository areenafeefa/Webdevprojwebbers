import sqlite3

DATABASE = 'database.db'

def inspect_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Get info about the comments table
    cursor.execute("PRAGMA table_info(comments)")
    columns = cursor.fetchall()
    
    print("Columns in comments table:")
    for col in columns:
        print(col)
        
    conn.close()

if __name__ == "__main__":
    inspect_db()
