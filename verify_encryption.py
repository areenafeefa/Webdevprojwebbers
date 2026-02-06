import sqlite3
import json

def check_messages():
    try:
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        # Check messages table
        print("--- Checking 'messages' table ---\n")
        cursor = conn.execute("SELECT * FROM messages ORDER BY created_at DESC LIMIT 5")
        rows = cursor.fetchall()
        
        if not rows:
            print("No messages found.")
        
        for row in rows:
            print(f"ID: {row['message_id']}, Sender: {row['sender_username']}, Recipient: {row['recipient_username']}")
            print(f"Is Encrypted: {row['is_encrypted']}")
            content = row['content']
            print(f"Content (Raw): {content}")
            
            # Try parsing JSON if encrypted
            if row['is_encrypted']:
                try:
                    data = json.loads(content)
                    print("Status: VALID E2EE JSON STRUCTURE")
                    print(f"  - Key (Encrypted): {data.get('key')[:20]}...")
                    print(f"  - Data (Encrypted): {data.get('data')[:20]}...")
                    print(f"  - IV: {data.get('iv')}")
                except json.JSONDecodeError:
                    print("Status: INVALID JSON (Corruption or Plaintext?)")
            else:
                 print("Status: PLAINTEXT")
            print("-" * 40)
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_messages()
