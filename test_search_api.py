import requests
import json

BASE_URL = "http://127.0.0.1:5001"

def test_search():
    session = requests.Session()
    
    # 1. Register/Login
    print("Logging in...")
    login_payload = {'username': 'test_search', 'password': 'password'}
    
    try:
        session.post(f"{BASE_URL}/register", data={
            'username': 'test_search', 'password': 'password', 
            'email': 'test@test.com', 'age': 25, 'phone': '12345678'
        })
    except:
        pass
    
    res = session.post(f"{BASE_URL}/login", data=login_payload)
    if "Login Successful" in res.text or res.history:
        print("Login OK")
    else:
        print("Login might have failed.")
    
    # Test 1: Empty Query
    print("\nTesting Search API (Empty Query)...")
    try:
        res = session.get(f"{BASE_URL}/api/search_users?q=")
        print(f"Status: {res.status_code}")
        if res.status_code == 200:
            data = res.json()
            print(f"Success! Found {len(data)} suggested users.")
            print(data)
        else:
            print(f"Failed: {res.text}")
    except Exception as e:
        print(f"Error: {e}")
            
    # Test 2: Specific Query
    print("\nTesting Search API (Specific Query '1ucky')...")
    try:
        res = session.get(f"{BASE_URL}/api/search_users?q=1ucky")
        print(f"Status: {res.status_code}")
        if res.status_code == 200:
            data = res.json()
            print(f"Success! Found {len(data)} matching users.")
            print(data)
        else:
            print(f"Failed: {res.text}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_search()
