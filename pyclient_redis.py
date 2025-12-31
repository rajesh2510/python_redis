import requests
import re
import sys
from time import sleep

# Configuration
BASE_URL = 'http://localhost:8080'

def validate_email(email):
    if not email:
        return False
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(regex, email) is not None

def validate_password(password):
    if not password:
        return False
    byte_length = len(password.encode('utf-8'))
    if byte_length <= 8 or byte_length >= 72:
        return False
    return True

def main():
    print("--- Auth Client ---")
    username = input("Enter username: ")
    email = input("Enter email: ")
    password = input("Enter password: ")

    if not validate_email(email):
        print("Error: Invalid email format.")
        sys.exit(1)

    if not validate_password(password):
        byte_len = len(password.encode('utf-8'))
        print(f"Error: Invalid password length ({byte_len} bytes).")
        print("Password must be greater than 8 bytes and less than 72 bytes.")
        sys.exit(1)

    # Use a Session object to persist cookies automatically
    session = requests.Session()

    # SIGNUP
    print(f"Attempting to sign up as {username}...")
    signup_payload = {
        "username": username,
        "email": email,
        "password": password
    }
    
    try:
        response = session.post(f"{BASE_URL}/signup", json=signup_payload)
        print(f"Status: {response.status_code} | Response: {response.json()}")

    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to server. Is it running on port 8080?")
        return

    # LOGIN
    print(f"Attempting to login...")
    login_payload = {
        "email": email,
        "password": password
    }
    
    response = session.post(f"{BASE_URL}/login", json=login_payload)
    print(f"Status: {response.status_code} | Response: {response.json()}")

    if response.status_code == 200:
        # ACCESS PROTECTED ROUTE
        print("Accessing protected route...")
        response = session.get(f"{BASE_URL}/protected")
        print(f"Status: {response.status_code} | Response: {response.json()}")

        # LOGOUT
        sleep(10)
        print("Logging out...")
        response = session.post(f"{BASE_URL}/logout")
        print(f"Status: {response.status_code} | Response: {response.json()}")

if __name__ == '__main__':
    main()