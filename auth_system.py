import json
import hashlib
import os
import re

CREDENTIALS_FILE = 'user_credentials.json'

def hash_password(password):
    """
    Hashes a password using SHA-256.

    Args:
    password (str): The password to hash.

    Returns:
    str: The hashed password.
    """
    return hashlib.sha256(password.encode()).hexdigest()

def load_credentials():
    """
    Loads user credentials from a JSON file.

    Returns:
    dict: The dictionary containing user credentials.
    """
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, 'r') as file:
            return json.load(file)
    return {}

def save_credentials(credentials):
    """
    Saves user credentials to a JSON file.

    Args:
    credentials (dict): The dictionary containing user credentials.
    """
    with open(CREDENTIALS_FILE, 'w') as file:
        json.dump(credentials, file, indent=4)

def validate_password(password):
    """
    Validates the password against standard criteria.

    Args:
    password (str): The password to validate.

    Returns:
    bool: True if the password is valid, False otherwise.
    """
    if len(password) < 8:
        print("Error: Password must be at least 8 characters long.")
        return False
    if not re.search(r"[A-Z]", password):
        print("Error: Password must contain at least one uppercase letter.")
        return False
    if not re.search(r"[a-z]", password):
        print("Error: Password must contain at least one lowercase letter.")
        return False
    if not re.search(r"\d", password):
        print("Error: Password must contain at least one digit.")
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        print("Error: Password must contain at least one special character.")
        return False
    return True

def register_user(username, password):
    """
    Registers a new user with a username and password.

    Args:
    username (str): The username for the new user.
    password (str): The password for the new user.

    Returns:
    bool: True if registration was successful, False otherwise.
    """
    credentials = load_credentials()
    username = username.lower()

    if username in credentials:
        print("Error: Username already exists.")
        return False

    if not validate_password(password):
        return False

    credentials[username] = hash_password(password)
    save_credentials(credentials)
    print("User registered successfully!")
    return True

def login_user(username, password):
    """
    Logs in a user by validating their username and password.

    Args:
    username (str): The username of the user.
    password (str): The password of the user.

    Returns:
    bool: True if login was successful, False otherwise.
    """
    credentials = load_credentials()
    username = username.lower()

    if username not in credentials:
        print("Error: Username not found.")
        return False

    if credentials[username] == hash_password(password):
        print("Login successful! Welcome", username)
        return True
    else:
        print("Error: Invalid credentials.")
        return False

def main():
    """
    The main function providing the user interface for registration and login.
    """
    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            register_user(username, password)
        elif choice == '2':
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            login_user(username, password)
        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
