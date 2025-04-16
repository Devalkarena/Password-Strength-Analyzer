import hashlib
import string
import requests

# List of common weak passwords
weak_passwords = [
    "123456", "password", "123456789", "qwerty", "abc123", "12345", "password1", "123qwe", "letmein", "welcome"
]

# Function to check password length
def check_length(password):
    if len(password) < 8:
        return False, "Password is too short. It should be at least 8 characters."
    return True, ""

# Function to check character variety
def check_character_variety(password):
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special = any(char in string.punctuation for char in password)
    
    if not (has_upper and has_lower and has_digit and has_special):
        return False, "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character."
    return True, ""

# Function to check if the password is weak
def check_weak_password(password):
    if password.lower() in weak_passwords:
        return False, "Password is too weak, it's a common password."
    return True, ""

# Function to check if the password has been breached
def check_breach(password):
    # Hash the password with SHA1 and get the first 5 characters of the hash
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]
    
    # Call the API to check if the password has been compromised
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    
    if response.status_code == 200:
        hashes = response.text.splitlines()
        for hash in hashes:
            if hash.split(":")[0] == suffix:
                return False, "Password has been compromised in a data breach."
    return True, ""

# Function to analyze the password
def analyze_password(password):
    # Check password length
    valid, message = check_length(password)
    if not valid:
        return f"Password strength: Weak. {message}"

    # Check for character variety
    valid, message = check_character_variety(password)
    if not valid:
        return f"Password strength: Weak. {message}"

    # Check for weak password
    valid, message = check_weak_password(password)
    if not valid:
        return f"Password strength: Weak. {message}"

    # Check if the password has been breached
    valid, message = check_breach(password)
    if not valid:
        return f"Password strength: Weak. {message}"

    # If all checks pass
    return "Password strength: Strong."

# Main function to accept user input
if __name__ == "__main__":
    password = input("Enter a password to check its strength: ")
    print(analyze_password(password))
