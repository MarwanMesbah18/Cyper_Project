import secrets
import string
import re

# Password strength testing
# Now returns (strength, color, missing_message)
def test_password_strength(password, use_lower, use_upper, use_digits, use_special):
    # Check for presence of each type in the password
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[@#$%^&+=!]', password))
    
    # Build list of missing types and message about what's needed for better strength
    missing = []
    if not has_upper:
        missing.append('uppercase letters')
    if not has_digit:
        missing.append('digits')
    if not has_special:
        missing.append('special characters')
    
    # Create message about missing types to improve strength
    message = ""
    if missing:
        message = "To improve strength, add: " + ", ".join(missing)
    
    # Determine strength based on character types present
    # Assessing purely based on character types regardless of length
    
    # Only lowercase - Very Weak
    if has_lower and not has_upper and not has_digit and not has_special:
        return ("Very Weak", "#f00", message)  # Red
    
    # Lowercase + uppercase - Weak
    elif has_lower and has_upper and not has_digit and not has_special:
        return ("Weak", "#ff8000", message)  # Orange
    
    # Lowercase + uppercase + digits - Medium
    elif has_lower and has_upper and has_digit and not has_special:
        return ("Medium", "#ffe100", message)  # Yellow
    
    # All types - Strong
    elif has_lower and has_upper and has_digit and has_special:
        return ("Strong", "#00ff00", "")  # Green
    
    # For other combinations not fitting the pattern
    else:
        # Check how many types are present
        types_present = sum([has_lower, has_upper, has_digit, has_special])
        
        if types_present <= 1:
            return ("Very Weak", "#f00", message)
        elif types_present == 2:
            return ("Weak", "#ff8000", message)
        elif types_present == 3:
            return ("Medium", "#ffe100", message)
        else:
            return ("Strong", "#00ff00", "")

def generate_password(length=12, use_lower=True, use_upper=True, use_digits=True, use_special=True):
    characters = ""
    pools = []
    special_chars = '@#$%^&+=!'
    if use_lower:
        characters += string.ascii_lowercase
        pools.append(string.ascii_lowercase)
    if use_upper:
        characters += string.ascii_uppercase
        pools.append(string.ascii_uppercase)
    if use_digits:
        characters += string.digits
        pools.append(string.digits)
    if use_special:
        characters += special_chars
        pools.append(special_chars)
    if not characters:
        raise ValueError("At least one character type must be selected.")
    if length < len(pools):
        raise ValueError(f"Password length must be at least {len(pools)} to include all selected character types.")
    # Ensure at least one character from each selected set
    password = [secrets.choice(pool) for pool in pools]
    password += [secrets.choice(characters) for _ in range(length - len(password))]
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)

if __name__ == "__main__":
    # Example usage
    length = int(input("Enter password length: "))
    use_lower = input("Include lowercase? (y/n): ").lower() == 'y'
    use_upper = input("Include uppercase? (y/n): ").lower() == 'y'
    use_digits = input("Include digits? (y/n): ").lower() == 'y'
    use_special = input("Include special characters? (y/n): ").lower() == 'y'

    try:
        password = generate_password(length, use_lower, use_upper, use_digits, use_special)
        print("Generated Password:", password)
        strength, color, missing = test_password_strength(password, use_lower, use_upper, use_digits, use_special)
        print("Password Strength:", strength, "Color Code:", color)
        if missing:
            print(missing)
    except ValueError as e:
        print("Error:", e)