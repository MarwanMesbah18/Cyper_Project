# Caesar Cipher Implementation in Python

def caesar_encrypt(message, key):
    encrypted_message = ""
    for char in message:
        if char.isalpha():
            shift = key % 26
            if char.islower():
                encrypted_message += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            elif char.isupper():
                encrypted_message += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        else:
            encrypted_message += char
    return encrypted_message

def caesar_decrypt(encrypted_message, key):
    decrypted_message = ""
    for char in encrypted_message:
        if char.isalpha():
            shift = key % 26
            if char.islower():
                decrypted_message += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            elif char.isupper():
                decrypted_message += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
        else:
            decrypted_message += char
    return decrypted_message

# Example usage
if __name__ == "__main__":
    print("Caesar Cipher Encryption/Decryption")
    message = input("Enter the message: ")
    key = int(input("Enter the encryption key (integer): "))

    # Encrypt the message
    encrypted = caesar_encrypt(message, key)
    print("Encrypted Message:", encrypted)

    # Decrypt the message
    decrypted = caesar_decrypt(encrypted, key)
    print("Decrypted Message:", decrypted)
