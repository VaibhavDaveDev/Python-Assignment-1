"""
    Encrypts the message by shifting each printable ASCII character forward by the key.
    Printable characters range from ASCII 32 to 126.
    
    Parameters:
        message (str): The text to encrypt (must not be purely numeric).
        key (int): A positive integer used to shift the characters.
    
    Returns:
        str: The encrypted message.
    
    Raises:
        ValueError: If key is not a positive integer (> 0), if message is not a string,
                    or if message is purely numeric.
"""
def encrypt(message, key):
    if not isinstance(message, str):
        raise ValueError("Message must be a string.")
    if message.isdigit():
        raise ValueError("Message cannot be purely numeric. Please enter text.")
    if key <= 0:
        raise ValueError("Key must be a positive integer greater than zero.")
    
    encrypted_message = ""
    for char in message:
        ascii_val = ord(char)
        if 32 <= ascii_val <= 126:
            new_ascii = ((ascii_val - 32 + key) % 95) + 32
            encrypted_message += chr(new_ascii)
        else:
            encrypted_message += char
    return encrypted_message

"""
    Decrypts the message by shifting each printable ASCII character backward by the key.
    Parameters:
        message (str): The encrypted text (must not be purely numeric).
        key (int): A positive integer that was used to encrypt the message.
    Returns:
        str: The decrypted (original) message.
    Raises:
        ValueError: If key is not a positive integer (> 0), if message is not a string,
                    or if message is purely numeric.
"""
def decrypt(message, key):
    if not isinstance(message, str):
        raise ValueError("Message must be a string.")
    if message.isdigit():
        raise ValueError("Message cannot be purely numeric. Please enter text.")
    if key <= 0:
        raise ValueError("Key must be a positive integer greater than zero.")
    
    decrypted_message = ""
    for char in message:
        ascii_val = ord(char)
        if 32 <= ascii_val <= 126:
            new_ascii = ((ascii_val - 32 - key) % 95) + 32
            decrypted_message += chr(new_ascii)
        else:
            decrypted_message += char
    return decrypted_message

def run_tests():
    """
    Runs tests to verify the encryption and decryption functions.
    """
    print("Running tests:")
    
    # Test 1: Encryption of 'hello' with key 3 should produce 'khoor'
    try:
        test_message = "hello"
        test_key = 3
        encrypted = encrypt(test_message, test_key)
        assert encrypted == "khoor", f"Expected 'khoor', got '{encrypted}'"
        print("Test 1 passed: encrypt('hello', 3) ->", encrypted)
    except Exception as e:
        print("Test 1 failed:", e)
    
    # Test 2: Decryption of 'khoor' with key 3 should produce 'hello'
    try:
        test_message = "khoor"
        test_key = 3
        decrypted = decrypt(test_message, test_key)
        assert decrypted == "hello", f"Expected 'hello', got '{decrypted}'"
        print("Test 2 passed: decrypt('khoor', 3) ->", decrypted)
    except Exception as e:
        print("Test 2 failed:", e)
    
    # Test 3: Zero key should raise ValueError
    try:
        encrypt("test", 0)
        print("Test 3 failed: Expected ValueError for key=0")
    except ValueError:
        print("Test 3 passed: ValueError raised for key=0")
    
    # Test 4: Negative key should raise ValueError
    try:
        decrypt("test", -5)
        print("Test 4 failed: Expected ValueError for negative key")
    except ValueError:
        print("Test 4 passed: ValueError raised for negative key")
    
    # Test 5: Non-string message should raise ValueError
    try:
        encrypt(12345, 3)
        print("Test 5 failed: Expected ValueError for non-string message")
    except ValueError:
        print("Test 5 passed: ValueError raised for non-string message")
    
    # Test 6: Purely numeric message should raise ValueError
    try:
        encrypt("45", 12)
        print("Test 6 failed: Expected ValueError for purely numeric message")
    except ValueError:
        print("Test 6 passed: ValueError raised for purely numeric message")

def main():
    # Uncomment the following line to run tests:
    run_tests()
    message = input("Enter the message: ")
    
    # Check if the message is purely numeric.
    if message.isdigit():
        print("Invalid message. Message cannot be purely numeric. Please enter text.")
        return
    
    try:
        key = int(input("Enter the key (a positive integer): "))
    except ValueError:
        print("Invalid key. Please enter a valid integer.")
        return
    
    if key <= 0:
        print("Invalid key. Please enter a positive integer greater than zero.")
        return

    mode = input("Choose mode (encrypt/decrypt): ").strip().lower()
    
    try:
        if mode == "encrypt":
            result = encrypt(message, key)
            print("Encrypted message:", result)
        elif mode == "decrypt":
            result = decrypt(message, key)
            print("Decrypted message:", result)
        else:
            print("Invalid mode selected. Please choose either 'encrypt' or 'decrypt'.")
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()