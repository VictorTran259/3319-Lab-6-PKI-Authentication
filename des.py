from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

def des_encrypt(key, plaintext):
    # Generate an 8-byte IV (Initialization Vector)
    iv = get_random_bytes(8)

    # Create a DES cipher object with the specified key and IV
    cipher = DES.new(key, DES.MODE_CBC, iv)

    # Pad the plaintext to be a multiple of 8 bytes (DES block size)
    plaintext = plaintext + b"\0" * (8 - len(plaintext) % 8)

    # Encrypt the plaintext
    ciphertext = iv + cipher.encrypt(plaintext)

    return ciphertext

def des_decrypt(key, ciphertext):
    # Extract the IV from the ciphertext
    iv = ciphertext[:8]

    # Create a DES cipher object with the specified key and IV
    cipher = DES.new(key, DES.MODE_CBC, iv)

    # Decrypt the ciphertext and remove any padding
    plaintext = cipher.decrypt(ciphertext[8:]).rstrip(b"\0")

    return plaintext

"""
if __name__ == "__main__":
    key = b'YOUR8KEY'  # Replace with your 8-byte key
    plaintext = b'Hello, DES!'  # Message to be encrypted

    encrypted = des_encrypt(key, plaintext)
    decrypted = des_decrypt(key, encrypted)

    print("Plaintext:", plaintext)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted.decode('utf-8'))
"""