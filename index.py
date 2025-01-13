import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import getpass

# --- Function to derive encryption key ---
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# --- AES Encryption ---
def encrypt_file(input_file, password):
    salt = os.urandom(16)  # Generate a random salt
    key = derive_key(password, salt)
    iv = os.urandom(16)  # Initialization Vector

    # Read input file data
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Encrypt data
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Write encrypted data to a new file
    encrypted_file = input_file + ".enc"
    with open(encrypted_file, 'wb') as f:
        f.write(salt + iv + ciphertext)
    print(f"File encrypted: {encrypted_file}")

    return key

# --- AES Decryption ---
def decrypt_file(encrypted_file, password):
    with open(encrypted_file, 'rb') as f:
        data = f.read()

    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Write decrypted data to a new file
    decrypted_file = encrypted_file.replace(".enc", ".dec")
    with open(decrypted_file, 'wb') as f:
        f.write(plaintext)
    print(f"File decrypted: {decrypted_file}")

# --- Main Function ---
def main():
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    choice = input("Enter your choice: ")

    if choice == '1':
        input_file = input("Enter the file path to encrypt: ")
        password = input("Enter a password: ")
        key = encrypt_file(input_file, password)
        print(f"Your decryption key: {urlsafe_b64encode(key).decode()}")
    elif choice == '2':
        encrypted_file = input("Enter the encrypted file path: ")
        password = input("Enter the password: ")
        decrypt_file(encrypted_file, password)
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()
