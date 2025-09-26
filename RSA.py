# RSA.py
# Aiden Cary
# Information Security Assignment 3

# Imports
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import time

# Generate RSA key
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Encrypt & Decrypt
def rsa_encrypt(message):
    return public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def rsa_decrypt(ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

if __name__ == "__main__":
    print("RSA Encryption/Decryption Benchmark")
    print("What size file would you like to test with RSA?")
    print("1. 10KB")
    print("2. 500KB")
    print("3. 5MB")
    choice = input("Enter choice: ").strip()

    if choice == "1":
        file_path = "10kb_words.txt"
    elif choice == "2":
        file_path = "500kb_words.txt"
    elif choice == "3":
        file_path = "5mb_words.txt"
    else:
        print("Invalid choice. Please try again.")
        exit(1)

    with open(file_path, "rb") as f:
        file_data = f.read()

    # RSA can only encrypt small chunks
    chunk = file_data[:190]  # first 190 bytes (fits RSA-2048 with OAEP)

    start = time.time()
    ciphertext = rsa_encrypt(chunk)
    end = time.time()
    print("RSA Encryption time:", end - start)

    start = time.time()
    plaintext = rsa_decrypt(ciphertext)
    end = time.time()
    print("RSA Decryption time:", end - start)

    print("Decryption successful:", plaintext == chunk)

