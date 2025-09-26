# AES.py
# Aiden Cary
# Information Security Assignment 3
# Used to test AES encryption and decryption with files created in rand_word_file_generator.py

# Imports
import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# AES Encryption and Decryption Functions made with ChatGPT
def aes_encrypt(data, key, iv):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def aes_decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_padded) + unpadder.finalize()

# Main execution for benchmarking created my Aiden Cary to test AES with the files created in rand_word_file_generator.py
if __name__ == "__main__":
    print("AES Encryption/Decryption Benchmark")
    print("What size file would you like to test with AES?")
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

    key = os.urandom(32)  # AES-256
    iv = os.urandom(16)   # CBC IV

    start = time.time()
    ciphertext = aes_encrypt(file_data, key, iv)
    end = time.time()
    print("AES Encryption time:", end - start)

    start = time.time()
    plaintext = aes_decrypt(ciphertext, key, iv)
    end = time.time()
    print("AES Decryption time:", end - start)

    # Optional: verify
    print("Decryption successful:", plaintext == file_data)



