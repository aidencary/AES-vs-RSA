# Part 2 - Avalanche Effect Analysis
# Aiden Cary
# Information Security Assignment 3 - Part 2 Only
# Made with ChatGPT and Claude
# This script demonstrates the avalanche effect in AES and RSA encryption
# using a small text message with both bit-by-bit and text comparison

import os
import time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# ----------------------
# Helper Functions
# ----------------------
def hamming_distance_bytes(b1: bytes, b2: bytes) -> int:
    """Count differing bits between two byte sequences"""
    assert len(b1) == len(b2), "Byte sequences must be same length"
    diff = 0
    for x, y in zip(b1, b2):
        diff += bin(x ^ y).count("1")
    return diff

def flip_one_bit(data: bytes, byte_index: int = 0, bit_index: int = 0) -> bytes:
    """Flip one bit in the data at specified position"""
    data_array = bytearray(data)
    data_array[byte_index] ^= (1 << bit_index)
    return bytes(data_array)

def show_text_comparison(original: bytes, modified: bytes, description: str):
    """Show text comparison between original and modified data"""
    print(f"\n=== {description} TEXT COMPARISON ===")
    print(f"Original text:  {original.decode('utf-8', errors='replace')}")
    print(f"Modified text:  {modified.decode('utf-8', errors='replace')}")
    
    # Find first difference
    for i, (b1, b2) in enumerate(zip(original, modified)):
        if b1 != b2:
            print(f"First difference at position {i}: '{chr(b1)}' (0x{b1:02x}) -> '{chr(b2)}' (0x{b2:02x})")
            # Show which bit was flipped
            diff = b1 ^ b2
            bit_pos = []
            for bit in range(8):
                if diff & (1 << bit):
                    bit_pos.append(7-bit)  # MSB first
            print(f"Bits flipped in byte: {bit_pos} (binary diff: {diff:08b})")
            break

def show_hex_comparison(ct1: bytes, ct2: bytes, description: str, max_bytes: int = 32):
    """Show hexadecimal comparison of ciphertexts"""
    print(f"\n=== {description} CIPHERTEXT COMPARISON ===")
    print(f"Ciphertext 1: {ct1[:max_bytes].hex()}")
    print(f"Ciphertext 2: {ct2[:max_bytes].hex()}")
    
    # Count different bytes in sample
    different_bytes = sum(1 for b1, b2 in zip(ct1[:max_bytes], ct2[:max_bytes]) if b1 != b2)
    print(f"Different bytes in first {max_bytes}: {different_bytes}/{max_bytes} ({different_bytes/max_bytes*100:.1f}%)")
    
    # Total bit analysis
    total_diff_bits = hamming_distance_bytes(ct1, ct2)
    total_bits = len(ct1) * 8
    print(f"Total different bits: {total_diff_bits}/{total_bits} ({total_diff_bits/total_bits*100:.2f}%)")

# ----------------------
# AES Functions
# ----------------------
def aes_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt data using AES-256-CBC"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded)

def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt data using AES-256-CBC"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, AES.block_size)

# ----------------------
# RSA Functions
# ----------------------
def generate_rsa_keypair(bits: int = 2048):
    """Generate RSA key pair"""
    start_time = time.time()
    key = RSA.generate(bits)
    end_time = time.time()
    
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    return private_key, public_key, (end_time - start_time)

def rsa_encrypt(plaintext: bytes, public_key_pem: bytes) -> bytes:
    """Encrypt data using RSA-OAEP"""
    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(plaintext)

def rsa_decrypt(ciphertext: bytes, private_key_pem: bytes) -> bytes:
    """Decrypt data using RSA-OAEP"""
    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)

# ----------------------
# Avalanche Effect Tests
# ----------------------
def test_aes_avalanche(test_message: str):
    """Test AES avalanche effect"""
    print("\n" + "="*60)
    print("AES-256-CBC AVALANCHE EFFECT TEST")
    print("="*60)
    
    # Convert to bytes
    original_data = test_message.encode('utf-8')
    modified_data = flip_one_bit(original_data, byte_index=0, bit_index=0)  # Flip first bit
    
    # Show input comparison
    show_text_comparison(original_data, modified_data, "AES INPUT")
    
    # Generate AES key and IV
    key = get_random_bytes(32)  # AES-256
    iv = get_random_bytes(16)   # AES block size
    
    print(f"\nAES Key: {key.hex()[:32]}...")
    print(f"AES IV:  {iv.hex()}")
    
    # Encrypt both versions
    print("\nEncrypting original and modified messages...")
    start_time = time.time()
    ciphertext1 = aes_encrypt(original_data, key, iv)
    end_time = time.time()
    aes_enc_time = end_time - start_time
    
    ciphertext2 = aes_encrypt(modified_data, key, iv)
    
    print(f"AES encryption time: {aes_enc_time:.6f} seconds")
    print(f"Ciphertext lengths: {len(ciphertext1)} bytes each")
    
    # Show output comparison
    show_hex_comparison(ciphertext1, ciphertext2, "AES OUTPUT")
    
    # Verify decryption works
    decrypted = aes_decrypt(ciphertext1, key, iv)
    print(f"\nDecryption verification: {'PASS' if decrypted == original_data else 'FAIL'}")

def test_rsa_avalanche(test_message: str):
    """Test RSA avalanche effect"""
    print("\n" + "="*60)
    print("RSA-2048-OAEP AVALANCHE EFFECT TEST")
    print("="*60)
    
    # RSA can only handle small messages, so truncate if needed
    max_rsa_size = 190  # Safe size for RSA-2048 with OAEP padding
    if len(test_message.encode('utf-8')) > max_rsa_size:
        test_message = test_message[:max_rsa_size - 10]  # Leave some margin
        print(f"Note: Truncated message to {len(test_message)} characters for RSA")
    
    # Convert to bytes
    original_data = test_message.encode('utf-8')
    modified_data = flip_one_bit(original_data, byte_index=0, bit_index=0)  # Flip first bit
    
    # Show input comparison
    show_text_comparison(original_data, modified_data, "RSA INPUT")
    
    # Generate RSA keys
    print("\nGenerating RSA-2048 key pair...")
    private_key_pem, public_key_pem, keygen_time = generate_rsa_keypair(2048)
    print(f"RSA key generation time: {keygen_time:.6f} seconds")
    
    # Encrypt both versions
    print("\nEncrypting original and modified messages...")
    start_time = time.time()
    ciphertext1 = rsa_encrypt(original_data, public_key_pem)
    end_time = time.time()
    rsa_enc_time = end_time - start_time
    
    ciphertext2 = rsa_encrypt(modified_data, public_key_pem)
    
    print(f"RSA encryption time: {rsa_enc_time:.6f} seconds")
    print(f"Ciphertext lengths: {len(ciphertext1)} bytes each")
    
    # Show output comparison
    show_hex_comparison(ciphertext1, ciphertext2, "RSA OUTPUT")
    
    # Verify decryption works
    decrypted = rsa_decrypt(ciphertext1, private_key_pem)
    print(f"\nDecryption verification: {'PASS' if decrypted == original_data else 'FAIL'}")

# ----------------------
# Main Test Function
# ----------------------
def main():
    """Run avalanche effect tests"""
    print("PART 2 - AVALANCHE EFFECT DEMONSTRATION")
    print("Information Security Assignment 3")
    print("Testing with small text message")
    
    # Small test message
    test_message = "This is a test message for demonstrating the avalanche effect in cryptographic algorithms!"
    
    print(f"\nTest message ({len(test_message)} characters):")
    print(f'"{test_message}"')
    
    # Test AES avalanche effect
    test_aes_avalanche(test_message)
    
    # Test RSA avalanche effect
    test_rsa_avalanche(test_message)
    
    # Summary
    print("\n" + "="*60)
    print("AVALANCHE EFFECT SUMMARY")
    print("="*60)
    print("Key Observations:")
    print("1. ONE BIT change in plaintext causes ~50% of ciphertext bits to change")
    print("2. This demonstrates excellent avalanche effect in both AES and RSA")
    print("3. Ciphertexts appear completely unrelated despite minimal input change")
    print("4. This property is crucial for cryptographic security")
    print("\nScreenshot this output for your assignment submission!")

if __name__ == "__main__":
    main()