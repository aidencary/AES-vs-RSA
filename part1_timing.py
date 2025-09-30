# Part 1 - Local Implementation & Timing
# Aiden Cary
# Information Security Assignment 3 - Part 1 Only
# Made with ChatGPT and Claude
#
# CODE ATTRIBUTION:
# - Core structure and timing framework: Written by student
# - AES/RSA implementation: Adapted from PyCryptodome library documentation
# - File handling and measurement: Student implementation
#
# This script implements AES-256-CBC and RSA-2048+ encryption/decryption
# and measures timing performance on three different file sizes:
# - Small: ~10KB
# - Medium: ~500KB  
# - Large: ~5MB
#
# Dependencies: pycryptodome
# Example usage: python part1_timing.py

import os
import time
import datetime
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# ----------------------
# Helper Functions
# ----------------------
def now_iso():
    return datetime.datetime.now().isoformat()

def ts_print(msg):
    print(f"[{now_iso()}] {msg}")

def time_ns():
    return time.perf_counter_ns()

def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()

def write_bytes(path, data):
    with open(path, "wb") as f:
        f.write(data)

# ----------------------
# AES-256-CBC Functions
# ----------------------
def aes_encrypt_bytes(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt data using AES-256-CBC"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_data)

def aes_decrypt_bytes(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt data using AES-256-CBC"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    return unpad(decrypted_padded, AES.block_size)

def aes_encrypt_file(input_path, output_path, key, iv):
    """Encrypt a file using AES and measure timing"""
    plaintext = read_bytes(input_path)
    
    start_time = time_ns()
    ciphertext = aes_encrypt_bytes(key, iv, plaintext)
    end_time = time_ns()
    
    write_bytes(output_path, ciphertext)
    return (end_time - start_time) / 1e9  # Convert to seconds

def aes_decrypt_file(input_path, output_path, key, iv):
    """Decrypt a file using AES and measure timing"""
    ciphertext = read_bytes(input_path)
    
    start_time = time_ns()
    plaintext = aes_decrypt_bytes(key, iv, ciphertext)
    end_time = time_ns()
    
    write_bytes(output_path, plaintext)
    return (end_time - start_time) / 1e9  # Convert to seconds

# ----------------------
# RSA-2048+ Functions
# ----------------------
def generate_rsa_keypair(bits=2048):
    """Generate RSA key pair and measure timing"""
    start_time = time_ns()
    key = RSA.generate(bits)
    end_time = time_ns()
    
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    generation_time = (end_time - start_time) / 1e9
    
    return private_key, public_key, generation_time

def rsa_encrypt_bytes(public_key_pem, plaintext: bytes):
    """Encrypt data using RSA-OAEP and measure timing"""
    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key)
    
    start_time = time_ns()
    ciphertext = cipher.encrypt(plaintext)
    end_time = time_ns()
    
    encrypt_time = (end_time - start_time) / 1e9
    return ciphertext, encrypt_time

def rsa_decrypt_bytes(private_key_pem, ciphertext: bytes):
    """Decrypt data using RSA-OAEP and measure timing"""
    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key)
    
    start_time = time_ns()
    plaintext = cipher.decrypt(ciphertext)
    end_time = time_ns()
    
    decrypt_time = (end_time - start_time) / 1e9
    return plaintext, decrypt_time

# ----------------------
# Main Timing Experiment
# ----------------------
def run_timing_experiment(file_paths):
    """Part 1: Comprehensive timing analysis"""
    ts_print("=== PART 1: LOCAL IMPLEMENTATION & TIMING ===")
    ts_print("Testing AES-256-CBC and RSA-2048+ encryption/decryption")
    
    # Generate RSA keys
    ts_print("Generating RSA-2048 key pair...")
    private_key, public_key, keygen_time = generate_rsa_keypair(2048)
    ts_print(f"RSA key generation completed in {keygen_time:.6f} seconds")
    
    results = []
    
    for file_path in file_paths:
        if not os.path.exists(file_path):
            ts_print(f"ERROR: File {file_path} not found!")
            continue
            
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        ts_print(f"\n--- Processing: {file_name} ({file_size:,} bytes) ---")
        
        # === AES-256-CBC Testing ===
        ts_print("Testing AES-256-CBC...")
        aes_key = get_random_bytes(32)
        aes_iv = get_random_bytes(16)
        
        # AES Encryption
        aes_enc_file = file_path + ".aes_encrypted"
        aes_enc_time = aes_encrypt_file(file_path, aes_enc_file, aes_key, aes_iv)
        ts_print(f"  AES encryption: {aes_enc_time:.6f} seconds")
        
        # AES Decryption
        aes_dec_file = file_path + ".aes_decrypted"
        aes_dec_time = aes_decrypt_file(aes_enc_file, aes_dec_file, aes_key, aes_iv)
        ts_print(f"  AES decryption: {aes_dec_time:.6f} seconds")
        
        # Verify AES correctness
        original_data = read_bytes(file_path)
        decrypted_data = read_bytes(aes_dec_file)
        aes_correct = (original_data == decrypted_data)
        ts_print(f"  AES verification: {'PASS' if aes_correct else 'FAIL'}")
        
        # === RSA-2048-OAEP Testing ===
        ts_print("Testing RSA-2048-OAEP...")
        
        # RSA can only handle small data (~190 bytes for 2048-bit key with OAEP)
        max_rsa_size = 190
        sample_data = original_data[:max_rsa_size]
        
        # RSA Encryption
        rsa_ciphertext, rsa_enc_time = rsa_encrypt_bytes(public_key, sample_data)
        ts_print(f"  RSA encryption ({len(sample_data)} bytes): {rsa_enc_time:.6f} seconds")
        
        # RSA Decryption
        rsa_plaintext, rsa_dec_time = rsa_decrypt_bytes(private_key, rsa_ciphertext)
        ts_print(f"  RSA decryption: {rsa_dec_time:.6f} seconds")
        
        # Verify RSA correctness
        rsa_correct = (sample_data == rsa_plaintext)
        ts_print(f"  RSA verification: {'PASS' if rsa_correct else 'FAIL'}")
        
        # Store results
        results.append({
            "file": file_name,
            "size_bytes": file_size,
            "aes_enc_time": aes_enc_time,
            "aes_dec_time": aes_dec_time,
            "rsa_enc_time": rsa_enc_time,
            "rsa_dec_time": rsa_dec_time,
            "aes_correct": aes_correct,
            "rsa_correct": rsa_correct
        })
    
    ts_print("\n=== TIMING EXPERIMENT COMPLETE ===")
    return results

# ----------------------
# Results Display
# ----------------------
def print_results_table(results):
    """Print timing results in a formatted table"""
    print("\n" + "="*80)
    print("PART 1 - ENCRYPTION/DECRYPTION TIMING RESULTS")
    print("="*80)
    print(f"{'File':<15} {'Size':<10} {'AES Enc (s)':<12} {'AES Dec (s)':<12} {'RSA Enc (s)':<12} {'RSA Dec (s)':<12}")
    print("-" * 80)
    
    for r in results:
        size_str = f"{r['size_bytes']//1024}KB" if r['size_bytes'] < 1024*1024 else f"{r['size_bytes']//(1024*1024)}MB"
        
        print(f"{r['file']:<15} {size_str:<10} {r['aes_enc_time']:<12.6f} {r['aes_dec_time']:<12.6f} "
              f"{r['rsa_enc_time']:<12.6f} {r['rsa_dec_time']:<12.6f}")
    
    print("\nNotes:")
    print("- RSA timing is for small sample (~190 bytes) due to RSA size limitations")
    print("- For large files in practice, use AES for bulk data encryption")
    print("- All algorithms use secure parameters: AES-256-CBC, RSA-2048-OAEP")

def print_analysis(results):
    """Print performance analysis"""
    print("\n" + "="*60)
    print("PERFORMANCE ANALYSIS")
    print("="*60)
    
    for r in results:
        print(f"\nFile: {r['file']} ({r['size_bytes']:,} bytes)")
        print(f"  AES-256 is {r['rsa_enc_time']/r['aes_enc_time']:.1f}x faster than RSA for encryption")
        print(f"  AES-256 is {r['rsa_dec_time']/r['aes_dec_time']:.1f}x faster than RSA for decryption")
        print(f"  Verification: AES={r['aes_correct']}, RSA={r['rsa_correct']}")

# ----------------------
# Main Execution
# ----------------------
if __name__ == "__main__":
    # File paths for testing
    test_files = ["10kb_words.txt", "500kb_words.txt", "5mb_words.txt"]
    
    print("INFORMATION SECURITY ASSIGNMENT 3 - PART 1")
    print("Local Implementation & Timing Analysis")
    print("Testing AES-256-CBC vs RSA-2048-OAEP")
    
    ts_print("REMINDER: Take screenshots with timestamps for assignment submission!")
    
    # Run the timing experiment
    results = run_timing_experiment(test_files)
    
    # Display results
    print_results_table(results)
    print_analysis(results)
    
    print("\n" + "="*60)
    print("ASSIGNMENT SUBMISSION READY!")
    print("Screenshot the timing results table and analysis above.")
    print("="*60)