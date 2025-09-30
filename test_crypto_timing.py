# Part 1 - Local Implementation & Timing
# Aiden Cary  
# Information Security Assignment 3 - Part 1 Only
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
# Example usage: python test_crypto_timing.py

import os
import time
import datetime
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# ----------------------
# Helpers
# ----------------------
def now_iso():
    return datetime.datetime.now().isoformat()

def ts_print(msg):
    print(f"[{now_iso()}] {msg}")

def time_ns():
    return time.perf_counter_ns()

def write_bytes(path, data):
    with open(path, "wb") as f:
        f.write(data)

def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()



# ----------------------
# AES-256-CBC functions
# ----------------------
def aes_encrypt_bytes(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, AES.block_size))

def aes_decrypt_bytes(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

def aes_encrypt_file(in_path, out_path, key, iv):
    plaintext = read_bytes(in_path)
    t0 = time_ns()
    ciphertext = aes_encrypt_bytes(key, iv, plaintext)
    t1 = time_ns()
    write_bytes(out_path, ciphertext)
    return (t1 - t0) / 1e9  # seconds

def aes_decrypt_file(in_path, out_path, key, iv):
    ciphertext = read_bytes(in_path)
    t0 = time_ns()
    plaintext = aes_decrypt_bytes(key, iv, ciphertext)
    t1 = time_ns()
    write_bytes(out_path, plaintext)
    return (t1 - t0) / 1e9  # seconds

# ----------------------
# RSA functions (PyCryptodome)
# ----------------------
def generate_rsa_keypair(bits=2048):
    t0 = time_ns()
    key = RSA.generate(bits)
    t1 = time_ns()
    private = key.export_key()
    public = key.publickey().export_key()
    return private, public, (t1 - t0) / 1e9

def rsa_encrypt_bytes(public_key_bytes, plaintext: bytes) -> tuple[bytes, float]:
    pub = RSA.import_key(public_key_bytes)
    cipher = PKCS1_OAEP.new(pub)
    t0 = time_ns()
    ct = cipher.encrypt(plaintext)
    t1 = time_ns()
    return ct, (t1 - t0)/1e9

def rsa_decrypt_bytes(private_key_bytes, ciphertext: bytes) -> tuple[bytes, float]:
    key = RSA.import_key(private_key_bytes)
    cipher = PKCS1_OAEP.new(key)
    t0 = time_ns()
    pt = cipher.decrypt(ciphertext)
    t1 = time_ns()
    return pt, (t1 - t0)/1e9

# -------------------------------------------------------------------
# RSA Full File Encryption (Chunking)
# -------------------------------------------------------------------
def rsa_encrypt_file_chunked(in_path, out_path, public_key_bytes):
    pub_key = RSA.import_key(public_key_bytes)
    cipher = PKCS1_OAEP.new(pub_key, hashAlgo=SHA256)
    
    chunk_size = pub_key.size_in_bytes() - 2 * SHA256.digest_size - 2
    
    plaintext = read_bytes(in_path)
    encrypted_chunks = []
    
    t0 = time_ns()
    for i in range(0, len(plaintext), chunk_size):
        chunk = plaintext[i:i+chunk_size]
        encrypted_chunks.append(cipher.encrypt(chunk))
    t1 = time_ns()
    
    write_bytes(out_path, b''.join(encrypted_chunks))
    return (t1 - t0) / 1e9

def rsa_decrypt_file_chunked(in_path, out_path, private_key_bytes):
    priv_key = RSA.import_key(private_key_bytes)
    cipher = PKCS1_OAEP.new(priv_key, hashAlgo=SHA256)

    encrypted_chunk_size = priv_key.size_in_bytes()

    ciphertext = read_bytes(in_path)
    decrypted_chunks = []

    t0 = time_ns()
    for i in range(0, len(ciphertext), encrypted_chunk_size):
        chunk = ciphertext[i:i+encrypted_chunk_size]
        decrypted_chunks.append(cipher.decrypt(chunk))
    t1 = time_ns()

    write_bytes(out_path, b''.join(decrypted_chunks))
    return (t1 - t0) / 1e9

# ----------------------
# Hybrid: encrypt file with AES, encrypt AES key with RSA
# ----------------------
def hybrid_encrypt_file(in_path, out_cipher_path, rsa_pub_bytes):
    # AES part
    key = get_random_bytes(32)  # AES-256
    iv = get_random_bytes(16)
    aes_ct_time = aes_encrypt_file(in_path, out_cipher_path, key, iv)
    # RSA part (encrypt AES key + iv)
    to_encrypt = key + iv
    rsa_ct, rsa_time = rsa_encrypt_bytes(rsa_pub_bytes, to_encrypt)
    return aes_ct_time, rsa_time, rsa_ct

def hybrid_decrypt_file(encrypted_path, rsa_private_bytes, out_plain_path, rsa_ct):
    # decrypt AES key
    to_decrypt, rsa_dec_time = rsa_decrypt_bytes(rsa_private_bytes, rsa_ct)
    key = to_decrypt[:32]
    iv = to_decrypt[32:48]
    aes_dec_time = aes_decrypt_file(encrypted_path, out_plain_path, key, iv)
    return rsa_dec_time, aes_dec_time

# ----------------------
# Main experiment flow
# ----------------------
def experiment(files):
    ts_print("=== Starting experiment ===")
    # Generate RSA keys
    ts_print("Generating RSA-2048 keypair")
    priv, pub, rsa_keygen_time = generate_rsa_keypair(2048)
    ts_print(f"RSA key generation time: {rsa_keygen_time:.6f} s")

    results = []

    for fpath in files:
        base = os.path.basename(fpath)
        ts_print(f"Processing file {base}, size={os.path.getsize(fpath)} bytes")

        # AES timing
        aes_key = get_random_bytes(32)
        aes_iv = get_random_bytes(16)

        aes_enc_out = fpath + ".aes.ct"
        ts_print(f"Encrypting with AES: {aes_key.hex()[:16]}.. iv:{aes_iv.hex()[:16]}..")
        t_aes_enc = aes_encrypt_file(fpath, aes_enc_out, aes_key, aes_iv)
        ts_print(f"AES encrypt time: {t_aes_enc:.6f} s")

        aes_dec_out = fpath + ".aes.dec"
        ts_print("Decrypting with AES")
        t_aes_dec = aes_decrypt_file(aes_enc_out, aes_dec_out, aes_key, aes_iv)
        ts_print(f"AES decrypt time: {t_aes_dec:.6f} s")

        # RSA timing on a small sample: encrypt a small 200-byte sample
        sample = read_bytes(fpath)[:190] # Use 190 to be safe for 2048-bit key
        ts_print("Encrypting small sample with RSA (OAEP)")
        rsa_ct_sample, rsa_enc_time = rsa_encrypt_bytes(pub, sample)
        ts_print(f"RSA encrypt time (sample): {rsa_enc_time:.6f} s")
        rsa_pt_sample, rsa_dec_time = rsa_decrypt_bytes(priv, rsa_ct_sample)
        ts_print(f"RSA decrypt time (sample): {rsa_dec_time:.6f} s")
        assert rsa_pt_sample == sample

        # -------------------------------------------------------------------
        # MODIFIED SECTION: Run full RSA timing for ALL files
        # -------------------------------------------------------------------
        ts_print("!!! WARNING: Starting SLOW full RSA file encryption (for demonstration only)...")
        rsa_enc_full_out = fpath + ".rsa_full.ct"
        t_rsa_enc_full = rsa_encrypt_file_chunked(fpath, rsa_enc_full_out, pub)
        ts_print(f"RSA full encrypt time: {t_rsa_enc_full:.6f} s")

        rsa_dec_full_out = fpath + ".rsa_full.dec"
        t_rsa_dec_full = rsa_decrypt_file_chunked(rsa_enc_full_out, rsa_dec_full_out, priv)
        ts_print(f"RSA full decrypt time: {t_rsa_dec_full:.6f} s")
        # -------------------------------------------------------------------

        # Hybrid encrypt file (AES for data + RSA for AES key)
        ts_print("Hybrid encrypt (AES file + RSA encrypt AES key)")
        hybrid_aes_time, hybrid_rsa_time, hybrid_rsa_ct = hybrid_encrypt_file(fpath, fpath + ".hybrid.ct", pub)
        ts_print(f"Hybrid AES time: {hybrid_aes_time:.6f} s, RSA time (key encrypt): {hybrid_rsa_time:.6f} s")

        # Avalanche: AES - flip 1 bit in plaintext and compare ciphertexts
        ts_print("Avalanche test (AES): reading plaintext")
        original_plain = read_bytes(fpath)
        iv = get_random_bytes(16)
        key = get_random_bytes(32)
        ctA = aes_encrypt_bytes(key, iv, original_plain)
        flipped_plain = flip_one_bit(original_plain, byte_index=0, bit_index=0)
        ctB = aes_encrypt_bytes(key, iv, flipped_plain)
        hamming_bits = hamming_distance_bytes(ctA, ctB)
        pct_bits_changed = hamming_bits / (8 * len(ctA)) * 100
        ts_print(f"AES avalanche: differing bits={hamming_bits}, percent bits changed={pct_bits_changed:.4f}%")

        # Avalanche: RSA - use small sample
        sample_plain = sample
        rsa_ct1, r_enc1 = rsa_encrypt_bytes(pub, sample_plain)
        flipped_sample = flip_one_bit(sample_plain, 0, 0)
        rsa_ct2, r_enc2 = rsa_encrypt_bytes(pub, flipped_sample)
        if len(rsa_ct1) == len(rsa_ct2):
            rsa_hamming_bits = hamming_distance_bytes(rsa_ct1, rsa_ct2)
            rsa_pct_bits = rsa_hamming_bits / (8 * len(rsa_ct1)) * 100
        else:
            rsa_hamming_bits = None
            rsa_pct_bits = None

        ts_print(f"RSA avalanche: differing bits={rsa_hamming_bits}, percent bits changed={rsa_pct_bits}")

        results.append({
            "file": base,
            "size_bytes": os.path.getsize(fpath),
            "aes_enc_s": t_aes_enc,
            "aes_dec_s": t_aes_dec,
            "rsa_enc_sample_s": rsa_enc_time,
            "rsa_dec_sample_s": rsa_dec_time,
            "rsa_enc_full_s": t_rsa_enc_full,
            "rsa_dec_full_s": t_rsa_dec_full,
            "hybrid_aes_enc_s": hybrid_aes_time,
            "hybrid_rsa_enckey_s": hybrid_rsa_time,
            "aes_avalanche_bits": hamming_bits,
            "aes_avalanche_pct": pct_bits_changed,
            "rsa_avalanche_bits": rsa_hamming_bits,
            "rsa_avalanche_pct": rsa_pct_bits
        })

    ts_print("=== Experiment complete ===")
    return results

# -------------------------------------------------------------------
# MODIFIED SECTION: Updated printing function for new data
# -------------------------------------------------------------------
def print_timing_table(results):
    """Print timing results in a formatted table as required by assignment"""
    print("\n" + "="*80)
    print("PART 1 - ENCRYPTION/DECRYPTION TIMING RESULTS")
    print("="*80)
    print(f"{'File Size':<12} {'AES Encrypt (s)':<18} {'AES Decrypt (s)':<18} {'RSA Encrypt (Full)':<20} {'RSA Decrypt (Full)':<20}")
    print("-" * 80)
    
    for r in results:
        size_str = f"~{r['size_bytes']//1024}KB" if r['size_bytes'] < 1024*1024 else f"~{r['size_bytes']//(1024*1024)}MB"
        
        rsa_full_enc = f"{r['rsa_enc_full_s']:.6f}" if isinstance(r['rsa_enc_full_s'], float) else r['rsa_enc_full_s']
        rsa_full_dec = f"{r['rsa_dec_full_s']:.6f}" if isinstance(r['rsa_dec_full_s'], float) else r['rsa_dec_full_s']
        
        print(f"{size_str:<12} {r['aes_enc_s']:<18.6f} {r['aes_dec_s']:<18.6f} {rsa_full_enc:<20} {rsa_full_dec:<20}")
    
    print("\nNote: 'Full' RSA timing reflects encrypting the entire file in chunks.")
    print("This is for demonstration and is extremely inefficient compared to AES.")

def print_avalanche_table(results):
    """Print avalanche effect results in a formatted table"""
    print("\n" + "="*80)
    print("PART 2 - AVALANCHE EFFECT RESULTS")
    print("="*80)
    print(f"{'File Size':<12} {'AES Bits Changed':<18} {'AES % Changed':<15} {'RSA Bits Changed':<18} {'RSA % Changed':<15}")
    print("-" * 80)
    
    for r in results:
        size_str = f"~{r['size_bytes']//1024}KB" if r['size_bytes'] < 1024*1024 else f"~{r['size_bytes']//(1024*1024)}MB"
        rsa_bits = r['rsa_avalanche_bits'] if r['rsa_avalanche_bits'] is not None else "N/A"
        rsa_pct = f"{r['rsa_avalanche_pct']:.2f}%" if r['rsa_avalanche_pct'] is not None else "N/A"
        print(f"{size_str:<12} {r['aes_avalanche_bits']:<18} {r['aes_avalanche_pct']:<14.2f}% {rsa_bits:<18} {rsa_pct:<15}")
    
    print("\nGood cryptographic algorithms should change approximately 50% of bits")
    print("when a single input bit is flipped (avalanche effect)")

if __name__ == "__main__":
    # put your file paths here
    files = ["10kb_words.txt", "500kb_words.txt", "5mb_words.txt"]
    ts_print("Starting: Make sure the three files exist in this folder.")
    ts_print("REMINDER: Take screenshots with timestamps for assignment submission!")
    out = experiment(files)
    
    # Print formatted tables as required by assignment
    print_timing_table(out)
    print_avalanche_table(out)
    
    ts_print("\nDetailed results (for debugging):")
    for r in out:
        print(r)