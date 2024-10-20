import argparse
import time
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def encrypt_file(algorithm, mode, input_file, output_file):
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    if algorithm == 'AES':
        key = get_random_bytes(32)  # 256-bit key for AES
        iv = get_random_bytes(16) if mode != 'ECB' else None
        cipher = AES.new(key, getattr(AES, f'MODE_{mode}'), iv) if mode != 'ECB' else AES.new(key, AES.MODE_ECB)
    elif algorithm == 'DES':
        key = get_random_bytes(8)  # 56-bit key for DES (8 bytes, but only 56 bits are used)
        iv = get_random_bytes(8) if mode != 'ECB' else None
        cipher = DES.new(key, getattr(DES, f'MODE_{mode}'), iv) if mode != 'ECB' else DES.new(key, DES.MODE_ECB)
    
    ciphertext = cipher.encrypt(pad(plaintext, cipher.block_size))
    
    with open(output_file, 'wb') as f:
        if iv:
            f.write(iv)
        f.write(ciphertext)
    
    return key

def decrypt_file(algorithm, mode, input_file, output_file, key):
    with open(input_file, 'rb') as f:
        if mode != 'ECB':
            iv = f.read(16 if algorithm == 'AES' else 8)
            ciphertext = f.read()
        else:
            ciphertext = f.read()
            iv = None
    
    if algorithm == 'AES':
        cipher = AES.new(key, getattr(AES, f'MODE_{mode}'), iv) if mode != 'ECB' else AES.new(key, AES.MODE_ECB)
    elif algorithm == 'DES':
        cipher = DES.new(key, getattr(DES, f'MODE_{mode}'), iv) if mode != 'ECB' else DES.new(key, DES.MODE_ECB)
    
    plaintext = unpad(cipher.decrypt(ciphertext), cipher.block_size)
    
    with open(output_file, 'wb') as f:
        f.write(plaintext)

def main():
    parser = argparse.ArgumentParser(description='Encrypt or decrypt files using AES or DES')
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help='Action to perform')
    parser.add_argument('algorithm', choices=['AES', 'DES'], help='Encryption algorithm')
    parser.add_argument('mode', choices=['ECB', 'CBC'], help='Mode of operation')
    parser.add_argument('input_file', help='Input file path')
    parser.add_argument('output_file', help='Output file path')
    parser.add_argument('--key', help='Decryption key (hex format)', required=False)
    
    args = parser.parse_args()
    
    start_time = time.time()
    
    if args.action == 'encrypt':
        key = encrypt_file(args.algorithm, args.mode, args.input_file, args.output_file)
        print(f"Encryption key: {key.hex()}")
    else:
        if not args.key:
            print("Error: Decryption key is required")
            return
        key = bytes.fromhex(args.key)
        decrypt_file(args.algorithm, args.mode, args.input_file, args.output_file, key)
    
    end_time = time.time()
    print(f"Execution time: {end_time - start_time:.4f} seconds")

if __name__ == '__main__':
    main()

