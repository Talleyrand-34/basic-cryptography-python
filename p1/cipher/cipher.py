import argparse
import time
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def encrypt_file(algorithm, mode, input_file, output_file, key=None, iv=None, attach_iv=True):
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    if algorithm == 'AES':
        if key is None:
            key = get_random_bytes(32)  # 256-bit key for AES
        elif len(key) != 32:
            raise ValueError("AES key must be 32 bytes (256 bits)")
        
        if mode != 'ECB':
            if iv is None:
                iv = get_random_bytes(16)
            elif len(iv) != 16:
                raise ValueError(f"AES IV must be 16 bytes, got {len(iv)} bytes")
            cipher = AES.new(key, getattr(AES, f'MODE_{mode}'), iv)
        else:
            if iv is not None:
                raise ValueError("IV should not be provided for ECB mode")
            cipher = AES.new(key, AES.MODE_ECB)
            
    elif algorithm == 'DES':
        if key is None:
            key = get_random_bytes(8)  # 56-bit key for DES (8 bytes)
        elif len(key) != 8:
            raise ValueError("DES key must be 8 bytes")
        
        if mode != 'ECB':
            if iv is None:
                iv = get_random_bytes(8)
            elif len(iv) != 8:
                raise ValueError(f"DES IV must be 8 bytes, got {len(iv)} bytes")
            cipher = DES.new(key, getattr(DES, f'MODE_{mode}'), iv)
        else:
            if iv is not None:
                raise ValueError("IV should not be provided for ECB mode")
            cipher = DES.new(key, DES.MODE_ECB)
    
    ciphertext = cipher.encrypt(pad(plaintext, cipher.block_size))
    
    with open(output_file, 'wb') as f:
        if iv and mode != 'ECB' and attach_iv:
            f.write(iv)
        f.write(ciphertext)
    
    return key, iv

def decrypt_file(algorithm, mode, input_file, output_file, key, iv=None, hex_output=False):
    with open(input_file, 'rb') as f:
        if mode != 'ECB':
            if iv is None:
                # Read IV from file if not provided
                iv_size = 16 if algorithm == 'AES' else 8
                iv = f.read(iv_size)
                ciphertext = f.read()
            else:
                # Use provided IV, read all as ciphertext
                ciphertext = f.read()
        else:
            ciphertext = f.read()
            iv = None
    
    if algorithm == 'AES':
        cipher = AES.new(key, getattr(AES, f'MODE_{mode}'), iv) if mode != 'ECB' else AES.new(key, AES.MODE_ECB)
    elif algorithm == 'DES':
        cipher = DES.new(key, getattr(DES, f'MODE_{mode}'), iv) if mode != 'ECB' else DES.new(key, DES.MODE_ECB)
    
    plaintext = unpad(cipher.decrypt(ciphertext), cipher.block_size)
    
    if hex_output:
        with open(output_file, 'w') as f:
            f.write(plaintext.hex())
    else:
        with open(output_file, 'wb') as f:
            f.write(plaintext)

def main():
    parser = argparse.ArgumentParser(description='Encrypt or decrypt files using AES or DES')
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help='Action to perform')
    parser.add_argument('algorithm', choices=['AES', 'DES'], help='Encryption algorithm')
    parser.add_argument('mode', choices=['ECB', 'CBC'], help='Mode of operation')
    parser.add_argument('input_file', help='Input file path')
    parser.add_argument('output_file', help='Output file path')
    parser.add_argument('--key', help='Encryption/Decryption key (hex format)', required=False)
    parser.add_argument('--iv', help='Initialization Vector (hex format)', required=False)
    parser.add_argument('--hex-output', action='store_true', help='Output decrypted data in hexadecimal format')
    parser.add_argument('--no-attach-iv', action='store_true', help='Do not attach IV to the encrypted file')
    parser.add_argument('--iv-file', help='File to read/write IV separately', required=False)
    
    args = parser.parse_args()
    
    # Validate that IV is not provided for ECB mode
    if args.iv and args.mode == 'ECB':
        print("Error: IV should not be provided for ECB mode")
        return
    
    # Validate conflicting options
    if args.no_attach_iv and args.iv_file:
        print("Error: --no-attach-iv and --iv-file cannot be used together")
        return
    
    # Validate hex-output is only used for decryption
    if args.hex_output and args.action == 'encrypt':
        print("Warning: --hex-output is only applicable for decryption, ignoring for encryption")
    
    start_time = time.time()
    
    if args.action == 'encrypt':
        key = None
        iv = None
        
        if args.key:
            try:
                key = bytes.fromhex(args.key)
                print(f"Key length: {len(key)} bytes")
            except ValueError:
                print("Error: Invalid key format. Key must be in hexadecimal.")
                return
        
        if args.iv:
            try:
                iv = bytes.fromhex(args.iv)
                print(f"IV length: {len(iv)} bytes")
            except ValueError:
                print("Error: Invalid IV format. IV must be in hexadecimal.")
                return
        
        try:
            key, iv = encrypt_file(args.algorithm, args.mode, args.input_file, args.output_file, key, iv, not args.no_attach_iv)
            print(f"Encryption key: {key.hex()}")
            if args.mode != 'ECB':
                if args.no_attach_iv:
                    print("IV was not attached to file")
                    if args.iv_file:
                        with open(args.iv_file, 'wb') as f:
                            f.write(iv)
                        print(f"IV written to: {args.iv_file}")
                    else:
                        print(f"IV (save this!): {iv.hex()}")
                else:
                    print("IV was attached to file")
        except ValueError as e:
            print(f"Error: {e}")
            return
    
    else:  # decrypt
        if not args.key:
            print("Error: Decryption key is required")
            return
        
        try:
            key = bytes.fromhex(args.key)
            print(f"Key length: {len(key)} bytes")
        except ValueError:
            print("Error: Invalid key format. Key must be in hexadecimal.")
            return
        
        iv = None
        if args.iv:
            try:
                iv = bytes.fromhex(args.iv)
                print(f"IV length: {len(iv)} bytes")
            except ValueError:
                print("Error: Invalid IV format. IV must be in hexadecimal.")
                return
        elif args.iv_file:
            try:
                with open(args.iv_file, 'rb') as f:
                    iv = f.read()
                expected_iv_size = 16 if args.algorithm == 'AES' else 8
                if len(iv) != expected_iv_size:
                    print(f"Error: IV file must contain exactly {expected_iv_size} bytes for {args.algorithm}")
                    return
                print(f"IV read from file: {args.iv_file}")
            except FileNotFoundError:
                print(f"Error: IV file not found: {args.iv_file}")
                return
            except Exception as e:
                print(f"Error reading IV file: {e}")
                return
        
        try:
            decrypt_file(args.algorithm, args.mode, args.input_file, args.output_file, key, iv, args.hex_output)
            if args.hex_output:
                print("Output written in hexadecimal format")
        except ValueError as e:
            print(f"Error: {e}")
            return
    
    end_time = time.time()
    print(f"Execution time: {end_time - start_time:.4f} seconds")

if __name__ == '__main__':
    main()
