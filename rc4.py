#!/usr/bin/env python3

import argparse
import sys
import time

# RC4 implementation
state = [None] * 256
p = q = None

def setKey(key):
    global p, q, state
    state = [n for n in range(256)]
    p = q = j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) % 256
        state[i], state[j] = state[j], state[i]

def byteGenerator():
    global p, q, state
    p = (p + 1) % 256
    q = (q + state[p]) % 256
    state[p], state[q] = state[q], state[p]
    return state[(state[p] + state[q]) % 256]

def encrypt(inputString):
    encrypted = []
    
    for char in inputString:
        byte = ord(char)
        keystream_byte = byteGenerator()
        encrypted_byte = byte ^ keystream_byte
        
        # Displaying the required information
        print(f"Character: '{char}' | ASCII: {byte} | Binary: {byte:08b}")
        print(f"Keystream: {keystream_byte} | Binary: {keystream_byte:08b}")
        print(f"Encrypted Byte: {encrypted_byte} | Binary: {encrypted_byte:08b} | Hex: {encrypted_byte:02x}\n")
        
        encrypted.append(encrypted_byte)
        
        # Simulate typing effect
        time.sleep(0.5)  # Adjust speed here
    
    return encrypted

def decrypt(inputByteList):
    return "".join([chr(c ^ byteGenerator()) for c in inputByteList])

# New main function with CLI options
def main():
    parser = argparse.ArgumentParser(description="RC4 encryption tool")
    parser.add_argument("-k", "--key", required=True, help="Hexadecimal encryption key")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt mode (default is encrypt)")
    args = parser.parse_args()

    # Convert hex key to bytes
    try:
        key_bytes = bytes.fromhex(args.key)
    except ValueError as e:
        print(f"Error decoding key: {e}")
        sys.exit(1)

    # Set the key
    setKey(key_bytes)

    print("RC4 Encryption Tool")
    print("Type your text to encrypt (type 'exit' to quit):")

    #if -d is present choose between encrypting or decrypt
    if args.decrypt:
        # Assuming input is hex-encoded for decryption
        # input_data = sys.stdin.read()
        input_data = input("Input hex-encoded text to decrypt: ")
        input_bytes = bytes.fromhex(input_data.strip())
        result = decrypt(input_bytes)
        print(result)
    else:
        while True:
            input_data = input("Input: ")
            
            if input_data.lower() == 'exit':
                print("Exiting the program.")
                break
            
            encrypted_result = encrypt(input_data)
            
            # Final output of encrypted text in hex format after all characters are processed
            print("Encrypted text (hex):", ''.join(f'{b:02x}' for b in encrypted_result))


if __name__ == '__main__':
    main()
