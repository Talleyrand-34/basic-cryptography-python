#!/usr/bin/env python3

import argparse
import sys
import time
import sys

# RC4 implementation (unchanged)
state = [None] * 256
p = q = None

def setKey(key):
    global p, q, state
    state = [n for n in range(256)]
    p = q = j = 0
    for i in range(256):
        if len(key) > 0:
            j = (j + state[i] + key[i % len(key)]) % 256
        else:
            j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]

def byteGenerator():
    global p, q, state
    p = (p + 1) % 256
    q = (q + state[p]) % 256
    state[p], state[q] = state[q], state[p]
    return state[(state[p] + state[q]) % 256]

def encrypt(inputString):
    encrypted = []
    output = list(inputString)  
    
    for i, p in enumerate(inputString):
        byte = ord(p) ^ byteGenerator()
        encrypted.append(byte)

        output[i] = f'{byte:02x}'
        
        sys.stdout.write('\r' + ''.join(output))  
        sys.stdout.flush()
        time.sleep(0.5) #change value to inc/decr speed
    
    sys.stdout.write('\n') 
    return encrypted

def decrypt(inputByteList):
    return "".join([chr(c ^ byteGenerator()) for c in inputByteList])

# New main function with CLI options
def main():
    parser = argparse.ArgumentParser(description="RC4 encryption/decryption tool")
    parser.add_argument("-k", "--key", required=True, help="Encryption/decryption key")
    parser.add_argument("-f", "--file", help="Input file (if not specified, read from stdin)")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt mode (default is encrypt)")
    args = parser.parse_args()

    # Set the key
    setKey([ord(c) for c in args.key])

    # Read input
    if args.file:
        with open(args.file, 'r') as f:
            input_data = f.read()
    else:
        input_data = sys.stdin.read()

    # Process data
    if args.decrypt:
        # Assuming input is hex-encoded for decryption
        input_bytes = bytes.fromhex(input_data.strip())
        result = decrypt(input_bytes)
        print(result)
    else:
        result = encrypt(input_data)
        print(''.join(f'{b:02x}' for b in result))

if __name__ == '__main__':
    main()
