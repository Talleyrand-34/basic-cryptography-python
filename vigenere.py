import argparse
import os
import json

def read_file(filepath):
    with open(filepath, 'r') as file:
        return file.read().strip()

def vigenere_encrypt(plaintext, key):
    ciphertext = []
    key_length = len(key)
    
    for i, char in enumerate(plaintext):
        if char.isalpha():
            shift = ord(key[i % key_length]) - ord('A')
            encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            ciphertext.append(encrypted_char)
        else:
            ciphertext.append(char)
    
    return ''.join(ciphertext)

def vigenere_decrypt(ciphertext, key):
    plaintext = []
    key_length = len(key)
    
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            shift = ord(key[i % key_length]) - ord('A')
            decrypted_char = chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A'))
            plaintext.append(decrypted_char)
        else:
            plaintext.append(char)
    
    return ''.join(plaintext)

def print_help():
    help_message = """
    Vigenère Cipher Program
    ------------------------
    
    This program allows you to encrypt and decrypt messages using the Vigenère cipher.
    
    Parameters:
      - Enter '-e' to encrypt a message with file input.
      - Enter '-d' to decrypt a message with file input.
      - Enter '-E' to encrypt a message with args input.
      - Enter '-D' to decrypt a message with args input.
      - Enter '--key' specify a key to use.
    Commands interactive mode:
      - Enter 'e' to encrypt a message.
      - Enter 'd' to decrypt a message.
      - Enter 'q' to quit the program.
    
    Encryption Process:
      1. Input your plaintext (uppercase letters only).
      2. The program will encrypt your message using the specified key.
      3. The output will be your encrypted text.
      4. The encrypted text will be saved to a file named 'enc-out-N.txt', where N is an auto-incrementing number.

    Decryption Process:
      1. Input your ciphertext (uppercase letters only).
      2. The program will decrypt your message using the same key used for encryption.
      3. The output will be your decrypted text.
      4. The decrypted text will be saved to a file named 'dec-out-N.txt', where N is an auto-incrementing number.

    Note: 
      - The key should consist of uppercase letters.
      - Each encryption or decryption operation will create a new output file with an incremented number.
      - The counter for file naming is stored in a local 'counter.json' file.
    
    Enjoy using the Vigenère cipher!
    """
    print(help_message)

def get_next_id():
    filename = 'counter.json'
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            data = json.load(f)
            current_id = data['id']
    else:
        current_id = 0

    next_id = current_id + 1

    with open(filename, 'w') as f:
        json.dump({'id': next_id}, f)

    return next_id

def write_output(text, prefix):
    file_id = get_next_id()
    filename = f"./out-mono/{prefix}-out-{file_id}.txt"
    with open(filename, 'w') as f:
        f.write(text)
    print(f"Output written to {filename}")

def create_parser():
    parser = argparse.ArgumentParser(description='Vigenère Cipher Encryption/Decryption')
    
    parser.add_argument('-help', action='help', help='Show this help message and exit')
    parser.add_argument('-E', metavar='PLAINTEXT', type=str,
                        help='Encrypt the given plaintext (uppercase)')
    parser.add_argument('-D', metavar='CIPHERTEXT', type=str,
                        help='Decrypt the given ciphertext (uppercase)')
    parser.add_argument('-e', metavar='FILEPATH', type=str,
                        help='Encrypt the content of the given file')
    parser.add_argument('-d', metavar='FILEPATH', type=str,
                        help='Decrypt the content of the given file')
    parser.add_argument('--key', type=str, default='ARMOG',
                        help='Set the encryption/decryption key (default: ARMOG)')
    
    return parser

def main():
    parser = create_parser()
    args = parser.parse_args()
    key = args.key.upper()

    if args.E:
        plaintext = args.E.upper()
        ciphertext = vigenere_encrypt(plaintext, key)
        print("Encrypted text:", ciphertext)
        # write_output(ciphertext, "enc")
    elif args.D:
        ciphertext = args.D.upper()
        plaintext = vigenere_decrypt(ciphertext, key)
        print("Decrypted text:", plaintext)
        # write_output(plaintext, "dec")
    elif args.e:
        plaintext = read_file(args.e).upper()
        ciphertext = vigenere_encrypt(plaintext, key)
        print("Encrypted text:", ciphertext)
        write_output(ciphertext, "enc")
    elif args.d:
        ciphertext = read_file(args.d).upper()
        plaintext = vigenere_decrypt(ciphertext, key)
        print("Decrypted text:", plaintext)
        write_output(plaintext, "dec")
    else:
        choice = input("Enter 'e' for encryption or 'd' for decryption (q to quit) or 'help' for help: ")

        if choice == 'q':
            print("Bye")
        elif choice == 'help':
            print_help()
        elif choice == 'e':
            key = input("Enter the key: ")
        
            # Check if the key is empty and retain its original value if it is
            if key.strip() == "":
                print("Key is empty. Retaining original key.")
                # Optionally, you can set a default key here if needed
                # key = "DEFAULT_KEY"  # Uncomment to set a default key
            else:
                print("Key set to:", key)
            plaintext = input("Enter the plaintext (uppercase): ").upper()
            ciphertext = vigenere_encrypt(plaintext, key)
            print("Encrypted text:", ciphertext)
            # write_output(ciphertext, "enc")
        elif choice == 'd':
            key = input("Enter the key: ")
        
            # Check if the key is empty and retain its original value if it is
            if key.strip() == "":
                print("Key is empty. Retaining original key.")
                # Optionally, you can set a default key here if needed
                # key = "DEFAULT_KEY"  # Uncomment to set a default key
            else:
                print("Key set to:", key)
            ciphertext = input("Enter the ciphertext (uppercase): ").upper()
            plaintext = vigenere_decrypt(ciphertext, key)
            print("Decrypted text:", plaintext)
            # write_output(plaintext, "dec")
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
