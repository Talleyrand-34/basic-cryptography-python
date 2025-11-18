import argparse
import os
import json

def read_file(filepath):
    with open(filepath, 'r') as file:
        return file.read().strip()
def create_playfair_matrix(key):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    key = "".join(dict.fromkeys(key.upper().replace("J", "I") + alphabet))
    matrix = [key[i:i+5] for i in range(0, 25, 5)]
    return matrix

def find_position(matrix, char):
    for i, row in enumerate(matrix):
        if char in row:
            return i, row.index(char)
    return -1, -1

def playfair_encrypt(plaintext, key):
    matrix = create_playfair_matrix(key)
    plaintext = plaintext.upper().replace("J", "I")
    ciphertext = ""
    
    for i in range(0, len(plaintext), 2):
        pair = plaintext[i:i+2]
        if len(pair) == 1:
            pair += "X"
        elif pair[0] == pair[1]:
            pair = pair[0] + "X"
        
        row1, col1 = find_position(matrix, pair[0])
        row2, col2 = find_position(matrix, pair[1])
        
        if row1 == row2:
            ciphertext += matrix[row1][(col1+1)%5] + matrix[row2][(col2+1)%5]
        elif col1 == col2:
            ciphertext += matrix[(row1+1)%5][col1] + matrix[(row2+1)%5][col2]
        else:
            ciphertext += matrix[row1][col2] + matrix[row2][col1]
    
    return ciphertext

def playfair_decrypt(ciphertext, key):
    matrix = create_playfair_matrix(key)
    plaintext = ""
    
    for i in range(0, len(ciphertext), 2):
        pair = ciphertext[i:i+2]
        row1, col1 = find_position(matrix, pair[0])
        row2, col2 = find_position(matrix, pair[1])
        
        if row1 == row2:
            plaintext += matrix[row1][(col1-1)%5] + matrix[row2][(col2-1)%5]
        elif col1 == col2:
            plaintext += matrix[(row1-1)%5][col1] + matrix[(row2-1)%5][col2]
        else:
            plaintext += matrix[row1][col2] + matrix[row2][col1]
    
    return plaintext

def print_help():
    help_message = """
    Playfair Cipher Program
    ------------------------
    
    This program allows you to encrypt and decrypt messages using the Playfair cipher.
    
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
      1. Input your plaintext (uppercase letters only, no spaces).
      2. The program will encrypt your message using the specified key.
      3. If there are duplicate letters in a pair, an 'X' will be added.
      4. The output will be your encrypted text.
      5. (Optional file mode) The encrypted text will be saved to a file named 'enc-out-N.txt', where N is an auto-incrementing number.

    Decryption Process:
      1. Input your ciphertext (uppercase letters only).
      2. The program will decrypt your message using the same key used for encryption.
      3. The output will be your decrypted text.
      4. (Optional file mode) The decrypted text will be saved to a file named 'dec-out-N.txt', where N is an auto-incrementing number.

    Note: 
      - The key should consist of uppercase letters and will be used to create a Playfair matrix.
      - Each encryption or decryption operation will create a new output file with an incremented number.
      - The counter for file naming is stored in a local 'counter.json' file.
    
    Example Key: "MONAR"
    
    Enjoy using the Playfair cipher!
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
    parser = argparse.ArgumentParser(description='Playfair Cipher Encryption/Decryption')
    
    parser.add_argument('-help', action='help', help='Show this help message and exit')
    parser.add_argument('-E', metavar='PLAINTEXT', type=str,
                        help='Encrypt the given plaintext (uppercase, no spaces)')
    parser.add_argument('-D', metavar='CIPHERTEXT', type=str,
                        help='Decrypt the given ciphertext (uppercase)')
    parser.add_argument('-e', metavar='FILEPATH', type=str,
                        help='Encrypt the content of the given file')
    parser.add_argument('-d', metavar='FILEPATH', type=str,
                        help='Decrypt the content of the given file')
    parser.add_argument('--key', type=str, default='MONAR',
                        help='Set the encryption/decryption key (default: MONAR)')
    
    return parser

def main():
    parser = create_parser()
    args = parser.parse_args()
    key = args.key

    if args.E:
        plaintext = args.E
        ciphertext = playfair_encrypt(plaintext, key)
        print("Encrypted text:", ciphertext)
        # write_output(ciphertext, "enc")
    elif args.D:
        ciphertext = args.D
        plaintext = playfair_decrypt(ciphertext, key)
        print("Decrypted text:", plaintext)
        # write_output(plaintext, "dec")
    elif args.e:
        plaintext = read_file(args.e)
        ciphertext = playfair_encrypt(plaintext, key)
        print("Encrypted text:", ciphertext)
        write_output(ciphertext, "enc")
    elif args.d:
        ciphertext = read_file(args.d)
        plaintext = playfair_decrypt(ciphertext, key)
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
            plaintext = input("Enter the plaintext (uppercase, no spaces): ")
            ciphertext = playfair_encrypt(plaintext, key)
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
            ciphertext = input("Enter the ciphertext (uppercase): ")
            plaintext = playfair_decrypt(ciphertext, key)
            print("Decrypted text:", plaintext)
            # write_output(plaintext, "dec")
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
