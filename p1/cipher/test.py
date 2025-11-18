from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Exact same parameters as your command
key = bytes.fromhex('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
iv = bytes.fromhex('00000000000000000000000000000000')

# Read your file
with open('secreto.txt', 'rb') as f:
    plaintext = f.read()

print("Input data:", repr(plaintext))

# Manual encryption
cipher = AES.new(key, AES.MODE_CBC, iv)
padded = pad(plaintext, 16)
ciphertext = cipher.encrypt(padded)

print("Ciphertext (first 16 bytes hex):", ciphertext[:16].hex())
