#!/usr/bin/env python3
"""
cipher.py - Cifrado y descifrado de archivos usando AES o DES
Implementación compatible con OpenSSL usando PyCryptodome
"""

import argparse
import sys
import time
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def validate_key(key_hex, algorithm):
    """Valida que la clave tenga la longitud correcta para el algoritmo"""
    if not key_hex:
        return None
        
    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError:
        raise ValueError("La clave debe estar en formato hexadecimal")
    
    if algorithm.upper() == 'DES':
        if len(key_bytes) != 8:  # DES usa claves de 64 bits (8 bytes)
            raise ValueError(f"DES requiere una clave de 64 bits (16 caracteres hex). Recibido: {len(key_bytes)*8} bits")
    elif algorithm.upper() == 'AES':
        if len(key_bytes) not in [16, 24, 32]:  # AES-128, AES-192, AES-256
            raise ValueError(f"AES requiere una clave de 128, 192 o 256 bits. Recibido: {len(key_bytes)*8} bits")
    
    return key_bytes


def validate_iv(iv_hex, algorithm):
    """Valida que el IV tenga la longitud correcta"""
    if not iv_hex:
        return None
        
    try:
        iv_bytes = bytes.fromhex(iv_hex)
    except ValueError:
        raise ValueError("El IV debe estar en formato hexadecimal")
    
    if algorithm.upper() == 'DES':
        if len(iv_bytes) != 8:  # DES usa bloques de 64 bits
            raise ValueError(f"DES requiere un IV de 64 bits (16 caracteres hex). Recibido: {len(iv_bytes)*8} bits")
    elif algorithm.upper() == 'AES':
        if len(iv_bytes) != 16:  # AES usa bloques de 128 bits
            raise ValueError(f"AES requiere un IV de 128 bits (32 caracteres hex). Recibido: {len(iv_bytes)*8} bits")
    
    return iv_bytes


def encrypt_file(algorithm, mode, input_file, output_file, key=None, iv=None):
    """Cifra un archivo usando el algoritmo y modo especificados"""
    
    # Leer el archivo de entrada
    try:
        with open(input_file, 'rb') as f:
            plaintext = f.read()
    except FileNotFoundError:
        print(f"Error: El archivo '{input_file}' no existe", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error al leer el archivo: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Generar clave aleatoria si no se proporciona
    if key is None:
        if algorithm.upper() == 'AES':
            key = get_random_bytes(32)  # AES-256
        elif algorithm.upper() == 'DES':
            key = get_random_bytes(8)   # DES
        print(f"Clave generada: {key.hex()}")
    
    # Generar IV aleatorio si es necesario y no se proporciona
    if mode.upper() == 'CBC' and iv is None:
        if algorithm.upper() == 'AES':
            iv = get_random_bytes(16)
        elif algorithm.upper() == 'DES':
            iv = get_random_bytes(8)
        print(f"IV generado: {iv.hex()}")
    
    # Crear el cifrador según el algoritmo y modo
    try:
        if algorithm.upper() == 'DES':
            block_size = DES.block_size
            if mode.upper() == 'ECB':
                cipher = DES.new(key, DES.MODE_ECB)
            else:  # CBC
                if iv is None:
                    raise ValueError("El modo CBC requiere un IV")
                cipher = DES.new(key, DES.MODE_CBC, iv)
        
        elif algorithm.upper() == 'AES':
            block_size = AES.block_size
            if mode.upper() == 'ECB':
                cipher = AES.new(key, AES.MODE_ECB)
            else:  # CBC
                if iv is None:
                    raise ValueError("El modo CBC requiere un IV")
                cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Aplicar padding y cifrar
        padded_plaintext = pad(plaintext, block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        
        # Escribir el archivo cifrado (solo el ciphertext, sin IV)
        with open(output_file, 'wb') as f:
            f.write(ciphertext)
        
        print(f"✓ Archivo cifrado exitosamente: {output_file}")
        print(f"  Algoritmo: {algorithm.upper()}, Modo: {mode.upper()}")
        print(f"  Tamaño original: {len(plaintext)} bytes")
        print(f"  Tamaño cifrado: {len(ciphertext)} bytes")
        
        return key, iv
        
    except Exception as e:
        print(f"Error durante el cifrado: {e}", file=sys.stderr)
        sys.exit(1)


def decrypt_file(algorithm, mode, input_file, output_file, key, iv=None):
    """Descifra un archivo usando el algoritmo y modo especificados"""
    
    # Leer el archivo cifrado
    try:
        with open(input_file, 'rb') as f:
            ciphertext = f.read()
    except FileNotFoundError:
        print(f"Error: El archivo '{input_file}' no existe", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error al leer el archivo: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Crear el descifrador según el algoritmo y modo
    try:
        if algorithm.upper() == 'DES':
            block_size = DES.block_size
            if mode.upper() == 'ECB':
                cipher = DES.new(key, DES.MODE_ECB)
            else:  # CBC
                if iv is None:
                    raise ValueError("El modo CBC requiere un IV")
                cipher = DES.new(key, DES.MODE_CBC, iv)
        
        elif algorithm.upper() == 'AES':
            block_size = AES.block_size
            if mode.upper() == 'ECB':
                cipher = AES.new(key, AES.MODE_ECB)
            else:  # CBC
                if iv is None:
                    raise ValueError("El modo CBC requiere un IV")
                cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Descifrar y quitar padding
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, block_size)
        
        # Escribir el archivo descifrado
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        
        print(f"✓ Archivo descifrado exitosamente: {output_file}")
        print(f"  Algoritmo: {algorithm.upper()}, Modo: {mode.upper()}")
        print(f"  Tamaño cifrado: {len(ciphertext)} bytes")
        print(f"  Tamaño descifrado: {len(plaintext)} bytes")
        
    except ValueError as e:
        if "Padding is incorrect" in str(e):
            print("Error: Padding incorrecto. Verifique que la clave y el IV sean correctos.", file=sys.stderr)
        else:
            print(f"Error durante el descifrado: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error durante el descifrado: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    # Crear el parser de argumentos
    parser = argparse.ArgumentParser(
        description='Encrypt or decrypt files using AES or DES',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:

  # Encrypt with DES in ECB mode
  python3 cipher.py encrypt DES ECB secreto.txt secreto.enc --key 133457799BBCDFF1

  # Encrypt with DES in CBC mode
  python3 cipher.py encrypt DES CBC secreto.txt secreto.enc \\
      --key 133457799BBCDFF1 --iv 0102030405060708

  # Encrypt with AES-256 in ECB mode
  python3 cipher.py encrypt AES ECB secreto.txt secreto.enc \\
      --key 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4

  # Encrypt with AES-256 in CBC mode
  python3 cipher.py encrypt AES CBC secreto.txt secreto.enc \\
      --key 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 \\
      --iv 000102030405060708090a0b0c0d0e0f

  # Decrypt
  python3 cipher.py decrypt AES CBC secreto.enc recuperado.txt \\
      --key 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 \\
      --iv 000102030405060708090a0b0c0d0e0f

Key and IV requirements:
  DES:     64-bit key  (16 hex chars), 64-bit IV  (16 hex chars)
  AES-128: 128-bit key (32 hex chars), 128-bit IV (32 hex chars)
  AES-192: 192-bit key (48 hex chars), 128-bit IV (32 hex chars)
  AES-256: 256-bit key (64 hex chars), 128-bit IV (32 hex chars)
        """
    )
    
    # Argumentos posicionales
    parser.add_argument('action', 
                       choices=['encrypt', 'decrypt'],
                       help='Action to perform')
    parser.add_argument('algorithm',
                       choices=['AES', 'DES'],
                       help='Encryption algorithm')
    parser.add_argument('mode',
                       choices=['ECB', 'CBC'],
                       help='Mode of operation')
    parser.add_argument('input_file',
                       help='Input file path')
    parser.add_argument('output_file',
                       help='Output file path')
    
    # Argumentos opcionales
    parser.add_argument('--key',
                       help='Decryption key (hex format)')
    parser.add_argument('--iv',
                       help='Input vector (hex format)')
    
    # Parsear argumentos
    args = parser.parse_args()
    
    # Para descifrado, la clave es obligatoria
    if args.action == 'decrypt' and not args.key:
        parser.error("decrypt requiere el parámetro --key")
    
    # Para CBC en descifrado, el IV es obligatorio
    if args.action == 'decrypt' and args.mode.upper() == 'CBC' and not args.iv:
        parser.error("decrypt con modo CBC requiere el parámetro --iv")
    
    # Validar que ECB no use IV
    if args.mode.upper() == 'ECB' and args.iv is not None:
        print("Advertencia: El modo ECB no utiliza IV, el parámetro será ignorado", file=sys.stderr)
        args.iv = None
    
    # Validar y convertir clave e IV
    try:
        key = validate_key(args.key, args.algorithm)
        iv = validate_iv(args.iv, args.algorithm) if args.iv else None
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Medir tiempo de ejecución
    start_time = time.time()
    
    # Ejecutar la acción correspondiente
    if args.action == 'encrypt':
        returned_key, returned_iv = encrypt_file(
            args.algorithm, args.mode, args.input_file, 
            args.output_file, key, iv
        )
        if key is None:
            print(f"\nGuarde estos valores para descifrar:")
            print(f"  --key {returned_key.hex()}")
            if returned_iv:
                print(f"  --iv {returned_iv.hex()}")
    else:  # decrypt
        decrypt_file(args.algorithm, args.mode, args.input_file, 
                    args.output_file, key, iv)
    
    end_time = time.time()
    print(f"\nTiempo de ejecución: {end_time - start_time:.4f} segundos")


if __name__ == '__main__':
    main()
