#!/usr/bin/env python3
"""
Script para calcular hashes MD5, SHA-1 y SHA-256 de textos o archivos.
Autor: Sistema de Hash
Fecha: 2025
"""

import hashlib
import argparse
import sys
import os


def calcular_hash(data, algoritmo):
    """
    Calcula el hash de los datos usando el algoritmo especificado.
    
    Args:
        data (bytes): Datos a hashear
        algoritmo (str): Algoritmo a usar ('md5', 'sha1', 'sha256')
    
    Returns:
        str: Hash hexadecimal
    """
    if algoritmo == 'md5':
        hash_obj = hashlib.md5()
    elif algoritmo == 'sha1':
        hash_obj = hashlib.sha1()
    elif algoritmo == 'sha256':
        hash_obj = hashlib.sha256()
    else:
        raise ValueError(f"Algoritmo no soportado: {algoritmo}")
    
    hash_obj.update(data)
    return hash_obj.hexdigest()


def hash_desde_texto(texto, algoritmo):
    """
    Calcula el hash de un texto.
    
    Args:
        texto (str): Texto a hashear
        algoritmo (str): Algoritmo a usar
    
    Returns:
        str: Hash hexadecimal
    """
    data = texto.encode('utf-8')
    return calcular_hash(data, algoritmo)


def hash_desde_archivo(ruta_archivo, algoritmo):
    """
    Calcula el hash de un archivo.
    
    Args:
        ruta_archivo (str): Ruta del archivo
        algoritmo (str): Algoritmo a usar
    
    Returns:
        str: Hash hexadecimal
    """
    if not os.path.exists(ruta_archivo):
        raise FileNotFoundError(f"El archivo '{ruta_archivo}' no existe")
    
    if algoritmo == 'md5':
        hash_obj = hashlib.md5()
    elif algoritmo == 'sha1':
        hash_obj = hashlib.sha1()
    elif algoritmo == 'sha256':
        hash_obj = hashlib.sha256()
    else:
        raise ValueError(f"Algoritmo no soportado: {algoritmo}")
    
    # Leer archivo en bloques para manejar archivos grandes
    with open(ruta_archivo, 'rb') as f:
        while True:
            chunk = f.read(8192)  # Leer en bloques de 8KB
            if not chunk:
                break
            hash_obj.update(chunk)
    
    return hash_obj.hexdigest()


def main():
    """
    Función principal que maneja los argumentos de línea de comandos.
    """
    parser = argparse.ArgumentParser(
        description='Calculadora de hashes MD5, SHA-1 y SHA-256',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  # Calcular MD5 de un texto
  python hash.py -t "Hola Mundo" -a md5
  
  # Calcular SHA-256 de un archivo
  python hash.py -f documento.txt -a sha256
  
  # Calcular SHA-1 de un texto (algoritmo por defecto)
  python hash.py -t "Mi texto secreto"
  
  # Calcular todos los hashes de un archivo
  python hash.py -f imagen.jpg -a md5
  python hash.py -f imagen.jpg -a sha1
  python hash.py -f imagen.jpg -a sha256
"""
    )
    
    # Crear grupo mutuamente excluyente para texto o archivo
    grupo_entrada = parser.add_mutually_exclusive_group(required=True)
    grupo_entrada.add_argument(
        '-t', '--texto',
        type=str,
        help='Texto del cual calcular el hash'
    )
    grupo_entrada.add_argument(
        '-f', '--file',
        type=str,
        help='Archivo del cual calcular el hash'
    )
    
    # Argumento para el algoritmo
    parser.add_argument(
        '-a', '--algoritmo',
        type=str,
        choices=['md5', 'sha1', 'sha256'],
        default='sha256',
        help='Algoritmo de hash a utilizar (por defecto: sha256)'
    )
    
    # Argumento para mostrar información adicional
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Mostrar información detallada'
    )
    
    # Parsear argumentos
    args = parser.parse_args()
    
    try:
        # Procesar según el tipo de entrada
        if args.texto:
            hash_resultado = hash_desde_texto(args.texto, args.algoritmo)
            origen = f"Texto: \"{args.texto}\""
        else:
            hash_resultado = hash_desde_archivo(args.file, args.algoritmo)
            origen = f"Archivo: {args.file}"
        
        # Mostrar resultados
        if args.verbose:
            print("=" * 70)
            print(f"Calculadora de Hash")
            print("=" * 70)
            print(f"Origen:     {origen}")
            print(f"Algoritmo:  {args.algoritmo.upper()}")
            print(f"Hash:       {hash_resultado}")
            print("=" * 70)
        else:
            print(hash_resultado)
        
        return 0
    
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error inesperado: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
