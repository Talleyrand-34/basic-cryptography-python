#!/usr/bin/env python3
"""
monoalfabeto.py – Cifrado y descifrado por sustitución mono‑alfabética.

Uso:
    monoalfabeto.py  -e | -d  --input <archivo>  --key <clave>  --output <archivo>
    monoalfabeto.py  --help

Opciones:
    -e, --encrypt          Cifrar el archivo de entrada.
    -d, --decrypt          Descifrar el archivo de entrada.
    --input <archivo>      Ruta del archivo a procesar.
    --output <archivo>     Ruta donde se guardará el resultado.
    --key <clave>          Clave para codificar el archivo.
    --help                 Muestra esta ayuda y termina.
"""

import sys        # se usa para escribir mensajes de error y terminar el proceso con códigos de salida
import argparse   # gestiona la interpretación de los argumentos de la línea de comandos

ALFABETO = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" # letras permitidas (SOLO MAYÚSCULAS)
CLAVE_FIJA = "WZXCVBNMERTPASDFGHJQYUIOKL"
# Clave usuario: TPASDFGHJQYUIOKLWZXCVBNMER


# Verifica que la clave tenga la longitud correcta (26 caracteres)
# Comprueba que contenga exactamente las mismas letras que ALFABETO, sin duplicados ni faltantes
# Si alguna condición falla lanza ValueError, lo que detendrá la ejecución antes de procesar datos
def validar_clave(clave: str) -> None:
    """Comprueba que la clave sea una permutación válida del alfabeto."""
    if len(clave) != len(ALFABETO):
        raise ValueError(f"La clave debe tener {len(ALFABETO)} caracteres.")
    if set(clave) != set(ALFABETO):
        raise ValueError("La clave debe contener exactamente los mismos caracteres que el alfabeto, sin repeticiones.")


# Genera dos mapeos (diccionarios) que permiten traducir en ambas direcciones
# Se construyen mediante zip que empareja cada posición del alfabeto con la posición correspondiente de la clave
def crear_tablas(clave: str):
    """Devuelve dos diccionarios: codificador y decodificador."""
    codificador = {orig: sust for orig, sust in zip(ALFABETO, clave)}       # cifrar
    decodificador = {sust: orig for orig, sust in zip(ALFABETO, clave)}     # descifrar
    return codificador, decodificador


# Convierte todo el texto a mayúsculas (texto.upper())
# Recorre carácter por carácter:
# Si el carácter no pertenece a ALFABETO, lanza ValueError
# Si es válido, busca su sustituto en tabla (puede ser la tabla de cifrado o la de descifrado) y lo agrega a la lista resultado
# Finalmente une la lista en una única cadena y la devuelve
def procesar_texto(texto: str, tabla: dict) -> str:
    """Aplica la tabla de sustitución a todo el texto."""
    resultado = []
    for ch in texto.upper():
        if ch not in ALFABETO:
            raise ValueError(f"Carácter no permitido: '{ch}'. Solo se admiten los del alfabeto.")
        resultado.append(tabla[ch])
    return "".join(resultado)


# Abre el archivo indicado en modo lectura ("r"), usando UTF‑8
# Lee todo su contenido y elimina espacios en blanco iniciales y finales con .strip()
# Devuelve la cadena leída
def leer_archivo(ruta: str) -> str:
    with open(ruta, "r", encoding="utf-8") as f:
        return f.read().strip()


# Abre (crea o sobrescribe) el archivo destino en modo escritura ("w")
# Escribe la cadena contenido tal cual, usando UTF‑8
def escribir_archivo(ruta: str, contenido: str) -> None:
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(contenido)


# ArgumentParser: define las opciones de línea de comandos
# Parseo: parser.parse_args() convierte los argumentos recibidos en un objeto args
# Ayuda: si --help está presente, imprime el docstring completo y termina
# Validación de obligatoriedad: asegura que --input y --output se hayan provisto (excepto cuando solo se pide ayuda)
# Validación de la clave: llama a validar_clave para garantizar que la constante CLAVE_FIJA sea correcta
# Creación de tablas: genera los diccionarios de cifrado y descifrado
# Lectura del archivo: obtiene el texto original del archivo de entrada
# Procesamiento: según si --encrypt está activo, usa la tabla de cifrado; de lo contrario, asume descifrado (el script trata -d como implícito cuando -e no está)
# Escritura del archivo: guarda el texto transformado en la ruta indicada por --outpu
# Mensaje final: informa al usuario que la operación terminó y dónde está el archivo resultante
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cifrado/descifrado monoalfabético",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,             
    )

    # Modo (cifrar / descifrar) – obligatorio
    grupo_modo = parser.add_mutually_exclusive_group(required=False)
    grupo_modo.add_argument("-e", "--encrypt", action="store_true", help="Cifrar")
    grupo_modo.add_argument("-d", "--decrypt", action="store_true", help="Descifrar")

    # Argumentos que no son obligatorios en el parseo
    parser.add_argument("--input", help="Archivo de entrada")
    parser.add_argument("--output", help="Archivo de salida")
    parser.add_argument("--help", action="store_true", help="Muestra esta ayuda y termina")

    parser.add_argument(
        "--key", type=str,
        metavar="CLAVE",
        help=(
            "Clave de sustitución (26 caracteres). "
            "Si no se indica, se usará la clave fija definida en el script."
        ),
    )


    args = parser.parse_args()
    # Si se pidió ayuda, la mostramos y terminamos sin validar nada más
    if args.help:
        print(__doc__)          # muestra la cadena de documentación completa
        sys.exit(0)



    # Verificamos que los argumentos obligatorios estén presentes (solo cuando NO estamos en modo ayuda)
    if not args.input or not args.output:
        sys.stderr.write(
            "Error: los parámetros --input y --output son obligatorios cuando se ejecuta el cifrado/descifrado.\n"
            "Utilice '--help' para ver la sintaxis completa.\n"
        )
        sys.exit(1)

    # Validar clave (si el usuario no indica ninguna, se pone la que tenemos por defecto)
    try:
        if args.key:                     # el usuario proporcionó una clave
            validar_clave(args.key)      # valida la clave recibida
            clave_a_usar = args.key
        else:                            # usamos la clave fija del programa
            validar_clave(CLAVE_FIJA)
            clave_a_usar = CLAVE_FIJA
    except ValueError as e:
        sys.stderr.write(f"Error en la clave: {e}\n")
        sys.exit(1)

    # Crear tablas de sustitución (una para cifrar, otra para descifrar)
    codif, decod = crear_tablas(clave_a_usar)

    # Leer archivo de entrada
    try:
        texto_original = leer_archivo(args.input)
    except Exception as e:
        sys.stderr.write(f"No se pudo leer el archivo de entrada: {e}\n")
        sys.exit(1)

    # Procesar según el modo seleccionado
    try:
        if args.encrypt:
            texto_resultado = procesar_texto(texto_original, codif)
        else:
            texto_resultado = procesar_texto(texto_original, decod)
    except ValueError as e:
        sys.stderr.write(f"Error durante el procesamiento: {e}\n")
        sys.exit(1)

    # Guardar el resultado
    try:
        escribir_archivo(args.output, texto_resultado)
    except Exception as e:
        sys.stderr.write(f"No se pudo escribir el archivo de salida: {e}\n")
        sys.exit(1)

    print(f"{'Cifrado' if args.encrypt else 'Descifrado'} completado con clave {args.key}. Archivo guardado en: {args.output}")

# Garantiza que main() se ejecute sólo cuando el script se invoque directamente (python monoalfabeto.py …). Si el archivo se importa como módulo, el bloque no se ejecuta
if __name__ == "__main__":
    main()