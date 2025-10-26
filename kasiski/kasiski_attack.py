#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# =========================================================
#
# >> Author: adrian.pardo.martinez@udc.es | ApardoO
# >> Author: alba.gdoel@udc.es | albagdoel
# >> Author: r.d.gmantuano@udc.es |Talleyrand-34
#
# =========================================================
#
# >> Desc. general:
#     Según el método de Kasinski, empleando unos sencillos
#     pasos podremos romper el cifrado de Vigenère.
#
# =========================================================
#
# 1. Obtención del contenido a analizar
# 2. Limpiar el texto de caracteres que no aparezcan en el
#      alfabeto del idioma seleccionado
# 3. Encontrar subcriptogramas repetidos (Kasiski)
# 4. Factorización de todas las distancias / conteo de
#      divisores.
# 5. Cálculo de MCDs por pares (para diagnóstico)
# 6. Sugerir longitudes de claves canidatas
# 7. Recuperar la clave por análisis de frecuencias
# 8. Reconstruir y descifrar el texto
#
# =========================================================

import os                          # Comprobación de los archivos + I/O en el FS
import sys                         # Llamadas al sistema
import signal                      # Control del teclado con señales unix
import argparse                    # Control de los argumentos de entrada del usuario
import unicodedata                 # Normalización del texto a analizar

from math import gcd               # Función para el cálculo del MCD

from functools import reduce       # Calcula el MCD de varias distancias
from itertools import combinations # Hace la combinacion de un iterable (p.e. MCD de pares de distancias)
from collections import Counter    # Contar la frecuencia de letras en una columna de Vigenère y luego el cuadrado


# =========================================================
# >>> Variables globales del aplicativo
# =========================================================

# Alfabetos + frecuencias de los caracteres de los alfabetos usables
alphabets = {
	"es": {
		'A': 12.53, 'B': 1.42, 'C': 4.68, 'D': 5.86, 'E': 13.68, 'F': 0.69,
		'G':  1.01, 'H': 0.70, 'I': 6.25, 'J': 0.44, 'K':  0.01, 'L': 4.97,
		'M':  3.15, 'N': 6.71, 'O': 8.68, 'P': 2.51, 'Q':  0.88, 'R': 6.87,
		'S':  7.98, 'T': 4.63, 'U': 3.93, 'V': 1.14, 'W':  0.02, 'X': 0.22,
		'Y':  0.90, 'Z': 0.52
	}
}


# =========================================================
# >>> Interpretación de las señales del usuario
# =========================================================

# Ejecución de una salida de programa no exitosa con Ctrl+C
def sig_handler(sig, frame):
	print("\n\n[!] Saliendo...\n")
	sys.exit(0)

signal.signal(signal.SIGINT, sig_handler)


# =========================================================
# >>> Funcionalidades del programa
# =========================================================

# 1. Obtención del contenido a analizar
#    Lee el contenido de un archivo de texto y lo devuelve como cadena.
#    Si el archivo no existe o hay errores, devuelve cadenavacía.
def get_file_content(path:str="") -> str:
	# Comprobamos los parámetros de entrada
	if path == "" or not os.path.exists(path):
		raise AttributeError(f"The file {path} does not exist!")

	# Obtenemos el contenido del archivo
	with open(path, "r", encoding="utf-8") as f:
		content = f.read()

	return content


# 2. Limpiar el texto de caracteres que no aparezcan en el alfabeto del idioma seleccionado
#    Limpia el texto dejando solo letras comprendidas entre la primera y la última del abecedario dado.
#    Devuelve el texto limpio.
def sanitize_text(text:str="", first_ch:str='A', last_ch:str='Z') -> str:
	# Comprobación de los parámetros de entrada
	if text == "": return ""

	# Normalizamos el texto a "NFD": separa letras y acentos
	text = unicodedata.normalize("NFD", text)

	# Quitamos los acentos
	text = "".join(ch for ch in text if unicodedata.category(ch) != "Mn")

	# Convertimos todo a mayúsculas
	text = text.upper()

	# Filtramos solo las letras A-Z (es)
	text = "".join(ch for ch in text if first_ch <= ch <= last_ch)

	# Retornamos el texto sanitizado
	return text


# 3. Encontrar subcriptogramas repetidos (Kasiski)
#    Busca secuencias repetidas en el texto de longitud entre min_len y max_len.
#    Devuelve un diccionario:
#    	{'SEQ': [pos1, pos2, pos3], ...}
#    donde 'SEQ' es la secuencia repetida y los valores son las posiciones donde aparece.
def find_repeated_subcrypthographs(text:str="", min_len:int=3, max_len:int=3) -> dict[str, list[int]]:
	# Comprobamos los parámetros de entrada
	if text == "": return {}

	# Diccionario para los resultados
	repeated = {}

	text_lenght = len(text)

	# Para todas las longitudes de los subcriptogramas posibles
	for curr_len in range(min_len, max_len+1):
		# Recorremos todo el texto generando subcriptogramas de longitud "curr_len"
		for i in range(text_lenght - curr_len+1):
			# Obtenemos el subcriptograma actual
			sub = text[i:i + curr_len]

			# Si el subcriptograma se encuentra ya almacenada, solo añadimos la posición actual
			if sub in repeated:
				repeated[sub].append(i)
			else:
				# Para no añadir secuencias repetidas
				# Solo la añadimos si aparece más adelante
				if text[i+1:].find(sub) != -1:
					repeated[sub] = [i]

	# Retornamos el diccionario de subcriptogramas repetidos + sus posiciones
	return repeated


# 4. Factorización de todas las distancias / conteo de divisores.
#    Para cada distancia calcula sus divisores y cuenta cuántas veces aparece cada uno.
#    Devuelve:
# 	   - Un diccionario con el conteo de divisores: {divisor: frecuencia}
# 	   - Un diccionario con los divisores por distancia: {distancia: [divisores]}
def factorize_distances(distances:list=[]) -> tuple[dict[int, int], dict[int, list[int]]]:
	divisors_counts = {}        # Cuantas veces aparece un factor como factor de distancias
	divisors_per_distances = {} # Factor de cada distacia

	# Por cada distancia
	for d in distances:
		divisors = []

		# Obtenemos todos los factores del divisor
		for i in range(2, d+1):
			# Si es un factor se añade
			if d % i == 0:
				divisors.append(i)

				# Se incrementa en 1, si el factori se ha repetido
				divisors_counts[i] = divisors_counts.get(i, 0) +1

		# Añadimos la distancia factorizada al diccionario
		divisors_per_distances[d] = divisors

	return divisors_counts, divisors_per_distances


# 5. Cálculo de MCDs por pares (para diagnóstico)
#    Calcula el MCD de cada par de distancias.
#    Devuelve un diccionario con los MCD y cuántas veces se repiten:
#    	{mcd: frecuencia}
def mcd_by_pairs(distances:list=[]) -> dict[int, int]:
	mcd_counts = {}

	# Recorremos todas las combinaciones de pares de las distancias proporcionadas
	for a, b in combinations(distances, 2):
		m = gcd(a, b) # MCD de a y b
		if m > 1:     # Ignoramos MCD=1, no aporta información adicional a la clave
			mcd_counts[m] = mcd_counts.get(m, 0) +1

	# Retornamos los mcd obtenidos
	return mcd_counts


# 6. Sugerir longitudes de claves canidatas
#    A partir del MCD global, divisores frecuentes y MCD por partes,
#      sugiere posibles longitudes de clave.
#      Devuelve una lista de enteros con las longitudes candidatas.
def suggest_key_length(distances:list=[], min_ration:float=0.25, max_len:int=30) -> list[int]:
	# Comprobamos los parámetros de entrada
	if not distances: return []
	distances_length = len(distances)

	# 1. MCD global
	mcd_global = reduce(gcd, distances)

	# 2. Divisores frecuentes
	factor_counts, _ = factorize_distances(distances)
	mcd_pairs_counts = mcd_by_pairs(distances)

	# 3. Combinar longitudes candidatas: MCD global, divisores frecuentes y MCD por partes
	candidates = set()
	if mcd_global > 1 and mcd_global <= max_len:
		candidates.add(mcd_global)

	# >> Divisores frecuentes
	for div, freq in factor_counts.items():
		if div <= max_len and freq / distances_length >= min_ration:
			candidates.add(div)

	# >> MCDs por pares
	for mcd_val, freq in mcd_pairs_counts.items():
		if mcd_val <= max_len and freq / (distances_length*(distances_length-1)/2) >= min_ration:
			candidates.add(mcd_val)

	# Ordenamos los candidatos de menor a mayor
	return sorted(candidates)


# 7. [1] Recuperar la clave por análisis de frecuencias
#
#    >> Análisi de frecuencia: Chi-Cuadrado (clásico)
#
#    Intenta recuperar la clave usando análisis de frecuencias para una longitud dad.
#    Devuelve:
#    	(clave_estimada, puntuacion_chi_cuadrado_total)
def chi_square_frequence_analysis(cyphertext:str="", key_length:int=-1, alphabet:dict={}) -> tuple[str, float]:
	# Comprobamos la longitud de la clave
	if key_length <= 0 or alphabet == {}:
		return "", 0.0

	key_estimate = ""
	total_chi = 0.0

	# Recorremos la columna de vigenere
	for i in range(key_length):
		column = cyphertext[i::key_length]
		n = len(column)
		chi_scores = []

		alphabet_length = len(alphabet)
		ascii_alphafet_first_letter = ord(list(alphabet.keys())[0])

		# Probar todas las rotaciones poribles del alfabeto proporcionado
		# >> (César)
		for shift in range(alphabet_length):
			shifted_text = [(chr(((ord(c) - ascii_alphafet_first_letter - shift) % alphabet_length) + ascii_alphafet_first_letter)) for c in column]
			count = Counter(shifted_text)
			chi = 0.0
			for letter in alphabet.keys():
				observed = count.get(letter, 0)
				expected = n * alphabet[letter] / 100
				chi += ((observed - expected) ** 2) / expected if expected != 0 else 0
			chi_scores.append((shift, chi))

		# Elegimos el shift con menor chi-cuadrado
		best_shift, best_chi = min(chi_scores, key=lambda x: x[1])
		key_estimate += chr(best_shift + ascii_alphafet_first_letter)
		total_chi += best_chi

	return key_estimate, total_chi


# 8. [!] Obtención de la clave final por medio del Índice de Coincidencia
def order_candidates_by_ci(candidate_keys:list[tuple[str, float]]=[]) -> list[tuple[str, float]]:
	candidate_keys.sort(key=lambda x: x[1])
	return candidate_keys


# [OPCIONAL] Descifrado de texto
def decypher_text(text:str="", key:str="", alphabet:dict={}) -> str:
	decrypted = ""

	key_len = len(key)
	alphabet_length = len(alphabet)
	alphabet_first_character = ord(list(alphabet.keys())[0])

	for i, c in enumerate(text):
		shift = ord(key[i % key_len]) - alphabet_first_character
		decrypted += chr(((ord(c) - alphabet_first_character - shift) % alphabet_length) + alphabet_first_character)

	return decrypted


# [OPTIONAL] Escritura del contenido descifrado en un archivo de salida
def save_decyphered_text_in_file(text:str="", path:str="", encoding:str="utf-8"):
	# Comprobación de los parámetros de entrada
	if text == "" or path == "":
		raise AttributeError(f"The file {path} does not exist!")

	with open(path, "w", encoding=encoding) as f:
		f.write(text)


# =========================================================
# >>> Flujo principal del programa
# =========================================================

# Función principal
# Ejecuta todo el proceso de Kasiski:
# 	- Encuentra repeticiones
# 	- Calcula distancias y MCDs
# 	- Sugiere longitudes
# 	- Prueba longitudes candidatas con análisis de frecuencias
# Imprime resultados y claves candidatas.
# No devuelve nada (solo muestra resultados).
def main(args, cyphertext:str="") -> None:
	# Compribando los datos de entrada
	if cyphertext ==  "":
		raise AttributeError("No hay texto a analizar")

	# Limpiar el texto
	print("[+] Limpiando el texto...")
	cyphertext = sanitize_text(
		text=cyphertext,
		first_ch=list(alphabets[args.language].keys())[0],
		last_ch=list(alphabets[args.language].keys())[-1]
	)

	# Encontrar repeticiones (Kasiski)
	print("\n[+] Obteniendo repeticiones de subcriptogramas...")
	repeated = find_repeated_subcrypthographs(cyphertext, args.min_len, args.max_len+2)

	# Calcular distancias
	print("\n[+] Calculo de las distancias...")
	distances = []
	for positions in repeated.values():
		for i in range(len(positions)-1):
			distances.append(positions[i+1] - positions[i])
	print(f">>> {distances}")

	# [!] No se eliminan las distancias repetidas porque cada distancia aactúa como un dato estadístico independiente
	# cuantas más veces se repite una misma distancia, más peso tiene su patrón

	if not distances:
		raise RuntimeError("No se hallaron distancias para proceder")

	# Sugerir longitudes de clave
	print("\n[+] Obteniendo las posibles longitudes de clave...")
	candidate_lengths = suggest_key_length(distances, args.min_ratio, args.max_len)
	print(f">>> {candidate_lengths}")

	# Probar cada longitud con análisis de frecuencia
	print("\n[+] Análisis de frecuencia de los candidatos de clave...")
	candidate_keys:list[tuple[str, float]] = []
	for length in candidate_lengths:
		candidate_keys.append((chi_square_frequence_analysis(cyphertext, length, alphabets[args.language])))
	print(f">>> {candidate_keys}")


	# [+] Análisis del índice de coincidencia con el alfabeto proporcionado
	#     (Integrar más tipos de análisis y dar la selección al usuario)
	candidate_keys = order_candidates_by_ci(candidate_keys)

	# Output de la clave
	print(f"\n\n[*] Key found!: {candidate_keys[0][0]}")

	# [OPCIONAL] Descifrado de texto
	decyphered_text = ""
	if args.decypher:
		print(f"\n[+] Descifrando el texto con la clave: {candidate_keys[0][0]}...")
		decyphered_text = decypher_text(cyphertext, candidate_keys[0][0], alphabets[args.language])

	# [OPCIONAL] Moestreo por pantalla / escritura en archivo
	if args.output:
		print(f"\n[+] Guardando el contenido del texto descifrado en el archivo {args.output}...")
		save_decyphered_text_in_file(decyphered_text, args.output)
	
	elif args.decypher:
		separator = "".join(['=' for i in range(30)])
		print(f"\nContent decrypted:\n{separator}\n{decyphered_text}\n{separator}")



# Función inicial -> Obtención de argumentos + lanzamos le
if __name__ == '__main__':
	# Parser de argumentos
	parser = argparse.ArgumentParser(
		description = "Descrifrado de texto cifrado con Vigenère usando análisi de Kasinski"
	)

	# Parámetros de entrada por consola
	parser.add_argument("file",             type=str,                 help="Path del archivo con en texto cifrado")
	parser.add_argument("--min-len",        type=int,   default=3,    help="Longitud mínima de subcriptogramas para Kasinski (default: 3)")
	parser.add_argument("--max-len",        type=int,   default=20,   help="Longitud máxima de clave a considerar (default: 20)")
	parser.add_argument("--min-ratio",      type=float, default=0.25, help="Proporción mínima para considerar divisores frecuentes (default: 0.25)")
	parser.add_argument("-l", "--language", type=str,   default="es", help="Idioma en el que se encuentra el texto introducido (default: 'es')")
	parser.add_argument("-o", "--output",   type=str,                 help="Archivo de salida en caso de que queramos no solo la clave, sino descifrar el contenido en un archivo.")
	parser.add_argument("-d", "--decypher", action="store_true",      help="Se descifra el texto en caso de que se pueda obtener la clave de descifrado")
	
	args = parser.parse_args()


	# [*] Validación de los argumentos de entrada
	if args.language not in alphabets.keys():
		print(f"\n[ERROR]: Parametro 'language' incorrecto: {args.language}")
		sys.exit(1)

	# [+] Lectura del contenido del archivo
	try:
		cyphertext = get_file_content(args.file)
	except Exception as e:
		print(f"\n[ERROR]: Error al leer el archivo: {e}")
		sys.exit(1)

	# [*] Resolución del algoritmo
	try:
		main(args, cyphertext)

	except Exception as e:
		print(f"\n[ERROR]: {e}")
		sys.exit(3)