#!/bin/python3
# -*- coding: utf-8 -*-

import os          # Lectura del archivo de entrada
import sys         # Salidas forzadas del programa
import argparse    # Lectura de los parámetros de entrada
import unicodedata # Normalización del texto de entrada

from math import gcd

from functools import reduce
from itertools import combinations
from collections import Counter

# =========================================================
# >>> Implementación para AEOS
# =========================================================

# Nombre por el cual identificar este método
AEOS_NAME = "aeos"

# Alfabetos disponibles para el método aeos
aeos_alphabets:dict[str, dict[str, float]] = {
	"es": {
		'A': 0.0, 'B': 0.0, 'C': 0.0, 'D': 0.0, 'E': 0.0, 'F': 0.0,
		'G': 0.0, 'H': 0.0, 'I': 0.0, 'J': 0.0, 'K': 0.0, 'L': 0.0,
		'M': 0.0, 'N': 0.0, 'O': 0.0, 'P': 0.0, 'Q': 0.0, 'R': 0.0,
		'S': 0.0, 'T': 0.0, 'U': 0.0, 'V': 0.0, 'W': 0.0, 'X': 0.0,
		'Y': 0.0, 'Z': 0.0
	}
}

aeos_characters:list[str] = [
	'A', 'E', 'O', 'S'
]


# factores
def _factorization(n):
	return [i for i in range(2, n+1) if n % i == 0]

# kasiski longitudes
def _aeos_key_distance_calc(args, cyphertext:str="") -> list[int]:
	# >> Cálculo de los subcriptogramas
	patterns_calc = {}

	# Calculo de los subcriptgramas almacenando todas los subcriptogramas
	# para un filrado más rápido
	cyphertext_len = len(cyphertext)
	for L in range(args.min_len, args.max_len+1):
		for i in range(cyphertext_len -  L + 1):
			sequence = cyphertext[i:i+L]                     # Subcriptograma
			patterns_calc.setdefault(sequence, []).append(i) # En que posiciones aparece ese partón

	# Son validos todos aquellos patrones que aparecen más de 1 vez en el criptograma
	patterns = {p: pos for p, pos in patterns_calc.items() if len(pos) > 1}


	# >> Cálculo de las distancias entre subcriptogramas iguales
	distances = []
	for positions in patterns.values():
		for i in range(len(positions)-1):
			distances.append(positions[i+1] - positions[i])

	# >> Cálculo de los patrones candidatos a clave
	cont = Counter()
	for d in distances:
		for f in _factorization(d):
			if f <= args.max_len:
				cont[f] += 1

	# Si no se hallaron factores comunes
	if not cont:
		return list(range(2, args.max_len+1))

	return [k for k, _ in cont.most_common()]


# Desplazamiento por aeos para un subcriptograma
def _aeos_best_despl(cyphertext:str="", alphabet:list[str]=[], alphabet_length:int=-1):
	best_shift, best_score = 0, 0

	for shift in range(alphabet_length):
		decypher = ''.join(alphabet[(alphabet.index(c) - shift) % alphabet_length] for c in cyphertext)
		frequence = sum(decypher.count(l) for l in aeos_characters) / len(decypher)
		if frequence > best_score:
			best_score, best_shift = frequence, shift

	return best_shift, best_score

# Estimar clave por aeos
def _aeos_stimation_key(cyphertext:str="", candidate:int=-1, alphabet:list[str]=[]) -> tuple[str, float]:
	# Obtención de los subcriptogramas para la distancia candidata
	subcryptograms = ['' for _ in range(candidate)]
	for i, c in enumerate(cyphertext):
		subcryptograms[i % candidate] += c

	# Calculamos las frecuencias mayores de cada subcrptograma para hallar la clave
	# para la distancia candidata actual
	current_candidate_key = ""
	total_score = 0
	alphabet_length = len(alphabet)

	for sub in subcryptograms:
		# Obtención del desplazamiento cesar para caracter del subcriptograma actual y
		# el porcentaje de acierto para dicho caracter
		shift, score = _aeos_best_despl(sub, alphabet, alphabet_length)

		# Calculo de la clave para el subcriptograma actual
		current_candidate_key += alphabet[shift % alphabet_length]
		total_score += score

	return current_candidate_key, total_score / candidate

# =========================================================

# [!] Funcionalidad AEOS
def aeos(args, cyphertext:str="", candidate_lengths:list[int]=[]) -> str:
	# Comprobación de los parámetros de entrada
	if not args or cyphertext == "":
		raise AttributeError("There is no valid parameters")

	# Alfabeto a usar
	alphabet = list(methods_aphabets[args.method][args.language].keys())

	# Calculo de distancias candidatas a ser clave
	candidates:list[int] = _aeos_key_distance_calc(args, cyphertext)
	results:list[tuple[int, str, float]] = []

	for m in candidates:
		key, score = _aeos_stimation_key(cyphertext, m, alphabet)
		results.append((m, key, score))
	results.sort(key=lambda x: x[2], reverse=True)

	# Obtenemos la mejor clave calculada 
	_, best_key, _ = results[0]

	if args.show_candidates == True:
		for _, key, score in results:
			print(f"Key: {key} - Score: {score:.5f}")
		print()

	return best_key


# =========================================================
# >>> Implementación para Chi-Cuadrado
# =========================================================

# Nombre por el cual identificar este método
CHI_SCUARE_NAME = "chi-scuare"

# Alfabetos disponibles para el método chi-cuadrado
chi_scuare_alphabets:dict[str, dict[str, float]] = {
	"es": {
		'A': 12.53, 'B': 1.42, 'C': 4.68, 'D': 5.86, 'E': 13.68, 'F': 0.69,
		'G':  1.01, 'H': 0.70, 'I': 6.25, 'J': 0.44, 'K':  0.01, 'L': 4.97,
		'M':  3.15, 'N': 6.71, 'O': 8.68, 'P': 2.51, 'Q':  0.88, 'R': 6.87,
		'S':  7.98, 'T': 4.63, 'U': 3.93, 'V': 1.14, 'W':  0.02, 'X': 0.22,
		'Y':  0.90, 'Z': 0.52
	}
}

# 7. [1] Recuperar la clave por análisis de frecuencias
#
#    >> Análisi de frecuencia: Chi-Cuadrado (clásico) :: SUM( (Frecuencia observada - Frecuencia esperada)^2 / (Frecuencia esperada))
#
#    Intenta recuperar la clave usando análisis de frecuencias para una longitud dad.
#    Devuelve:
#    	(clave_estimada, puntuacion_chi_cuadrado_total)
def _chi_square_frequence_analysis(cyphertext:str="", key_length:int=-1, alphabet:dict={}) -> tuple[str, float]:
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


# 8. [!] Obtención de la clave final
def _order_candidates_by_ci(candidate_keys:list[tuple[str, float]]=[]) -> list[tuple[str, float]]:
	candidate_keys.sort(key=lambda x: x[1])
	return candidate_keys


# [!] Funcionalidad Chi-Cuadrado
def chi_scuare(args, cyphertext:str="", candidate_lengths:list[int]=[]) -> str:
	# Obtención de claves
	candidate_keys:list[tuple[str, float]] = []
	for length in candidate_lengths:
		candidate_keys.append((_chi_square_frequence_analysis(cyphertext, length, methods_aphabets[args.method][args.language])))

	# [+] Análisis del índice de coincidencia con el alfabeto proporcionado
	candidate_keys = _order_candidates_by_ci(candidate_keys)

	if args.show_candidates == True:
		for key, score in candidate_keys:
			print(f"Key: {key} - Score: {score:.5f}")
		print()

	# Retornamos la clave con mayor probabilidad
	return candidate_keys[0][0]

# =========================================================
# >>> Definiciones base
# =========================================================

# Métodos disponibles
methods_aphabets = {
	CHI_SCUARE_NAME: chi_scuare_alphabets,
	AEOS_NAME: aeos_alphabets,
}

methods_functions = {
	CHI_SCUARE_NAME: chi_scuare, 
	AEOS_NAME: aeos,
}

# =========================================================
# >>> Funcionalidades indepentientes de los métodos
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
def sanitize_text(text:str="", alphabet_list:list=[]) -> str:
	# Comprobación de los parámetros de entrada
	if text == "" or alphabet_list == []: return ""

	# Normalizamos el texto a "NFD": separa letras y acentos
	text = unicodedata.normalize("NFD", text)

	# Quitamos los acentos
	text = "".join(ch for ch in text if unicodedata.category(ch) != "Mn")

	# Convertimos todo a mayúsculas
	text = text.upper()

	# Filtramos solo las letras A-Z (es)
	text = "".join(ch for ch in text if ch in alphabet_list)

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
	repeated:dict[str, list[int]] = {}

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
def _factorize_distances(distances:list=[]) -> tuple[dict[int, int], dict[int, list[int]]]:
	divisors_counts:dict[int, int] = {}              # Cuantas veces aparece un factor como factor de distancias
	divisors_per_distances:dict[int, list[int]] = {} # Factor de cada distacia

	# Por cada distancia
	for d in distances:
		divisors:list[int] = []

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
def _mcd_by_pairs(distances:list=[]) -> dict[int, int]:
	mcd_counts:dict[int, int] = {}

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
	factor_counts, _ = _factorize_distances(distances)
	mcd_pairs_counts = _mcd_by_pairs(distances)

	# 3. Combinar longitudes candidatas: MCD global, divisores frecuentes y MCD por partes
	candidates:list[int] = set()
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
# >>> Flujo de programa principal
# =========================================================

# Funcion principal
def main(args, cyphertext:str="") -> None:
	if cyphertext == "":
		raise AttributeError("There is no text to be analyzed")

	alphabet = list(methods_aphabets[args.method].keys())
	alphabet_characters = list(methods_aphabets[args.method][args.language].keys())

	cyphertext = sanitize_text(
		text=cyphertext,
		alphabet_list=alphabet_characters
	)

	min_subcryptograph_len = args.min_len if args.min_len <= args.max_len else args.max_len
	max_subcryptogram_len = args.max_len if args.max_len >= args.min_len else args.min_len

	repeated_subsequences:dict = find_repeated_subcrypthographs(cyphertext, min_subcryptograph_len, max_subcryptogram_len)

	distances:list = []
	for positions in repeated_subsequences.values():
		for i in range(len(positions)-1):
			distances.append(positions[i+1] - positions[i])

	if not distances:
		raise RuntimeError("No distances found!")

	candidate_lengths = suggest_key_length(distances, args.min_rate, args.max_len)

	key = methods_functions[args.method](args, cyphertext, candidate_lengths)
	if not key or key == "":
		raise RuntimeError("Key not found!")

	print(f"[!] Key found: {key}")

	# [OPCIONAL] Descifrado de texto
	decyphered_text = ""
	if args.decypher:
		decyphered_text = decypher_text(cyphertext, key, methods_aphabets[args.method][args.language])

	# [OPCIONAL] Moestreo por pantalla / escritura en archivo
	if args.output != None:
		print(f"\n[+] Guardando el contenido del texto descifrado en el archivo {args.output}...")
		save_decyphered_text_in_file(decyphered_text, args.output)
	
	elif args.decypher:
		separator = "".join(['=' for i in range(30)])
		print(f"\nContent decrypted:\n{separator}\n{decyphered_text}\n{separator}")


# Flujo de control principal
if __name__ == '__main__':
	# Parser de argumentos
	parser = argparse.ArgumentParser(
		description = "Descifrado de criptograma encriptado por el algoritmo de vigenère (Kasiski Method)"
	)

	# Variables para optimiación de código
	methods_keys = list(methods_aphabets.keys())
	first_method_languages = list(methods_aphabets[methods_keys[0]].keys())

	# Parámetros de la aplicación
	parser.add_argument("file", type=str)
	parser.add_argument("--min-len", type=int, default=3)
	parser.add_argument("--max-len", type=int, default=20)
	parser.add_argument("--min-rate", type=float, default=0.25)
	parser.add_argument("--show-candidates", action="store_true")
	parser.add_argument("-l", "--language", type=str, default=first_method_languages[0])
	parser.add_argument("--list-method-languages", action="store_true")
	parser.add_argument("-m", "--method", type=str, action="store", default=methods_keys[0])
	parser.add_argument("--list-frequence-methods", action="store_true")

	parser.add_argument("-o", "--output",   action="store", type=str, default=None)
	parser.add_argument("-d", "--decypher", action="store_true")

	# Compilación de los argumentos
	args = parser.parse_args()

	# [+] Listado de los métodos
	if args.list_frequence_methods:
		avaliable_methods:str = ""
		for m in list(methods_aphabets.keys()):
			avaliable_methods += "\n\t- " + m
		print(f"Avaliable Frequence Methods:{avaliable_methods}")
		sys.exit(0)

	# [+] Listado de lenguajes para el metodo seleccionado
	if args.list_method_languages:
		avaliable_languages:str = ""
		for l in list(methods_aphabets[args.method].keys()):
			avaliable_languages += "\n\t- " + l
		print(f"Avaliable Languages ({args.method} method):{avaliable_languages}")
		sys.exit(0)

	# [*] Lectura del archivo con el texto cifrado
	try:
		cyphertext = get_file_content(args.file)
	except Exception as e:
		print(f"\n[ERROR]: Error while readinf file: {e}")
		sys.exit(1)

	# [*] Ejecución del crackeo
	try:
		main(args, cyphertext)
	except KeyboardInterrupt as e:
		print(f"\n[!] Keyboard Interrupt: Exiting...")
		sys.exit(1)
	except Exception as e:
		print(f"\n[ERROR]: {e}")
		sys.exit(2)