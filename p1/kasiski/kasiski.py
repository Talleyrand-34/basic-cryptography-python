import math
from collections import Counter
from array import array
import vigenere
import sys
import itertools

alfabeto="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
def clave_subtextos(subtextos):
    clave = ""
    for texto in subtextos:
        cesar = clave_cesar(texto)
        clave = clave + cesar
    return clave

def clave_cesar(texto):
    recuento_letras = contar_letras(texto)
    claves_cesar = encontrar_claves_probables(recuento_letras)
    return claves_cesar

def contar_letras(texto):
    contar_letras = [0] * len(alfabeto)
    for c in alfabeto:
        i = alfabeto.index(c)
        for l in texto:
            if c == l:
                contar_letras[i] = contar_letras[i] + 1
    return contar_letras

def encontrar_claves_probables(recuento_letras):
    alfabeto_por_aparicion = sorted(range(len(recuento_letras)), key=lambda k: recuento_letras[k], reverse=True)
    
    # Letras más comunes en español (por orden de frecuencia)
    letras_comunes = 'EAOSRNIDLCTUMPBGVYQHFZJXKW'
    
    claves_probables = []
    for i in range(min(10, len(alfabeto_por_aparicion))):
        letra_mas_comun = alfabeto[alfabeto_por_aparicion[i]]
        for letra_comun in letras_comunes[:10]:  # Usamos las 10 letras más comunes
            desplazamiento = (alfabeto.index(letra_mas_comun) - alfabeto.index(letra_comun)) % len(alfabeto)
            claves_probables.append(alfabeto[desplazamiento])
    
    return claves_probables[:10]  # Devolvemos las 10 claves más probables

def generar_claves_candidatas(claves_subtextos):
    return [''.join(p) for p in itertools.product(*claves_subtextos)]

def subtextos(texto,tamano_clave):
    subtextos = [""]*tamano_clave
    for i in range(len(texto)):
        subtextos[i%tamano_clave]+=texto[i]
    return subtextos

def encontrar_repeticiones(texto, longitud_min_repeticion):
    repeticiones = {}
    for i in range(len(texto) - longitud_min_repeticion + 1):
        subcadena = texto[i:i + longitud_min_repeticion]
        if subcadena in repeticiones:
            repeticiones[subcadena].append(i)
        else:
            repeticiones[subcadena] = [i]
    
    return {k: v for k, v in repeticiones.items() if len(v) > 2}

def encontrar_distancias_entre_repeticiones(repeticiones):
    distancias = {}
    for subcadena, posiciones in repeticiones.items():
        distancias[subcadena] = [posiciones[i + 1] - posiciones[i] for i in range(len(posiciones) - 1)]
    
    return distancias

def encontrar_factores_comunes(distancias):
    factores_comunes = {}
    for subcadena, distancias_entre_repeticiones in distancias.items():
        factores_comunes[subcadena] = []
        for i in range(len(distancias_entre_repeticiones) - 1):
            for j in range(i + 1, len(distancias_entre_repeticiones)):
                #factor_comun = abs(distancias_entre_repeticiones[i] - distancias_entre_repeticiones[j])
                mcd = math.gcd(distancias_entre_repeticiones[i], distancias_entre_repeticiones[j])  # Calcula el MCD
                if mcd > 1:
                    factores_comunes[subcadena].append(mcd)
                

    return factores_comunes

def obtener_tamaño_clave(factores_comunes):
    todos_los_numeros = [num for lista in factores_comunes.values() for num in lista]

    contador = Counter(todos_los_numeros)

    numero_mas_comun = contador.most_common(1)[0][0]
    return numero_mas_comun

def ataque_kasiski(texto_cifrado, longitud_min_repeticion):
    repeticiones = encontrar_repeticiones(texto_cifrado, longitud_min_repeticion)
    distancias = encontrar_distancias_entre_repeticiones(repeticiones)
    factores_comunes = encontrar_factores_comunes(distancias)
    longitud_clave=obtener_tamaño_clave(factores_comunes)
    return longitud_clave


def ataque(fichero):
    with open(fichero, 'r') as f:
        texto = f.read()
        f.close()
    
    longitud_min_repeticion = 3

    print("TRIGRAMAS")
    print(encontrar_repeticiones(texto, longitud_min_repeticion))
    print("Distancias")
    print(encontrar_distancias_entre_repeticiones(encontrar_repeticiones(texto, longitud_min_repeticion)))
    print("factores_comunes")
    e=encontrar_factores_comunes(encontrar_distancias_entre_repeticiones(encontrar_repeticiones(texto, longitud_min_repeticion)))


    print(e)
    print("longitud_clave")
    print(obtener_tamaño_clave(e))
    tamano_clave = ataque_kasiski(texto, longitud_min_repeticion)
    print(tamano_clave)

    subtextos1 = subtextos(texto, tamano_clave)
    print(subtextos1)

    claves_subtextos = [clave_cesar(subtexto) for subtexto in subtextos1]
    claves_candidatas = generar_claves_candidatas(claves_subtextos)

    print("Las 10 claves más probables son:")
    for i, clave in enumerate(claves_candidatas[:10], 1):
        print(f"{i}. {clave}")
        # print(vigenere.descifrar(texto, clave))
        print(vigenere.vigenere_decrypt(texto,clave))

if len(sys.argv)!=2 or (len(sys.argv)==2 and sys.argv[1]=="--help"):
    print("Sintaxis: "+sys.argv[0]+" fichero.txt")
else:
    ataque(sys.argv[1])
