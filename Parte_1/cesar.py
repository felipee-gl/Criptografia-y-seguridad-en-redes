import sys

def cifrado_cesar(texto, corrimiento):
    resultado = []
    for caracter in texto:
        if caracter.isalpha():
            if caracter.isupper():
                codigo = ord(caracter) + corrimiento
                if codigo > ord('Z'):
                    codigo -= 26
            elif caracter.islower():
                codigo = ord(caracter) + corrimiento
                if codigo > ord('z'):
                    codigo -= 26
            resultado.append(chr(codigo))
        else:
            resultado.append(caracter)
    return ''.join(resultado)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 cesar.py <texto> <corrimiento>")
    else:
        texto = sys.argv[1]
        corrimiento = int(sys.argv[2])
        texto_cifrado = cifrado_cesar(texto, corrimiento)
        print(texto_cifrado)

