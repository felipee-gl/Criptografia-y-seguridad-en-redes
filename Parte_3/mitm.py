import sys
import re
from collections import Counter
from termcolor import colored
from scapy.all import rdpcap, ICMP, Raw

# Función para realizar el descifrado César
def caesar_decrypt(text, shift):
    decrypted_text = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            decrypted_char = chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            decrypted_text += decrypted_char
        else:
            decrypted_text += char
    return decrypted_text

# Lista de las palabras más comunes en español
spanish_common_words = [
    'el', 'de', 'que', 'y', 'a', 'en', 'un', 'ser', 'se', 'no',
    'haber', 'por', 'con', 'su', 'para', 'como', 'estar', 'tener', 'le', 'lo',
    'lo', 'todo', 'pero', 'más', 'hacer', 'o', 'poder', 'decir', 'este', 'ir',
    'otro', 'ese', 'la', 'si', 'me', 'ya', 'ver', 'porque', 'dar', 'cuando',
    'él', 'muy', 'sin', 'vez', 'mucho', 'saber', 'qué', 'sobre', 'mi', 'al',
    'yo', 'ya', 'también', 'hasta', 'año', 'dos', 'querer', 'entre', 'así', 'primero',
    'desde', 'grande', 'eso', 'ni', 'nos', 'llegar', 'uno', 'bien', 'estar', 'tiempo',
    'mismo', 'ese', 'otro', 'después', 'tan', 'eso', 'vida', 'mismo', 'hombre', 'años',
    'donde', 'ahora', 'parte', 'lugar', 'cada', 'una', 'tipo', 'nuestro', 'quedar', 'después',
    'tener', 'día', 'nombre', 'nada', 'alguno', 'año', 'hacer', 'día', 'vida', 'nuestro'
]

def calculate_similarity(text):
    words = re.findall(r'\w+', text)
    common_word_count = sum(1 for word in words if word.lower() in spanish_common_words)
    similarity = common_word_count / len(words)
    return similarity

def main():
    if len(sys.argv) != 2:
        print("Uso: sudo python3 archivo.py captura.pcapng")
        sys.exit(1)

    capture_file = sys.argv[1]
    packets = rdpcap(capture_file)
    sentence = ""
    last_identifier = None
    found_second_identifier = False

    for packet in packets:
        if packet.haslayer(ICMP) and packet[ICMP].type == 8:
            identifier = packet[ICMP].id

            if last_identifier is None:
                last_identifier = identifier

            if identifier != last_identifier and not found_second_identifier:
                found_second_identifier = True

            if found_second_identifier:
                if packet.haslayer("Raw"):
                    data = packet[Raw].load
                    if len(data) > 0:
                        least_significant_byte = data[0]
                        char = chr(least_significant_byte)
                        sentence += char

    if sentence:
        max_similarity = 0.0
        best_shift = 0
        best_sentence = ""

        for shift in range(26):
            decrypted_sentence = caesar_decrypt(sentence, shift)
            formatted_sentence = f"{shift:2d}: {decrypted_sentence}"
            similarity = calculate_similarity(decrypted_sentence)
            
            if similarity > max_similarity:
                max_similarity = similarity
                best_shift = shift
                best_sentence = decrypted_sentence
        
        for shift in range(26):
            decrypted_sentence = caesar_decrypt(sentence, shift)
            formatted_sentence = f"{shift:2d}: {decrypted_sentence}"
            
            if shift == best_shift:
                if calculate_similarity(decrypted_sentence) > 0.1:  # Ajustar el umbral según sea necesario
                    colored_sentence = colored(formatted_sentence, 'green')
                    print(colored_sentence)
                else:
                    print(formatted_sentence)
            else:
                print(formatted_sentence)

if __name__ == "__main__":
    main()

