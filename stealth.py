import sys
import time
import datetime
from scapy.all import IP, ICMP, send

def send_icmp_packets(text):
    dest_ip = "8.8.8.8"
    identifier = 12345
    seq_number = 1

    for char in text:
        # Obtener el timestamp actual
        timestamp = int(time.mktime(datetime.datetime.now().timetuple()))
	
	 # Modificar el byte menos significativo del timestamp con el valor ASCII del carácter
        modified_timestamp = (timestamp & 0xFFFFFF00) | (ord(char) & 0xFF)
	
        # Construir el paquete ICMP personalizado con el campo timestamp en Reserved
        icmp_packet = IP(dst=dest_ip) / ICMP(type="echo-request", id=identifier, seq=seq_number, reserved=timestamp) / (char.encode("utf-8") + b"\x00\x00\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17" + b"\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F" + b"\x20\x21\x22\x23\x24\x25\x26\x27" + b"\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F" + b"\x30\x31\x32\x33\x34\x35\x36\x37")

        # Enviar el paquete ICMP
        send(icmp_packet)

        # Incrementar el número de secuencia
        seq_number += 1

        # Esperar un breve tiempo para evitar saturar la red
        time.sleep(0.1)

    print(f"Se enviaron {len(text)} paquetes ICMP.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: sudo python3 archivo.py 'texto cifrado a enviar'")
        sys.exit(1)

    text_to_send = sys.argv[1]
    send_icmp_packets(text_to_send)
