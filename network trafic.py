# Scapy est utilisé pour la capture et l’analyse de paquets réseau
from scapy.all import sniff, TCP, UDP, IP, ICMP
# Scapy module pour la manipulation des paquets HTTP
from scapy.layers import http
# Pour la gestion des threads dans le programme
import threading
# Pour travailler avec les dates et heures
from datetime import datetime

# Fonction pour analyser les paquets
def packet_analyzer(packets, capture_date):
    # En-tête du tableau de sortie
    print("{:<5} {:<20} {:<20} {:<20} {:<20} {:<20} {:<10} {:<10} {:<10} {:<30} {:<30} {:<15}".format(
        "No", "Date", "Time", "Source", "Source Port", "Destination", "Destination Port",
        "Protocol", "Length", "Info", "Extra Info", "Malicious"
    ))
    
    # Analyse chaque paquet dans la liste
    for i, packet in enumerate(packets):
        seq = i + 1
        capture_time = datetime.fromtimestamp(packet.time).strftime("%Y-%m-%d %H:%M:%S")
        src = packet[IP].src if IP in packet else packet.src
        
        # Déterminer le protocole du paquet
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = "UDP"
        elif ICMP in packet:
            src_port = "N/A"
            dst_port = "N/A"
            protocol = "ICMP"
        else:
            src_port = "N/A"
            dst_port = "N/A"
            protocol = "Unknown"
        
        length = len(packet)
        info = packet.summary()
        
        # Ajouter des informations sur l’adresse de destination, l’adresse source, le port source et le port destination
        dst = packet[IP].dst if IP in packet else "N/A"
        dest_port = dst_port if dst_port != "N/A" else "N/A"
        src_info = f"{src}:{src_port}" if src_port != "N/A" else src
        dst_info = f"{dst}:{dest_port}" if dest_port != "N/A" else dst
        
        # Exemple : Marquer les requêtes HTTP suspects
        if hasattr(packet, 'HTTP'):
            http_info = packet[http.HTTP].summary()
            malicious_indicator = "Suspicious HTTP Request" if "malicious" in http_info or "example.org" in http_info else "N/A"
        else:
            http_info = "N/A"
            malicious_indicator = "N/A"
        
        # Imprimer les détails du paquet dans un format tabulaire
        print("{:<5} {:<20} {:<20} {:<20} {:<20} {:<20} {:<10} {:<10} {:<10} {:<30} {:<30} {:<15}".format(
            seq, capture_date, capture_time, src_info, src_port, dst_info, dest_port,
            protocol, length, info, http_info, malicious_indicator
        ))

# Fonction pour le sniffing des paquets avec une durée spécifiée
def packet_sniffer(duration):
    # Obtenir la date actuelle pour la capture
    capture_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Capturer les paquets avec Scapy en utilisant un filtre IP et une durée spécifiée
    packets = sniff(filter="ip", timeout=duration)
    # Appeler la fonction d’analyse sur les paquets capturés
    packet_analyzer(packets, capture_date)

# Point d’entrée du programme
if __name__ == "__main__":
    # Créer plusieurs threads pour le sniffing
    threads_list = []
    # Spécifiez la durée de capture en 5 secondes
    duration = 5
    
    # Créer et démarrer cinq threads pour capturer des paquets en parallèle
    for _ in range(5):
        thread = threading.Thread(target=packet_sniffer, args=(duration,))
        threads_list.append(thread)
        thread.start()
    
    # Attendre la fin de tous les threads
    for thread in threads_list:
        thread.join()
