# network-packet-analyzer
from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
	if IP in packet:
		ip_layer = packet[IP]
		src_ip = "PRIVATE_IP" # Placeholder for source IP
		dst_ip = "PRIVATE_IP" # Placeholder for destination IP
		print(f"Source IP: {src_ip} -> Destination IP: {dst_ip}")
	
		if TCP in packet:
			print(f"Protocol: TCP")
		elif UDP in packet:
			print(f"Protocol: UDP")
		else:
			print(f"Protocol: {packet[IP]. proto}")
		
		print(f"Payload: {packet.payload}")
		print("_" * 50)
