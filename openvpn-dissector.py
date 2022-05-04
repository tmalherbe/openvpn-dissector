#!/usr/bin/python3.9
# -*- coding: utf-8 -*-

import argparse
import binascii
from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC as hmac, SHA512
from scapy.all import *

packet_opcodes = {
	1 : "P_CONTROL_HARD_RESET_CLIENT_V1",
	2 : "P_CONTROL_HARD_RESET_SERVER_V1",
	3 : "P_CONTROL_SOFT_RESET_V1",
	4 : "P_CONTROL_V1",
	5 : "P_ACK_V1",
	6 : "P_DATA_V1",
	7 : "P_CONTROL_HARD_RESET_CLIENT_V2",
	8 : "P_CONTROL_HARD_RESET_SERVER_V2",
	9 : "P_DATA_V2",
	10 : "P_CONTROL_HARD_RESET_CLIENT_V3"
}

compression_methods = {
	0x66 : "Lzo compression",
	0x67 : "Lz4 compression",
	0xFA : "No compression",
	0xFB : "No compression byte swap"
}

def dissect_openvpn_plaintext(plaintext, index):

	sequence_number = int.from_bytes(plaintext[:4], 'big')
	compression_byte = plaintext[4]
	padding_byte = plaintext[-1]
	raw_plaintext = plaintext[5 : -padding_byte]
	
	print("sequence number : %r" % sequence_number)
	print("compression byte : %r (%r)" % (hex(compression_byte), compression_methods[compression_byte]))
	print("padding byte : %r" % padding_byte)
	print("raw plaintext : %r" % raw_plaintext)
	
	if (raw_plaintext[0] & 0xF0 == 0x40):
		parsed_packet = IP(raw_plaintext)
		parsed_packet.show()
	elif (raw_plaintext[0] & 0xF0 == 0x60):
		parsed_packet = IPv6(raw_plaintext)
		parsed_packet.show()
	else:
		print("could not guess type of traffic")


def dissect_openvpn_data_packet(openvpn_payload, index, k_enc = b'', k_auth = b''):
	print("dissect_openvpn_data_packet")
	
	is_authenticated = False
	peer_id = int.from_bytes(openvpn_payload[1:4], 'big')
	data = openvpn_payload[4:]
	
	mac = data[:64]
	iv = data[64:80]
	ciphertext = data[80:]
	
	print("Peer ID : %r" % hex(peer_id))
	#print("Data : %r" % data)
	
	print("Packet HMAC : %r" % mac)
	print("Packet IV : %r" % iv)
	print("Packet ciphertext : %r" % ciphertext)

	if k_auth != None:

		hmac_input = data[64:]
		h = hmac.new(binascii.unhexlify(k_auth), digestmod = SHA512)
		h.update(hmac_input)

		if h.digest() == mac:
			print("Packet is authenticated")
			is_authenticated = True
		else:
			print("Packet cannot be authenticated\nreal hmac = %r\ncomputed hmac = %r" % (mac, h.hexdigest()))

	if k_enc != None and (k_auth == None or is_authenticated == True):
	
		cipher = AES.new(binascii.unhexlify(k_enc), AES.MODE_CBC, iv = iv)
		plaintext = cipher.decrypt(ciphertext)
		print("Packet plaintext : %r" % plaintext)
		
		dissect_openvpn_plaintext(plaintext, index)

	print("");

def dissect_openvpn_control_packet(openvpn_payload, index, k_enc = b'', k_auth = b''):
	openvpn_packet_session_id = int.from_bytes(openvpn_payload[1:9], 'big')
	openvpn_packet_hmac = int.from_bytes(openvpn_payload[9:29], 'big')
	openvpn_packet_id = int.from_bytes(openvpn_payload[29:33], 'big')

	print("Session ID : %r" % hex(openvpn_packet_session_id))
	print("Packet HMAC : %r" % hex(openvpn_packet_hmac))
	print("Packet ID : %r" % hex(openvpn_packet_id))
	print("");

def dissect_openvpn_packet(packet, index, k_enc_client = b'', k_auth_client = b'',  k_enc_server = b'', k_auth_server = b''):
	
	if packet.haslayer(IP):
		if packet[IP].src == addr_client and packet[IP].dst == addr_server:
			print("client -> server")		
			k_enc = k_enc_client
			k_auth = k_auth_client
		elif packet[IP].dst == addr_client and packet[IP].src == addr_server:
			print("server -> client")
			k_enc = k_enc_server
			k_auth = k_auth_server
		else:
			print("Error: packet %r doesn't belong to the OpenVPN stream" % index)
			exit(0)
	elif packet.haslayer(IPv6):
		if packet[IPv6].src == addr_client and packet[IPv6].dst == addr_server:
			print("client -> server")		
			k_enc = k_enc_client
			k_auth = k_auth_client
		elif packet[IPv6].dst == addr_client and packet[IPv6].src == addr_server:
			print("server -> client")
			k_enc = k_enc_server
			k_auth = k_auth_server
		else:
			print("Error: packet %r doesn't belong to the OpenVPN stream" % index)
			exit(0)
	else:
		print("Error: packet %r doesn't have any IP layer" % index)
		exit(0)

	if not packet.haslayer(UDP):
		print("Error: packet %r doesn't have any UDP layer" % index)
		exit(0)

	openvpn_payload = bytes(packet[UDP].payload)

	openvpn_packet_type = openvpn_payload[0]
	openvpn_packet_opcode = openvpn_packet_type >> 3
	
	print("Packet %r : " % index)
	print("Packet Type : %r " % hex(openvpn_packet_type))
	print("Packet Opcode : %r (%r)" % (hex(openvpn_packet_opcode), packet_opcodes[openvpn_packet_opcode]))

	if openvpn_packet_opcode == 9:
		dissect_openvpn_data_packet(openvpn_payload, index, k_enc, k_auth)
	else:
		dissect_openvpn_control_packet(openvpn_payload, index, k_enc, k_auth)

def main():

	global addr_client
	global addr_server

	parser = argparse.ArgumentParser()

	parser.add_argument("-p", "--pcap",
								required=True,
								help="Openvpn traffic to dissect.The pcap file. This pcap is supposed to contain only 1 OpenVPN/UDP stream, and the 1st frame shall be the emitted by the client",
								type=str)

	parser.add_argument("-kc", "--k_enc_client",
								required=False,
								help="Client symetric session key to encrypt the traffic",
								type=str)

	parser.add_argument("-Kc", "--k_auth_client",
								required=False,
								help="Client symetric session key to authenticate the traffic",
								type=str)

	parser.add_argument("-ks", "--k_enc_server",
								required=False,
								help="Server symetric session key to encrypt the traffic",
								type=str)

	parser.add_argument("-Ks", "--k_auth_server",
								required=False,
								help="Server symetric session key to authenticate the traffic",
								type=str)

	args = parser.parse_args()

	pcap_path = args.pcap

	k_enc_client = args.k_enc_client
	k_auth_client = args.k_auth_client
	k_enc_server = args.k_enc_server
	k_auth_server = args.k_auth_server

	pcap = rdpcap(pcap_path)

	if pcap[0].haslayer(IP): 
		addr_client = pcap[0][IP].src
		addr_server = pcap[0][IP].dst
	elif pcap[0].haslayer(IPv6):
		addr_client = pcap[0][IPv6].src
		addr_server = pcap[0][IPv6].dst	
	else:
		print("Error: first packet doesn't have any IP layer")
		exit(0)

	for i in range(len(pcap)):
		dissect_openvpn_packet(pcap[i], i, k_enc_client, k_auth_client, k_enc_server, k_auth_server)

if __name__ == '__main__':
	main()
