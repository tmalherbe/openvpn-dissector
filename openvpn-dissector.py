#!/usr/bin/python3.9
# -*- coding: utf-8 -*-

import argparse
import binascii
from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC as hmac, SHA512
from scapy.all import *

#from tls_dissector import *

from dissector_const import *
from dissector_globals import *
from dissector_utils import *
 
import tls13_dissector# import as tls13_dissector

openvpn_handshake_finished = False

def add_tcp_ip_layer(openvpn_payload):

	if dissector_globals.is_from_client == True:
		ip_src = dissector_globals.addr_client
		ip_dst = dissector_globals.addr_server
		udp_src = 4444
		udp_dst = 1194
	else:
		ip_dst = dissector_globals.addr_client
		ip_src = dissector_globals.addr_server
		udp_dst = 4444
		udp_src = 1194	

	openvpn_packet = IP(src = ip_src, dst = ip_dst) / TCP(sport = udp_src, dport = udp_dst) / Raw(openvpn_payload)
	return openvpn_packet

tls_auth_begin_tag = "<tls-auth>"
tls_auth_end_tag = "</tls-auth>"
psk_begin_tag = "-----BEGIN OpenVPN Static key V1-----"
psk_end_tag = "-----END OpenVPN Static key V1-----"

psk_hmac_client = None
psk_hmac_server = None

def parse_openvpn_file(ovpn_path):

	global psk_hmac_client
	global psk_hmac_server

	try:
		fd = open(ovpn_path, "r")
	except:
		print("could not open %r" % ovpn_path)
		return

	ovpn_content = ""
	ovpn_lines = fd.readlines()
	
	for line in ovpn_lines:
		ovpn_content += line.strip('\n')

	index_begin = ovpn_content.find(tls_auth_begin_tag)
	index_end = ovpn_content.find(tls_auth_end_tag)

	if index_begin == -1 or index_end == -1:
		print("tls-auth doesn't seem to be used !")
		return

	index_begin = ovpn_content.find(psk_begin_tag)
	index_end = ovpn_content.find(psk_end_tag)

	if index_begin == -1 or index_end == -1:
		print("cannot find any PSK key !")
		return

	psk = ovpn_content[ index_begin + len(psk_begin_tag) : index_end]# - len(psk_end_tag) ]
	
	psk_hmac_client_hex = psk[384 : 384 + 128]
	psk_hmac_server_hex = psk[128 : 128 + 128]
	psk_hmac_client = binascii.unhexlify(psk_hmac_client_hex)
	psk_hmac_server = binascii.unhexlify(psk_hmac_server_hex)

	print("PSK HMAC client : %r" % psk_hmac_client_hex)
	print("PSK HMAC server : %r" % psk_hmac_server_hex)
	print("")

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

def get_compression_method(compression_method):
	try:
		return compression_methods[compression_method]
	except:
		print("unknown compression method (%r)" % compression_method)
		exit()

def dissect_openvpn_plaintext(plaintext, index):

	sequence_number = int.from_bytes(plaintext[:4], 'big')
	compression_byte = plaintext[4]
	padding_byte = plaintext[-1]

	if padding_byte > 0x10:
		print("padding seems to be incorrect! (%r)" % padding_byte)
		exit()

	raw_plaintext = plaintext[5 : -padding_byte]
	
	print("sequence number : %r" % sequence_number)
	print("compression byte : %r (%r)" % (hex(compression_byte), get_compression_method(compression_byte)))
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

	global openvpn_handshake_finished
	if openvpn_handshake_finished == False:
		openvpn_handshake_finished = True

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
			exit()

	if k_enc != None and (k_auth == None or is_authenticated == True):
	
		cipher = AES.new(binascii.unhexlify(k_enc), AES.MODE_CBC, iv = iv)
		plaintext = cipher.decrypt(ciphertext)
		print("Packet plaintext : %r" % plaintext)
		
		dissect_openvpn_plaintext(plaintext, index)

	print("");

def dissect_openvpn_ack_v1(openvpn_payload):

	global psk_hmac_client

	openvpn_pkt_type = (openvpn_payload[0]).to_bytes(1, 'big')
	openvpn_packet_session_id = openvpn_payload[1 : 9]
	openvpn_packet_hmac = openvpn_payload[9 : 73]
	openvpn_packet_id = openvpn_payload[73 : 77]
	openvpn_packet_time = openvpn_payload[77 : 81]
	openvpn_packet_id_array = openvpn_payload[81 : 86]
	openvpn_remote_session_id = openvpn_payload[86 : 94]

	print(" openvpn_payload : %r" % binascii.hexlify(openvpn_payload))
	print(" openvpn_pkt_type : %r" % binascii.hexlify(openvpn_pkt_type))
	print(" openvpn_session_id : %r" % binascii.hexlify(openvpn_packet_session_id))
	print(" openvpn_hmac : %r" % binascii.hexlify(openvpn_packet_hmac))
	print(" openvpn pkt_id : %r" % binascii.hexlify(openvpn_packet_id))
	print(" openvpn time : %r" % binascii.hexlify(openvpn_packet_time))
	print(" openvpn_packet_id_array : %r" % binascii.hexlify(openvpn_packet_id_array))
	print(" openvpn_remote_session_id : %r" % binascii.hexlify(openvpn_remote_session_id))

	if psk_hmac_client != None and openvpn_handshake_finished == False:
		hmac_input = b''
		hmac_input += openvpn_packet_id
		hmac_input += openvpn_packet_time
		hmac_input += openvpn_pkt_type
		hmac_input += openvpn_packet_session_id
		hmac_input += openvpn_packet_id_array
		hmac_input += openvpn_remote_session_id

		h = hmac.new(key = psk_hmac_client, digestmod = SHA512)
		h.update(hmac_input)
		openvpn_computed_hmac = h.digest()

		if openvpn_computed_hmac == openvpn_packet_hmac:
			print(" ack_v1 HMAC is correct :-)")
		else:
			print(" ack_v1 HMAC is not correct :-(")

def dissect_openvpn_hard_reset_client_v2(openvpn_payload):

	global psk_hmac_client

	openvpn_pkt_type = (openvpn_payload[0]).to_bytes(1, 'big')
	openvpn_packet_session_id = openvpn_payload[1 : 9]
	openvpn_packet_hmac = openvpn_payload[9 : 73]
	openvpn_packet_id = openvpn_payload[73 : 77]
	openvpn_packet_time = openvpn_payload[77 : 81]
	openvpn_packet_trailer = openvpn_payload[81 : 86]

	print(" openvpn_payload : %r" % binascii.hexlify(openvpn_payload))
	print(" openvpn_pkt_type : %r" % binascii.hexlify(openvpn_pkt_type))
	print(" openvpn_session_id : %r" % binascii.hexlify(openvpn_packet_session_id))
	print(" openvpn_hmac : %r" % binascii.hexlify(openvpn_packet_hmac))
	print(" openvpn pkt_id : %r" % binascii.hexlify(openvpn_packet_id))
	print(" openvpn time : %r" % binascii.hexlify(openvpn_packet_time))
	print(" openvpn trailer : %r" % binascii.hexlify(openvpn_packet_trailer))

	if psk_hmac_client != None:
		hmac_input = b''
		hmac_input += openvpn_packet_id
		hmac_input += openvpn_packet_time
		hmac_input += openvpn_pkt_type
		hmac_input += openvpn_packet_session_id
		hmac_input += openvpn_packet_trailer
		
		h = hmac.new(key = psk_hmac_client, digestmod = SHA512)
		h.update(hmac_input)
		openvpn_computed_hmac = h.digest()

		if openvpn_computed_hmac == openvpn_packet_hmac:
			print(" hard_reset_client_v2 HMAC is correct :-)")
		else:
			print(" hard_reset_client_v2 HMAC is not correct :-(")

def dissect_openvpn_hard_reset_server_v2(openvpn_payload):

	global psk_hmac_server

	openvpn_pkt_type = (openvpn_payload[0]).to_bytes(1, 'big')
	openvpn_packet_session_id = openvpn_payload[1 : 9]
	openvpn_packet_hmac = openvpn_payload[9 : 73]
	openvpn_packet_id = openvpn_payload[73 : 77]
	openvpn_packet_time = openvpn_payload[77 : 81]
	openvpn_packet_id_array = openvpn_payload[81 : 86]
	openvpn_remote_session_id = openvpn_payload[86 : 94]
	openvpn_packet_trailer = openvpn_payload[94 : 98]

	print(" openvpn_payload : %r" % binascii.hexlify(openvpn_payload))
	print(" openvpn_pkt_type : %r" % binascii.hexlify(openvpn_pkt_type))
	print(" openvpn_session_id : %r" % binascii.hexlify(openvpn_packet_session_id))
	print(" openvpn_hmac : %r" % binascii.hexlify(openvpn_packet_hmac))
	print(" openvpn pkt_id : %r" % binascii.hexlify(openvpn_packet_id))
	print(" openvpn time : %r" % binascii.hexlify(openvpn_packet_time))
	print(" openvpn_packet_id_array : %r" % binascii.hexlify(openvpn_packet_id_array))
	print(" openvpn_remote_session_id : %r" % binascii.hexlify(openvpn_remote_session_id))
	print(" openvpn trailer : %r" % binascii.hexlify(openvpn_packet_trailer))

	if psk_hmac_client != None:
		hmac_input = b''
		hmac_input += openvpn_packet_id
		hmac_input += openvpn_packet_time
		hmac_input += openvpn_pkt_type
		hmac_input += openvpn_packet_session_id
		hmac_input += openvpn_packet_id_array
		hmac_input += openvpn_remote_session_id
		hmac_input += openvpn_packet_trailer
		
		h = hmac.new(key = psk_hmac_server, digestmod = SHA512)
		h.update(hmac_input)
		openvpn_computed_hmac = h.digest()

		if openvpn_computed_hmac == openvpn_packet_hmac:
			print(" hard_reset_server_v2 HMAC is correct :-)")
		else:
			print(" hard_reset_server_v2 HMAC is not correct :-(")

def dissect_openvpn_control_v1(openvpn_payload):

	offset = 0

	openvpn_pkt_type = (openvpn_payload[offset]).to_bytes(1, 'big')
	offset += 1
	openvpn_packet_session_id = openvpn_payload[offset : offset + 8]
	offset += 8
	openvpn_packet_hmac = openvpn_payload[offset : offset + 64]
	offset += 64
	openvpn_packet_id = openvpn_payload[offset : offset + 4]
	offset += 4
	openvpn_packet_time = openvpn_payload[offset : offset + 4]
	offset += 4
	openvpn_packet_id_array_len = openvpn_payload[offset]
	offset += 1
	openvpn_packet_id_array = openvpn_payload[offset : offset + 4 * openvpn_packet_id_array_len]
	offset += 4 * openvpn_packet_id_array_len
	if openvpn_packet_id_array_len != 0:
		openvpn_remote_session_id = openvpn_payload[offset : offset + 8]
		offset += 8
	openvpn_msg_packet_id = openvpn_payload[offset : offset + 4]
	offset += 4
	
	openvpn_tls_payload = openvpn_payload[offset : ]

	print(" openvpn_payload : %r" % binascii.hexlify(openvpn_payload))
	print(" openvpn_pkt_type : %r" % binascii.hexlify(openvpn_pkt_type))
	print(" openvpn_session_id : %r" % binascii.hexlify(openvpn_packet_session_id))
	print(" openvpn_hmac : %r" % binascii.hexlify(openvpn_packet_hmac))
	print(" openvpn pkt_id : %r" % binascii.hexlify(openvpn_packet_id))
	print(" openvpn time : %r" % binascii.hexlify(openvpn_packet_time))
	print(" openvpn_packet_id_array_len : %r" % openvpn_packet_id_array_len)
	if openvpn_packet_id_array_len != 0:
		print(" openvpn_packet_id_array : %r" % binascii.hexlify(openvpn_packet_id_array))
		print(" openvpn_remote_session_id : %r" % binascii.hexlify(openvpn_remote_session_id))
	print(" openvpn_msg_packet_id : %r" % binascii.hexlify(openvpn_msg_packet_id))
	print(" openvpn_tls_payload : %r" % binascii.hexlify(openvpn_tls_payload))

	hmac_input = b''

	if openvpn_handshake_finished == False:
		hmac_input += openvpn_packet_id
		hmac_input += openvpn_packet_time
		hmac_input += openvpn_pkt_type
		hmac_input += openvpn_packet_session_id
		hmac_input += openvpn_packet_id_array_len.to_bytes(1, 'big')
		if openvpn_packet_id_array_len != 0:
			hmac_input += openvpn_packet_id_array
			hmac_input += openvpn_remote_session_id
		hmac_input += openvpn_msg_packet_id
		hmac_input += openvpn_tls_payload

		if psk_hmac_client != None and psk_hmac_server != None:
			if dissector_globals.is_from_client == True:
				h = hmac.new(key = psk_hmac_client, digestmod = SHA512)
				h.update(hmac_input)
				openvpn_computed_hmac = h.digest()

			elif dissector_globals.is_from_client == False:
				h = hmac.new(key = psk_hmac_server, digestmod = SHA512)
				h.update(hmac_input)
				openvpn_computed_hmac = h.digest()

			if openvpn_computed_hmac == openvpn_packet_hmac:
				print(" control_v1 HMAC is correct :-)")
			else:
				print(" control_v1 HMAC is not correct :-(")

	tls_pseudo_packet = add_tcp_ip_layer(openvpn_tls_payload)
	tls13_dissector.dissect_tls_packet(tls_pseudo_packet, 0)

def dissect_openvpn_control_packet(openvpn_payload, index, k_enc = b'', k_auth = b''):

	openvpn_packet_type = openvpn_payload[0]
	openvpn_packet_opcode = openvpn_packet_type >> 3

	if openvpn_packet_opcode == 4:
		dissect_openvpn_control_v1(openvpn_payload)
	elif openvpn_packet_opcode == 5:
		dissect_openvpn_ack_v1(openvpn_payload)
	elif openvpn_packet_opcode == 7:
		dissect_openvpn_hard_reset_client_v2(openvpn_payload)
	elif openvpn_packet_opcode == 8:
		dissect_openvpn_hard_reset_server_v2(openvpn_payload)
	print("");

def dissect_openvpn_packet(packet, index, k_enc_client = b'', k_auth_client = b'',  k_enc_server = b'', k_auth_server = b''):
	
	# check IP&TCP layers
	check_tcpip_layer(packet, index, False)

	openvpn_payload = bytes(packet[UDP].payload)

	openvpn_packet_type = openvpn_payload[0]
	openvpn_packet_opcode = openvpn_packet_type >> 3
	
	print("Packet %r : " % index)
	print(" Packet Type : %r" % hex(openvpn_packet_type))
	print(" Packet Opcode : %r (%r)" % (hex(openvpn_packet_opcode), packet_opcodes[openvpn_packet_opcode]))

	if dissector_globals.is_from_client == True:
		k_enc = k_enc_client
		k_auth = k_auth_client
	else:
		k_enc = k_enc_server
		k_auth = k_auth_server

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

	parser.add_argument("-k", "--keylogfile",
								required = False,
								help = "The file containing TLS master secret & crypto stuffs to decrypt the traffic. This file required a patched OpenSSL to be generated.",
								type = str)

	parser.add_argument("-c", "--config_file",
								required=False,
								help=".ovpn config file involved to generate the currently analyzed traffic",
								type=str)

	args = parser.parse_args()

	pcap_path = args.pcap
	ovpn_path = args.config_file

	k_enc_client = args.k_enc_client
	k_auth_client = args.k_auth_client
	k_enc_server = args.k_enc_server
	k_auth_server = args.k_auth_server

	tls13_dissector.keylogfile = args.keylogfile

	# open the pcap
	try:
		pcap = rdpcap(pcap_path)
	except:
		print("a problem occured while opening %r" % pcap_path)
		exit(0)

	# open the .ovpn file
	if ovpn_path != None:
		parse_openvpn_file(ovpn_path)

	if pcap[0].haslayer(IP): 
		dissector_globals.addr_client = pcap[0][IP].src
		dissector_globals.addr_server = pcap[0][IP].dst
	elif pcap[0].haslayer(IPv6):
		dissector_globals.addr_client = pcap[0][IPv6].src
		dissector_globals.addr_server = pcap[0][IPv6].dst
	else:
		print("Error: first packet doesn't have any IP layer")
		exit(0)

	# by assumption, first packet is from client to server
	dissector_globals.is_from_client = True

	for i in range(len(pcap)):
		dissect_openvpn_packet(pcap[i], i, k_enc_client, k_auth_client, k_enc_server, k_auth_server)

if __name__ == '__main__':
	main()
