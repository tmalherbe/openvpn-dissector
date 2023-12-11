#!/usr/bin/python3
# -*- coding: utf-8 -*-

import argparse
import binascii
from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC as hmac, SHA512, SHA384, SHA256, SHA1
from scapy.all import *

from dissector_const import *
from dissector_globals import *
from dissector_utils import *

import tls_dissector
import tls13_dissector

# Several global variables
#
## quite explicit, says, if the openvpn "handshake" is finished
openvpn_handshake_finished = False

## OpenVPN supports two methods to establish session secrets which will encrypt data:
## - old way: OpenvpnPRF is used to derive server/client keys/ivs from a client secret, and some seeds
## - new way: Via TLS Exporter mechanism: Some crypto material is derived from the Exporter secret
## This boolean is set to True when the later mechanism is used
crypto_via_exporter_mechanism = False

## some secrets for key generation
client_secret = None
client_seed_1 = None
client_seed_2 = None
server_seed_1 = None
server_seed_2 = None

## authentication/encryption keys for data channel
client_data_cipher_key = None
client_data_hmac_key = None
server_data_cipher_key = None
server_data_hmac_key = None

# IVs if GCM is used
client_iv = None
server_iv = None

## PSK algorithm for tls-auth
## Can be:
## - SHA512
## - SHA256
## - SHA1 (default behaviour, if not specified)
## - None (if tls-auth token doesn't appear in the configuration file)
psk_mode_algo = None
## WHen PSK algorithm is not None, then HMAC algorithm is the same as PSK algorithm
hmac_algo = None

## Boolean which will be set to True if data packets are encrypted with AES-GCM
aes_gcm = False

## PSK for tls-auth, aka "HMAC firewall" for control channel
psk_hmac_client = None
psk_hmac_server = None

## The session id for both sides
session_id_client = None
session_id_server = None

## Some tags for .ovpn configuration file parsing
tls_auth_begin_tag = "<tls-auth>"
tls_auth_end_tag = "</tls-auth>"
psk_begin_tag = "-----BEGIN OpenVPN Static key V1-----"
psk_end_tag = "-----END OpenVPN Static key V1-----"

## Get the size of an HMAC algorithm output
def get_hmac_len(algorithm):

	if algorithm == "SHA512":
		return 64
	elif algorithm == "SHA256":
		return 32
	elif algorithm == "SHA1":
		return 20
	else:
		return 0

## Compute an HMAC
def compute_hmac(key, hmac_algo, data):
	if hmac_algo == "SHA512":
		h = hmac.new(key, digestmod = SHA512)
	elif hmac_algo == "SHA256":
		h = hmac.new(key, digestmod = SHA256)
	elif hmac_algo == "SHA1":
		h = hmac.new(key, digestmod = SHA1)
	else:
		print(f"error: won't compute an HMAC if no HMAC algorithm is defined ! {hmac_algo}")
		exit()

	h.update(data)
	mac = h.digest()

	return mac

## Add a fake TCP layer for the TLS dissector
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

## Extract the following information from the .ovpn file:
## - Is tls-auth activated or not
## - HMAC algorithm (will be used for both data channel and tls-auth, unless tls-auth is deactivated)
## - HMAC tls-auth key (if activated)
def parse_openvpn_file(ovpn_path):

	global psk_hmac_client
	global psk_hmac_server
	global psk_mode_algo
	global hmac_algo

	try:
		fd = open(ovpn_path, "r")
	except:
		print("could not open %r" % ovpn_path)
		return

	ovpn_content = ""
	ovpn_lines = fd.readlines()

	# Unless explicitely configured, HMAC uses SHA1
	hmac_algo = "SHA1"

	# Loop over the .ovpn file and search some tokens:
	# - "tls-auth" token for tls-auth, aka HMAC firewall
	# - "auth" token for HMAC algorithm token
	# Each of these token is considered as commented if not at the very beginning of its line
	for line in ovpn_lines:
		ovpn_line = line.strip('\n')
		ovpn_content += ovpn_line

		# Look for "auth" token
		index_512 = ovpn_line.find("auth SHA512")
		index_256 = ovpn_line.find("auth SHA256")
		if index_512 == 0:
			print("auth uses SHA512 !")
			hmac_algo = "SHA512"
		elif index_256 == 0:
			print("auth uses SHA256 !")
			hmac_algo = "SHA256"

		# Look for the "tls-auth" token
		# If commented, then we have nothing more to do here
		index_tls_auth = ovpn_line.find("tls-auth")
		if index_tls_auth == 0:
			psk_mode_algo = hmac_algo
			print(f"tls-auth is used with {psk_mode_algo} !")
		elif index_tls_auth == 1 and ovpn_line[0] == ';':
			print("tls-auth is not used !")
			return

	# if we didn't take the return and psk_mode_algo is still None
	# it means no "auth" token was found
	# which means that SHA1 is used for both auth and tls-auth
	if psk_mode_algo == None:
		print("auth and tls-auth use SHA1 !")
		psk_mode_algo = "SHA1"

	# Look for the tls-auth key
	# This key is between <tls-auth> and </tls-auth> tokens
	index_begin = ovpn_content.find(tls_auth_begin_tag)
	index_end = ovpn_content.find(tls_auth_end_tag)

	# If no tls-auth key was found while tls-auth is used we have a problem
	if index_begin == -1 or index_end == -1:
		print("no tls-auth PSK found !")
		exit()

	# Take the content between the two tokens
	index_begin = ovpn_content.find(psk_begin_tag)
	index_end = ovpn_content.find(psk_end_tag)

	if index_begin == -1 or index_end == -1:
		print("cannot find any PSK key !")
		exit()

	psk = ovpn_content[ index_begin + len(psk_begin_tag) : index_end ]

	# Extract the HMAC PSK keys for each direction
	keylen = get_hmac_len(psk_mode_algo)
	psk_hmac_client_hex = psk[384 : 384 + 2 * keylen]
	psk_hmac_server_hex = psk[128 : 128 + 2 * keylen]
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
	0x69 : "Lz4 compression",
	0xFA : "No compression",
	0xFB : "No compression byte swap"
}

## Print compression method
def get_compression_method(compression_method):
	try:
		return compression_methods[compression_method]
	except:
		print(f"unknown compression method (0x{compression_method:x})")
		exit()

## Dissect a decrypted OpenVPN plaintext
def dissect_openvpn_plaintext(plaintext, index):

	# If GCM is not used, the packet has the following format:
	#
	# +-----------------+------+-----------------+
	# | sequence_number | data |     padding     |
	# +-----------------+------+-----------------+
	# <---- 4 bytes --->       <- 0 to 16 bytes ->
	#
	# A byte indicating compression algorithm used to be nested
	# between sequence number and data in older versions.
	#
	# Padding is PKCS#7 padding, that is to say it looks like:
	# 01
	# 02 02
	# 03 03 03
	# 04 04 04 04
	# and so on
	#
	if aes_gcm is False:
		# Such a packet begins with a 4 bytes sequence number
		sequence_number = int.from_bytes(plaintext[:4], 'big')
		#compression_byte = plaintext[4]
		# Get last byte of padding who tells who much bytes of padding
		# shall be removed
		padding_byte = plaintext[-1]

		# Check padding consistency
		if padding_byte > 0x10:
			print("padding seems to be incorrect! (%r)" % padding_byte)
			exit()

		# Plaintext is between sequence number and padding
		raw_plaintext = plaintext[4 : -padding_byte]
		#raw_plaintext = plaintext[5 : -padding_byte]

		print("sequence number : %r" % sequence_number)
		#print("compression byte : %r (%r)" % (hex(compression_byte), get_compression_method(compression_byte)))
		print("padding byte : %r" % padding_byte)
		print("raw plaintext : %r" % raw_plaintext)

	# if GCM is used,
	# - No sequence number is included
	# - No padding is needed because GCM uses CTR mode
	else:
		raw_plaintext = plaintext

	# Dump plaintext as IP packet
	if (raw_plaintext[0] & 0xF0 == 0x40):
		parsed_packet = IP(raw_plaintext)
		parsed_packet.show()
	elif (raw_plaintext[0] & 0xF0 == 0x60):
		parsed_packet = IPv6(raw_plaintext)
		parsed_packet.show()
	else:
		print("could not guess type of traffic")

## Dissect an OpenVPN data packet - HMAC case
def dissect_openvpn_data_packet_hmac(openvpn_payload, index, k_enc = b'', k_auth = b''):
	global client_data_cipher_key
	global client_data_hmac_key
	global server_data_cipher_key
	global server_data_hmac_key
	global hmac_algo

	# Boolean which says "the HMAC is correct"
	is_authenticated = False

	# First OpenVPN data packet proves that handshake has finished
	global openvpn_handshake_finished
	if openvpn_handshake_finished == False:
		openvpn_handshake_finished = True

	print("dissect_openvpn_data_packet_hmac")

	# Get peer id
	peer_id = int.from_bytes(openvpn_payload[1 : 4], 'big')
	data = openvpn_payload[4:]

	# Extract hmac, iv and ciphertext
	hmac_len = get_hmac_len(hmac_algo)
	real_mac = data[ : hmac_len]
	iv = data[hmac_len : hmac_len + 16]
	ciphertext = data[hmac_len + 16 : ]

	print("Peer ID : %r" % hex(peer_id))
	print("Packet HMAC : %r" % real_mac)
	print("Packet IV : %r" % iv)
	print("Packet ciphertext : %r" % ciphertext)

	# Set the appropriate keys for encryption and hmac
	if k_enc != None:
		k_enc = binascii.unhexlify(k_enc)
	elif client_secret != None:
		if dissector_globals.is_from_client == True:
			k_enc = client_data_cipher_key
		else:
			k_enc = server_data_cipher_key

	if k_auth != None:
		k_auth = binascii.unhexlify(k_auth)
	elif client_secret != None:
		if dissector_globals.is_from_client == True:
			k_auth = client_data_hmac_key
		else:
			k_auth = server_data_hmac_key

	if k_auth != None:

		# Recompute the HMAC
		# The HMAC is computed over the encrypted data (Encrypt-then-MAC)
		hmac_input = data[hmac_len : ]
		computed_mac = compute_hmac(k_auth, hmac_algo, hmac_input)

		# Check the HMAC
		if computed_mac == real_mac:
			print("Packet is authenticated")
			is_authenticated = True
		else:
			print("Packet cannot be authenticated\nreal hmac = %r\ncomputed hmac = %r" % (mac, h.hexdigest()))
			exit()

	# Decrypt the ciphertext
	if k_enc != None and (k_auth == None or is_authenticated == True):
	
		cipher = AES.new(k_enc, AES.MODE_CBC, iv = iv)
		plaintext = cipher.decrypt(ciphertext)
		print("Packet plaintext : %r" % plaintext)

		# Process the decrypted plaintext
		dissect_openvpn_plaintext(plaintext, index)

	print("");

## Dissect an OpenVPN data packet - GCM case
def dissect_openvpn_data_packet_gcm(openvpn_payload, index, k_enc = b''):
	global client_data_cipher_key
	global server_data_cipher_key

	# Boolean which says "the GCM tag is correct"
	is_authenticated = False

	# First OpenVPN data packet proves that handshake has finished
	global openvpn_handshake_finished
	if openvpn_handshake_finished == False:
		openvpn_handshake_finished = True

	print("dissect_openvpn_data_packet_gcm")

	# Get peer id
	peer_id = int.from_bytes(openvpn_payload[1 : 4], 'big')
	data = openvpn_payload[4:]

	# Extract partial iv, gcm tag and ciphertext
	gcm_count = data[0 : 4]
	gcm_tag = data[4 : 20]
	gcm_ciphertext = data[20 : ]

	print("Peer ID : %r" % hex(peer_id))
	print("GCM counter : %r" % gcm_count)
	print("GCM tag : %r" % gcm_tag)
	print("GCM ciphertext : %r" % gcm_ciphertext)

	# Set the appropriate keys for encryption and hmac
	if k_enc != None:
		k_enc = binascii.unhexlify(k_enc)
	elif client_secret != None:
		if dissector_globals.is_from_client == True:
			k_enc = client_data_cipher_key
			iv = client_iv
		else:
			k_enc = server_data_cipher_key
			iv = server_iv

	# Decrypt the ciphertext
	if k_enc != None:

		cipher = AES.new(k_enc, AES.MODE_GCM, gcm_count + iv)
		additional_data = openvpn_payload[0 : 8]
		cipher.update(additional_data)
		plaintext = cipher.decrypt(gcm_ciphertext)

		print(f"plaintext: {plaintext}")

		try:
			tag = cipher.verify(gcm_tag)
			print("  OpenVPN GCM tag is correct :-)")

			# Process the decrypted plaintext
			dissect_openvpn_plaintext(plaintext, index)

		except ValueError:
			print("  OpenVPN GCM tag is not correct :-(")
			exit()

	print("");

## Dissect an OpenVPN data packet
def dissect_openvpn_data_packet(openvpn_payload, index, k_enc = b'', k_auth = b''):

	global aes_gcm
	print("dissect_openvpn_data_packet")

	if aes_gcm == True:
		dissect_openvpn_data_packet_gcm(openvpn_payload, index, k_enc)
	else:
		dissect_openvpn_data_packet_hmac(openvpn_payload, index, k_enc, k_auth)

## Dissect an OpenVPN ACK_V1 packet
def dissect_openvpn_ack_v1(openvpn_payload):

	global psk_mode_algo
	offset = 0

	openvpn_pkt_type = (openvpn_payload[offset]).to_bytes(1, 'big')
	offset += 1
	openvpn_packet_session_id = openvpn_payload[offset : offset + 8]
	offset += 8

	hmac_len = get_hmac_len(psk_mode_algo)
	openvpn_packet_hmac = openvpn_payload[offset : offset + hmac_len]
	offset += hmac_len

	if psk_mode_algo != None:
		openvpn_packet_id = openvpn_payload[offset : offset + 4]
		offset += 4
		openvpn_packet_time = openvpn_payload[offset : offset + 4]
		offset += 4

	openvpn_packet_id_array_len = openvpn_payload[offset : offset + 1]
	openvpn_packet_id_array_len_int = int.from_bytes(openvpn_packet_id_array_len, 'big')
	offset += 1
	openvpn_packet_id_array = openvpn_payload[offset : offset + 4 * openvpn_packet_id_array_len_int]
	offset += 4 * openvpn_packet_id_array_len_int
	openvpn_remote_session_id = openvpn_payload[offset : offset + 8]
	offset += 8

	print(" openvpn_payload : %r" % binascii.hexlify(openvpn_payload))
	print(" openvpn_pkt_type : %r" % binascii.hexlify(openvpn_pkt_type))
	print(" openvpn_session_id : %r" % binascii.hexlify(openvpn_packet_session_id))
	if psk_mode_algo != None:
		print(" openvpn_hmac : %r" % binascii.hexlify(openvpn_packet_hmac))
		print(" openvpn pkt_id : %r" % binascii.hexlify(openvpn_packet_id))
		print(" openvpn time : %r" % binascii.hexlify(openvpn_packet_time))
	print(" openvpn_packet_id_array_len : %r" % openvpn_packet_id_array_len)
	print(" openvpn_packet_id_array : %r" % binascii.hexlify(openvpn_packet_id_array))
	print(" openvpn_remote_session_id : %r" % binascii.hexlify(openvpn_remote_session_id))

	if psk_hmac_client != None and openvpn_handshake_finished == False and psk_mode_algo != None:
		hmac_input = b''
		hmac_input += openvpn_packet_id
		hmac_input += openvpn_packet_time
		hmac_input += openvpn_pkt_type
		hmac_input += openvpn_packet_session_id
		hmac_input += openvpn_packet_id_array_len
		hmac_input += openvpn_packet_id_array
		hmac_input += openvpn_remote_session_id

		if dissector_globals.is_from_client == True:
			openvpn_computed_hmac = compute_hmac(psk_hmac_client, psk_mode_algo, hmac_input)
		else:
			openvpn_computed_hmac = compute_hmac(psk_hmac_server, psk_mode_algo, hmac_input)

		if openvpn_computed_hmac == openvpn_packet_hmac:
			print(" ack_v1 HMAC is correct :-)")
		else:
			print(" ack_v1 HMAC is not correct :-(")

## Dissect an OpenVPN Hard_reset_client_v2 packet
def dissect_openvpn_hard_reset_client_v2(openvpn_payload):

	global psk_mode_algo
	global psk_hmac_client
	offset = 0

	openvpn_pkt_type = (openvpn_payload[offset]).to_bytes(1, 'big')
	offset += 1
	openvpn_packet_session_id = openvpn_payload[offset : offset + 8]
	offset += 8

	hmac_len = get_hmac_len(psk_mode_algo)
	openvpn_packet_hmac = openvpn_payload[offset : offset + hmac_len]
	offset += hmac_len

	if psk_mode_algo != None:
		openvpn_packet_id = openvpn_payload[offset : offset + 4]
		offset += 4
		openvpn_packet_time = openvpn_payload[offset : offset + 4]
		offset += 4
	openvpn_packet_trailer = openvpn_payload[offset : offset + 5]

	print(" openvpn_payload : %r" % binascii.hexlify(openvpn_payload))
	print(" openvpn_pkt_type : %r" % binascii.hexlify(openvpn_pkt_type))
	print(" openvpn_session_id : %r" % binascii.hexlify(openvpn_packet_session_id))
	if psk_mode_algo != None:
		print(" openvpn_hmac : %r" % binascii.hexlify(openvpn_packet_hmac))
		print(" openvpn pkt_id : %r" % binascii.hexlify(openvpn_packet_id))
		print(" openvpn time : %r" % binascii.hexlify(openvpn_packet_time))
	print(" openvpn trailer : %r" % binascii.hexlify(openvpn_packet_trailer))

	if psk_hmac_client != None and psk_mode_algo != None:
		hmac_input = b''
		hmac_input += openvpn_packet_id
		hmac_input += openvpn_packet_time
		hmac_input += openvpn_pkt_type
		hmac_input += openvpn_packet_session_id
		hmac_input += openvpn_packet_trailer

		openvpn_computed_hmac = compute_hmac(psk_hmac_client, psk_mode_algo, hmac_input)
		if openvpn_computed_hmac == openvpn_packet_hmac:
			print(" hard_reset_client_v2 HMAC is correct :-)")
		else:
			print(" hard_reset_client_v2 HMAC is not correct :-(")

## Dissect an OpenVPN Hard_reset_server_v2 packet
def dissect_openvpn_hard_reset_server_v2(openvpn_payload):

	global session_id_client
	global session_id_server
	global psk_mode_algo
	global psk_hmac_server
	offset = 0

	openvpn_pkt_type = (openvpn_payload[offset]).to_bytes(1, 'big')
	offset += 1
	openvpn_packet_session_id = openvpn_payload[offset : offset + 8]
	offset += 8

	hmac_len = get_hmac_len(psk_mode_algo)
	openvpn_packet_hmac = openvpn_payload[offset : offset + hmac_len]
	offset += hmac_len

	if psk_mode_algo != None:
		openvpn_packet_id = openvpn_payload[offset : offset + 4]
		offset += 4
		openvpn_packet_time = openvpn_payload[offset : offset + 4]
		offset += 4

	openvpn_packet_id_array = openvpn_payload[offset : offset + 5]
	offset += 5
	openvpn_remote_session_id = openvpn_payload[offset : offset + 8]
	offset += 8
	openvpn_packet_trailer = openvpn_payload[offset : offset + 4]
	offset += 4

	print(" openvpn_payload : %r" % binascii.hexlify(openvpn_payload))
	print(" openvpn_pkt_type : %r" % binascii.hexlify(openvpn_pkt_type))
	print(" openvpn_session_id : %r" % binascii.hexlify(openvpn_packet_session_id))
	if psk_mode_algo != None:
		print(" openvpn_hmac : %r" % binascii.hexlify(openvpn_packet_hmac))
		print(" openvpn pkt_id : %r" % binascii.hexlify(openvpn_packet_id))
		print(" openvpn time : %r" % binascii.hexlify(openvpn_packet_time))
	print(" openvpn_packet_id_array : %r" % binascii.hexlify(openvpn_packet_id_array))
	print(" openvpn_remote_session_id : %r" % binascii.hexlify(openvpn_remote_session_id))
	print(" openvpn trailer : %r" % binascii.hexlify(openvpn_packet_trailer))

	session_id_server = openvpn_packet_session_id
	session_id_client = openvpn_remote_session_id

	if psk_hmac_server != None and psk_mode_algo != None:
		hmac_input = b''
		hmac_input += openvpn_packet_id
		hmac_input += openvpn_packet_time
		hmac_input += openvpn_pkt_type
		hmac_input += openvpn_packet_session_id
		hmac_input += openvpn_packet_id_array
		hmac_input += openvpn_remote_session_id
		hmac_input += openvpn_packet_trailer

		openvpn_computed_hmac = compute_hmac(psk_hmac_server, psk_mode_algo, hmac_input)
		if openvpn_computed_hmac == openvpn_packet_hmac:
			print(" hard_reset_server_v2 HMAC is correct :-)")
		else:
			print(" hard_reset_server_v2 HMAC is not correct :-(")

## Derivate Crypto material for data encryption - old way
def derivate_openvpn_crypto_material():

	global client_data_cipher_key
	global server_data_cipher_key

	# if GCM is NOT used
	global client_data_hmac_key
	global server_data_hmac_key
	global hmac_algo

	# if GCM is used
	global client_iv
	global server_iv

	print("going to derivate crypto key for data packets !")

	seed = client_seed_1 + server_seed_1
	label = b'OpenVPN master secret'

	tls_dissector.selected_version = 0x0302

	openvpn_master_secret = tls_dissector.PRF(client_secret, label, seed)
	openvpn_master_secret = openvpn_master_secret[:48]
	print("openvpn_master_secret : %r" % binascii.hexlify(openvpn_master_secret) )

	seed = client_seed_2 + server_seed_2 + session_id_client + session_id_server
	label = b'OpenVPN key expansion'

	openvpn_keys = tls_dissector.PRF(openvpn_master_secret, label, seed)
	print("openvpn_keys : %r" % binascii.hexlify(openvpn_keys) )

	tls_dissector.selected_version = None

	# Get hmac keys and IVs. They cannot be used simultaneously,
	# but when this function is called, server hasn't told yet
	# whether it want to used GCM or not.
	client_data_cipher_key = openvpn_keys[ : 32]
	server_data_cipher_key = openvpn_keys[128 : 160]
	client_data_hmac_key = openvpn_keys[64 : 128]
	server_data_hmac_key = openvpn_keys[192 : 256]
	client_iv = openvpn_keys[64 : 72]
	server_iv = openvpn_keys[192 : 200]

	# truncate the openvpn data hmac key according to the algorithm size
	if hmac_algo == "SHA256":
		client_data_hmac_key = client_data_hmac_key[ : 32]
		server_data_hmac_key = server_data_hmac_key[ : 32]
	elif hmac_algo == "SHA1":
		client_data_hmac_key = client_data_hmac_key[ : 20]
		server_data_hmac_key = server_data_hmac_key[ : 20]

	# Dump hmac keys and IVs. They cannot be used simultaneously,
	# but when this function is called, server hasn't told yet
	# whether it want to used GCM or not.
	print("client_data_cipher_key : %r" % binascii.hexlify(client_data_cipher_key))
	print("client_data_hmac_key : %r" % binascii.hexlify(client_data_hmac_key))
	print("server_data_cipher_key : %r" % binascii.hexlify(server_data_cipher_key))
	print("server_data_hmac_key : %r" % binascii.hexlify(server_data_hmac_key))
	print("client_iv : %r" % binascii.hexlify(client_iv))
	print("server_iv : %r" % binascii.hexlify(server_iv))

## Derivate Crypto material for data encryption - new way, with exporter
def derivate_openvpn_crypto_from_exporter():

	global client_data_cipher_key
	global server_data_cipher_key

	# GCM is used
	global client_iv
	global server_iv

	print(f"exporter_secret: {tls13_dissector.exporter_secret}")

	label = b'EXPORTER-OpenVPN-datakeys'
	# data = SHA384(b'')
	data = binascii.unhexlify(b'38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b')
	exportsecret = tls13_dissector.HKDF_Expand_Label(tls13_dissector.exporter_secret, label, data, 48, SHA384)

	print(f"exportsecret: {binascii.hexlify(exportsecret)}")

	exporterlabel = b'exporter'
	openvpn_crypto_material = tls13_dissector.HKDF_Expand_Label(exportsecret, exporterlabel, data, 256, SHA384)

	print(f"openvpn_crypto_material: {binascii.hexlify(openvpn_crypto_material)}")

	client_data_cipher_key = openvpn_crypto_material[0 : 32]
	client_iv = openvpn_crypto_material[64 : 72]
	server_data_cipher_key = openvpn_crypto_material[128 : 160]
	server_iv = openvpn_crypto_material[128 + 64 : 128 + 72]

	print(f"client_data_cipher_key: {binascii.hexlify(client_data_cipher_key)}")
	print(f"server_data_cipher_key: {binascii.hexlify(server_data_cipher_key)}")
	print(f"client_iv: {binascii.hexlify(client_iv)}")
	print(f"server_iv: {binascii.hexlify(server_iv)}")

def parse_tls_control_payload(tls_payload):
	if tls_payload == None:
		return

	global client_secret
	global client_seed_1
	global client_seed_2
	global server_seed_1
	global server_seed_2

	global client_data_cipher_key
	global server_data_cipher_key

	global aes_gcm

	global crypto_via_exporter_mechanism

	# set the encryption algorithm according to the server's PUSH_REPLY:
	# - truncate the openvpn data encryption key according to the algorithm size
	# - treat specific case of GCM
	# - recognize if session keys are established using openvpn_PRF (old way) or through exporter mechanism (new way)
	if tls_payload.find(b'PUSH_REPLY') != -1:

		if tls_payload.find(b'tls-ekm') != -1:
			print(" OpenVPN session keys are established via exporter mechanism !")
			crypto_via_exporter_mechanism = True

		if tls_payload.find(b'cipher AES-256-CBC') != -1:
			print(" OpenVPN traffic will be encrypted with AES-256-CBC")

		elif tls_payload.find(b'cipher AES-128-CBC') != -1:
			print(" OpenVPN traffic will be encrypted with AES-128-CBC")

			client_data_cipher_key = client_data_cipher_key[:16]
			server_data_cipher_key = server_data_cipher_key[:16]

		elif tls_payload.find(b'cipher AES-256-GCM') != -1:
			print(" OpenVPN traffic will be encrypted with AES-256-GCM")
			aes_gcm = True

	if tls_payload.find(b'tls-client') != -1:

		client_secret = tls_payload[5 : 5 + 48]
		client_seed_1 = tls_payload[5 + 48 : 5 + 48 + 32]
		client_seed_2 = tls_payload[5 + 48 + 32 : 5 + 48 + 32 + 32]

		print("client_secret : %r" % binascii.hexlify(client_secret))
		print("client_seed_1 : %r" % binascii.hexlify(client_seed_1))
		print("client_seed_2 : %r" % binascii.hexlify(client_seed_2))

	if tls_payload.find(b'tls-server') != -1:

		server_seed_1 = tls_payload[5 : 5 +32]
		server_seed_2 = tls_payload[5 + 32 : 5 + 32 + 32]

		print("server_seed_1 : %r" % binascii.hexlify(server_seed_1))
		print("server_seed_2 : %r" % binascii.hexlify(server_seed_2))

		derivate_openvpn_crypto_material()

	# if tls-ekm was found, we do derivation via exporter
	if crypto_via_exporter_mechanism is True:
		derivate_openvpn_crypto_from_exporter()

def dissect_openvpn_control_v1(openvpn_payload):

	global psk_mode_algo
	offset = 0

	openvpn_pkt_type = (openvpn_payload[offset]).to_bytes(1, 'big')
	offset += 1
	openvpn_packet_session_id = openvpn_payload[offset : offset + 8]
	offset += 8

	hmac_len = get_hmac_len(psk_mode_algo)
	openvpn_packet_hmac = openvpn_payload[offset : offset + hmac_len]
	offset += hmac_len

	if psk_mode_algo != None:
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
	if psk_mode_algo != None:
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

	if openvpn_handshake_finished == False and psk_mode_algo != None:
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
				openvpn_computed_hmac = compute_hmac(psk_hmac_client, psk_mode_algo, hmac_input)
			elif dissector_globals.is_from_client == False:
				openvpn_computed_hmac = compute_hmac(psk_hmac_server, psk_mode_algo, hmac_input)

			if openvpn_computed_hmac == openvpn_packet_hmac:
				print(" control_v1 HMAC is correct :-)")
			else:
				print(" control_v1 HMAC is not correct :-(")

	tls_pseudo_packet = add_tcp_ip_layer(openvpn_tls_payload)
	tls13_dissector.dissect_tls_packet(tls_pseudo_packet, 0)

	parse_tls_control_payload(tls13_dissector.current_plaintext)

def dissect_openvpn_control_packet(openvpn_payload, index):

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
		dissect_openvpn_control_packet(openvpn_payload, index)

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
