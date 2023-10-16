# wireshark & openvpn

- udp port destination 1194

- message de type `0x38` (opcode sur 1 octet) client->serveur
	- session ID sur 8 octets
	- HMAC sur 20 octets
	- Packet-ID sur 4 octets
	- Date sur 4 octets
	- d'autres trucs

- message de type `0x28` client->serveur
	- même structure

- message de type `0x40` serveur->client
	- même structure

- message de type `0x20` serveur->client
	- même structure

- message de type `0x48`
	- peer ID sur 3 octets

- Certains packets ont un packet TLS à la fin

- un session ID commun aux paquets client->serveur, un session ID commun aux paquets serveur->client

# interface tun/tap

- Interface réseau virtuelle recevant et délivrant du trafic réseau à programme dans l'espace utilisateur.

- Une interface tap est de niveau 2 (on lui envoie/on en reçoit des trames ethernet)

- Une interface tun est de niveau 3 (on lui envoie/on en reçoit des datagrammes IP)

- Openvpn utilise une interface tun

# Static Key mode vs SSL/TLS mode

## Static Key mode

- On utilise une PSK. Simple à configurer, mais pas de PFS.

## SSL/TLS mode

- Cryptographie à clé publique. Un canal de contrôle TLS est monté pour échanger les clés de chiffrement et d'authentification.

# structure du fichier <user>.ovpn

- proto : tcp ou udp

- client : indique qu'on a ici un fichier de configuration d'un client

- remote : `<ip>:<port>` du serveur OpenVPN. Il peut y en avoir plusieurs.

- remote-random : quand il y a plus d'un token 'remote', si ce token est présent alors on choisit aléatoirement.

- nobind : on ne se bind pas sur le port source.

- mssfix : la MSS du tun device.

- remote-cert-tls

- cipher : l'algorithme de chiffrement et son mode opératoire

- noeud `<ca>...</ca>` : le certificat racine

- noeud `<cert>...</cert>` : le certificat du client

- noeud `<key>...</key>` : la clé privée du client

- noeud `<tls-auth>...</tls-auth>` : 

- persist-key : On ne relit pas le fichier de configuration lorsque le processus reçoit un `SIGUSR1`

- persist-tun : On ne fait de fermeture/réouverture du device tun lorsqu'un `SIGUSR1` est reçu

- comp-lzo no|yes : (dés)activation de la compression lzo. À désactiver pour se prémunir de la faille VORACLE !

- remote-cert-tls client|server : Exige que le certificat du client|serveur soit signé avec un key usage & un extended key usage explicite. Devrait être présent !

- auth `<algo>` : les paquets du canal de données et ceux du canal de contrôle (s'il est présent) sont authentifiés avec un HMAC utilisant la fonction de hachage <algo>.
  Par défaut SHA1 est utilisé, ce qui est pas ouf.
  Si un mode AEAD est utilisé (GCM par exemple), ce token est ignoré pour le canal de données (mais reste utilisé par le canal tls-auth).
  En mode static-key, la clé HMAC est incluse dans le fichier généré par --genkey.
  En mode TLS, ce tte clé est générée dynamiquement et partagée via le canal TLS de contrôle.

- cipher `<algo>` : Algorithme (et mode) de chiffrement utilisé pour le canal de données.
  Par défaut BF-CBC est utilisé.
  Lorsque l'option de négociation d'algorithme (NCP) est utilisée, les versions "récentes" (>= 2.4) upgraderont automatiquement à AES-256-GCM.
  BF-CBC n'est pas recommandé ! (bloc de 64 bits => sweet32)
  Du fait de sweet32, les algo utilisant des algos de 64 bits ne sont plus disponibles à partir de la version 2.6

- secret `<file> <direction>` : Fichier contenant la PSK, si le mode PSK est utilisé.
  Le paramètre `<direction>` peut valoir HMAC-send, cipher-encrypt, HMAC-receive ou cipher-decrypt.

# lancer le client openvpn

- Client installé avec apt :

```
root@ankou:/home/thomas/perso/tryhackme# /usr/sbin/openvpn klook.ovpn
```

- Client compilé des sources :

```
root@ankou:/home/thomas/perso/tryhackme# /usr/localsbin/openvpn --data-ciphers AES-256-CBC --config klook.ovpn
```

- On a rajouté l'option `--data-ciphers` pour autoriser l'utilisation de AES-256-CBC

# structure générale des paquets

```
+----------------+-------------------------+
| opcode + keyID | reste du paquet OpenVPN |
+----------------+-------------------------+
<----1 octet---->

```

- L'opcode occupe les 5 premiers bits du premier octet, le keyID les 3 suivants.

- Visiblement le keyID indexe la session SSL/TLS utilisée pour négocier les clés.

## tableau des opcodes existants

```
+------+--------------------------------+-----------------------------------------+
| 0x01 | P_CONTROL_HARD_RESET_CLIENT_V1 | paquet client de réinitialisation - v1  |
+------+--------------------------------+-----------------------------------------+
| 0x02 | P_CONTROL_HARD_RESET_SERVER_V1 | paquet serveur de réinitialisation - v1 |
+------+--------------------------------+-----------------------------------------+
| 0x03 | P_CONTROL_SOFT_RESET_V1        | nouvelle clé, sorte de CCS OpenVPN      |
+------+--------------------------------+-----------------------------------------+
| 0x04 | P_CONTROL_V1                   | paquet du canal de contrôle             |
+------+--------------------------------+-----------------------------------------+
| 0x05 | P_ACK_V1                       | paquet d'acquittement                   |
+------+--------------------------------+-----------------------------------------+
| 0x06 | P_DATA_V1                      | paquet du canal de données - v1         |
+------+--------------------------------+-----------------------------------------+
| 0x07 | P_CONTROL_HARD_RESET_CLIENT_V2 | paquet client de réinitialisation - v2  |
+------+--------------------------------+-----------------------------------------+
| 0x08 | P_CONTROL_HARD_RESET_SERVER_V2 | paquet serveur de réinitialisation - v2 |
+------+--------------------------------+-----------------------------------------+
| 0x09 | P_DATA_V2                      | paquet du canal de données - v2         |
+------+--------------------------------+-----------------------------------------+
| 0x0A | P_CONTROL_HARD_RESET_CLIENT_V3 | paquet client de réinitialisation - v3  |
+------+--------------------------------+-----------------------------------------+
```
- Dans la version 2 d'OpenVPN, les paquets `0x01` et `0x02` sont invalides.

## structure des paquets, canal de données

- On parle des paquets `P_DATA_V2`

```
+----------------+----------+-------------+-----------------------------+-----------------+-------------+-----------+-----------+
| opcode + keyID | Peer ID  |    HMAC     | Vecteur d'initialisation IV | Sequence Number | Compression | plaintext |  padding  |
+----------------+----------+-------------+-----------------------------+-----------------+-------------+-----------+-----------+
<----1 octet-----><-1 octet-><- variable -><- variable -- 8/16 octets --><--- 4 octets ---><- 1 octet --><-variable-><-variable->
                            <------------------------------------------- authentifié ------------------------------------------->
                                                                        <------------------------ chiffré ---------------------->
```
- Le sequence number est incrémenté à chaque paquet

- L'octet de compression indique l'algorithme de compression utilisé (`0xfa` = pas de compression)

- Le padding est un padding PKCS#5 (`\x03\x03\x03`)

## structure des paquets, canal de contrôle

- `P_CONTROL_HARD_RESET_CLIENT_V2` : 

```
+----------------+------------+------+-----------+----------+--------------------------------+-------------------+
| opcode + keyID | Session ID | HMAC | Packet ID | Net Time | Message Packet-ID Array Length | Message Packet-ID |
+----------------+------------+------+-----------+----------+--------------------------------+-------------------+
        1              8                   4          4                     1
```

- Le `P_CONTROL_HARD_RESET_SERVER_V2` a une structure similaire, mais contient un Packet-ID Array embarquant le Session ID du client

- `P_ACK_V1` : structure similaire

- `P_CONTROL_V1` : structure similaire, mais avec des data après l'en-tête. Des paquets TLS en l'occurrence !

# cinématique

```
client                                   serveur
  | --- P_CONTROL_HARD_RESET_CLIENT_V2 ---> |
  | <-- P_CONTROL_HARD_RESET_SERVER_V2 ---- |
  | -------------- P_ACK_V1 --------------> |
  <------------ handshake TLS -------------->
  | <---------- P_CONTROL_V1 -------------- |
  | ----------------- P_ACK_V1 -----------> |
  | -------------- P_DATA_V2 -------------> |
  | <------------- P_DATA_V1 -------------- |
  
```

# Génération des clés

`<tls-auth>` : "HMAC-firewall", visiblement utilisé pour empêcher le déni de service/prise d'empreinte sur le serveur.
Cette PSK est juste découpée en morceau sans autre mécanisme de dérivation : Les clés utilisées sont donc fixe d'une session à l'autre.

# Handshake TLS
