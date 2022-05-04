# wireshark & openvpn

- udp port destination 1194

- message de type 0x38 (opcode sur 1 octet) client->serveur
	- session ID sur 8 octets
	- HMAC sur 20 octets
	- Packet-ID sur 4 octets
	- Date sur 4 octets
	- d'autres trucs

- message de type 0x28 client->serveur
	- même structure

- message de type 0x40 serveur->client
	- même structure

- message de type 0x20 serveur->client
	- même structure

- message de type 0x48
	- peer ID sur 3 octets

- Certains packets ont un packet TLS à la fin

- un session ID commun aux paquets client->serveur, un session ID commun aux paquets serveur->client

# interface tun/tap

- Interface réseau virtuelle recevant et délivrant du trafic réseau à programme dans l'espace utilisateur.
- Une interface tap est de niveau 2 (on lui envoie/on en reçoit des trames ethernet)
- Une interface tun est de niveau 3 (on lui envoie/on en reçoit des datagrammess IP)
- Openvpn utilise une interface tun

# Static Key mode vs SSL/TLS mode

## Static Key mode

- On utilise une PSK. Simple à configurer, mais pas de PFS.

## SSL/TLS mode

- Cryptographie à clé publique. Un canal de contrôle TLS est monté pour échanger les clés de chiffrement et d'authentification.

# structure du fichier <user>.ovpn

- proto : tcp ou udp

- client : indique qu'on a ici un fichier de configuration d'un client

- remote : <ip>:<port> du serveur OpenVPN. Il peut y en avoir plusieurs.

- remote-random : quand il y a plus d'un token 'remote', si ce token est présent alors on choisit aléatoirement.

- nobind : on ne se bind pas sur le port source.

- mssfix : la MSS du tun device.

- remote-cert-tls

- cipher : l'algorithme de chiffrement et son mode opératoire

- noeud <ca>...</ca> : le certificat racine
- noeud <cert>...</cert> : le certificat du client
- noeud <key>...</key> : la clé privée du client

- noeud <tls-auth>...</tls-auth> : 

- persist-key : On ne relit pas le fichier de configuration lorsque le processus reçoit un SIGUSR1
- persist-tun : On ne fait de fermeture/réouverture du device tun lorsqu'un SIGUSR1 est reçu

- comp-lzo no|yes : (dés)activation de la compression lzo. À désactiver pour se prémunir de la faille VORACLE !

- remote-cert-tls client|server : Exige que le certificat du client|serveur soit signé avec un key usage & un extended key usage explicite. Devrait être présent !

- auth <algo> : les paquets du canal de données et ceux du canal de contrôle (s'il est présent) sont authentifiés avec un HMAC utilisant la fonction de hachage <algo>.
  Par défaut SHA1 est utilisé, ce qui est pas ouf.
  Si un mode AEAD est utilisé (GCM par exemple), ce token est ignoré pour le canal de données (mais reste utilisé par le canal tls-auth).
  En mode static-key, la clé HMAC est incluse dans le fichier généré par --genkey.
  En mode TLS, ce tte clé est générée dynamiquement et partagée via le canal TLS de contrôle.

- cipher <algo> : Algorithme (et mode) de chiffrement utilisé pour le canal de données.
  Par défaut BF-CBC est utilisé.
  Lorsque l'option de négociation d'algorithme (NCP) est utilisée, les versions "récentes" (>= 2.4) upgraderont automatiquement à AES-256-GCM.
  BF-CBC n'est pas recommandé ! (bloc de 64 bits => sweet32)
  Du fait de sweet32, les algo utilisant des algos de 64 bits ne sont plus disponibles à partir de la version 2.6

- secret <file> <direction> : Fichier contenant la PSK, si le mode PSK est utilisé.
  Le paramètre <direction> peut valoir HMAC-send, cipher-encrypt, HMAC-receive ou cipher-decrypt.

# lancer le client openvpn

- Client installé avec apt :

```
root@ankou:/home/thomas/perso/tryhackme# /usr/sbin/openvpn klook.ovpn
```

- Client compilé des sources :

```
root@ankou:/home/thomas/perso/tryhackme# /usr/localsbin/openvpn --data-ciphers AES-256-CBC --config klook.ovpn
```

- On a rajouté l'option --data-ciphers pour que autoriser l'utilisation de AES-256-CBC

# structure des paquets, canal de données

Le canal de données utilise encrypt-then-mac :

plaintext -> hmac | iv | ciphertext 
