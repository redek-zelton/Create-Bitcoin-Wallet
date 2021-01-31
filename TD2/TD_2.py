#Libraire
import binascii
import hmac
import hashlib
import struct
import ecdsa
import base58
import os, sys
import unicodedata
from ecdsa.curves import SECP256k1
from ecdsa.ecdsa import int_to_string, string_to_int





#############
#   BIP_39  #
#############

### Créer un entier aléatoire pouvant servir
#de seed à un wallet de façon sécurisée
bits = 128
E128=""   # 128 bits
Entier=0 
Entropy=""                # generateur de l'entier
while len(E128) != bits:
    sec=os.urandom(bits//8)  # 8 bits
    Entier=int.from_bytes(sec,sys.byteorder)
    E128=bin(Entier)[2:]

for i in range(len(E128)//4):
    value=E128[4*i:4*(i+1)]
    Entropy+=hex(int(value,2))[2]

print('\nUn entier aléatoire (seed): ',Entier)
print('\nSeed en binaire : ',E128)
print('\nL\'entropy : ',Entropy)

encode = Entropy.strip()
encode = binascii.unhexlify(Entropy)
print('\nEncode : ',encode)


#####Représenter cette seed en binaire et le
####découper en lot de 11 bits 
SHA256 = hashlib.sha256(encode).hexdigest()
E132 =  E128+bin(int(SHA256,16))[2:].zfill(256)[: bits//32]
lot =[]
for i in range(len(E132)//11):
    value = E132[11*i:11*(i+1)]
    lot.append(value)

print('\nLot de 11 bits : ',lot)



### Attribuer
## à chaque lot un mot selon la
## liste BIP 39 et afficher la seed en
## mnémonique (2 pts)

with open("wordlist/english.txt", "r") as f:
         wordlist = [w.strip() for w in f.readlines()]

list_seed= []
for i in lot:
    indx = int(i,2)
    list_seed.append(wordlist[indx])

print('\nAfficher la seed : ',list_seed) 

seed=" ".join(list_seed)
print('\nAfficher la seed : ',seed)

with open('seed.txt',"w") as f:
    f.write(seed)




#Permettre l’import d’une seed
#mnémonique
import_seed=""
with open('seed.txt',"r") as f:
    import_seed=f.readline()

print("\nLe seed importé : ",import_seed)

normalized_mnemonic = unicodedata.normalize("NFKD", import_seed)
password = ""
normalized_passphrase = unicodedata.normalize("NFKD", password)
passphrase = "mnemonic" + normalized_passphrase
mnemonic = normalized_mnemonic.encode("utf-8")
passphrase = passphrase.encode("utf-8")
bin_seed = hashlib.pbkdf2_hmac("sha512", mnemonic, passphrase, 2048)

BIP39_seed=binascii.hexlify(bin_seed[:64]).decode()
print("\nBIP39 Seed : ",BIP39_seed)





##########
# BIP_32 #
##########

#Hmac
#BIP39_seed
seed = binascii.unhexlify(BIP39_seed)
#seed = binascii.unhexlify("8178779bee02dd20eca25924352fa7994f41023c2036c0a40b4715ed8405c95c0c03574a0b8eed54b1554e3bde0e8e856671ed30c102d4f8b463f87803824500") #METTRE ICI LE SEED EN HEX
#HMAC512= hashlib.pbkdf2_hmac("sha512", seed, b"Bitcoin seed", 2048)  # FONCTION HMAC-SHA512
HMAC512 = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
def diffusion(HMAC512,depth,fingerp,index):
    #EXTRATION
    Hmac_l, Hmac_r= HMAC512[:32], HMAC512[32:]
    Master_private_key = Hmac_l 
    Master_chain_code = Hmac_r
    xprv = binascii.unhexlify("0488ade4") # FORME BINAIRE xprv
    xpub = binascii.unhexlify("0488b21e") #FORME BINAIRE xpub
    ##
    depth = base58.b58decode(str(depth))        # DERIVATION
    fingerp= base58.b58decode(str(fingerp))       #b"\0\0\0\0"   
    child = struct.pack('>L', index)   # CHILD
    ## TRANSFORMATION DE LA CLE PRIVEE
    k_priv = ecdsa.SigningKey.from_string(Master_private_key, curve=SECP256k1)
    K_priv = k_priv.get_verifying_key()
    #CONVERTION
    data_priv = depth + (k_priv.to_string())

    # serialisation
    if K_priv.pubkey.point.y() & 1:
        data_pub = b'\3' + int_to_string(K_priv.pubkey.point.x())
    else:
        data_pub = b'\2' + int_to_string(K_priv.pubkey.point.x())

    clé_privée = xprv + depth + fingerp + child + Master_chain_code + data_priv
    clé_publique = xpub + depth + fingerp + child + Master_chain_code + data_pub

    # Hasher les clés
    hashed_xprv = hashlib.sha256(clé_privée).digest()
    hashed_xprv = hashlib.sha256(hashed_xprv).digest()
    hashed_xpub = hashlib.sha256(clé_publique).digest()
    hashed_xpub = hashlib.sha256(hashed_xpub).digest()


    # les clés
    clé_privée += hashed_xprv[:4]
    clé_publique += hashed_xpub[:4]
    return Master_private_key,Master_chain_code,data_pub,clé_privée,clé_publique

##params
depth=1
fingerp=1111
index=0
Master_private_key,Master_chain_code,data_pub,clé_privée,clé_publique=diffusion(HMAC512,depth,fingerp,index)



## Extraire la master private key et le chain
## code 
##Extraire la master public key
# les clés à BIP32 Derivation Path : m/
print('\n\n-------------Generer les informations Parent------------------------')
print("\nLa Master Private KEY : ",base58.b58encode(Master_private_key).decode())
print("\nLa Master Chain Code : ",base58.b58encode(Master_chain_code).decode())
print("\nLa Master Public KEY : ",base58.b58encode(data_pub).decode())
print("\nParent Private KEY : ",base58.b58encode(clé_privée).decode())
print("\nParent Public KEY : ",base58.b58encode(clé_publique).decode())





#Générer un clé enfant
# Valeur
index=0
depth=1
fingerp=1111
def génerer_child(data_pub,Parent_chain_code,index,depth,fingerp):
    # Hasher Parent Public Key + Parent Chain Code + index Number
    seed_child = data_pub+Parent_chain_code+str(index).encode()
    HMAC512_Child = hmac.new(b"Bitcoin seed",seed_child, hashlib.sha512).digest()
    Master_private_key,Master_chain_code,data_pub,clé_privée,clé_publique=diffusion(HMAC512_Child,depth,fingerp,index)
    return Master_private_key,Master_chain_code,data_pub,clé_privée,clé_publique

Child_private_key,Child_chain_code,Child_data_pub,Child_clé_privée,Child_clé_publique=génerer_child(data_pub,Master_chain_code,index,depth,fingerp)
#Convertion
print('\n\n ------------------Generation d\'une clé enfant----------------')
print("\nLa Child Private KEY 256 bits : ",base58.b58encode(Child_private_key).decode())
print("\nLa Child Chain Code 256 bits : ",base58.b58encode(Child_chain_code).decode())
print("\nLa Child Public KEY 256 bits : ",base58.b58encode(Child_data_pub).decode())
print("\nChild Private KEY : ",base58.b58encode(Child_clé_privée).decode())
print("\nChild Public KEY : ",base58.b58encode(Child_clé_publique).decode())





#Générer une clé enfant à l’index N
index_N=int(input("Générer une clé enfant à l’index N : "))
Child_private_key,Child_chain_code,Child_data_pub,Child_clé_privée,Child_clé_publique=génerer_child(data_pub,Master_chain_code,index_N,depth,fingerp)
#Convertion
print('\n\n ------------------Generation d\'une clé enfant à l\'index ',index_N,'----------------')
print("\nLa Child Private KEY 256 bits : ",base58.b58encode(Child_private_key).decode())
print("\nLa Child Chain Code 256 bits : ",base58.b58encode(Child_chain_code).decode())
print("\nLa Child Public KEY 256 bits : ",base58.b58encode(Child_data_pub).decode())
print("\nChild Private KEY : ",base58.b58encode(Child_clé_privée).decode())
print("\nChild Public KEY : ",base58.b58encode(Child_clé_publique).decode())





#Générer une clé enfant
#à l’index N au
#niveau de dérivation M
index_N=int(input("Générer une clé enfant à l’index N : "))
derivation=int(input(' Générer une dérivation de niveau M : '))
Child_private_key,Child_chain_code,Child_data_pub,Child_clé_privée,Child_clé_publique=génerer_child(data_pub,Master_chain_code,index_N,derivation,fingerp)
#Convertion
print('\n\n ------------------Generation d\'une clé enfant à l\'index ',index_N,' et à la dérivation ',derivation,'----------------')
print("\nLa Child Private KEY 256 bits : ",base58.b58encode(Child_private_key).decode())
print("\nLa Child Chain Code 256 bits : ",base58.b58encode(Child_chain_code).decode())
print("\nLa Child Public KEY 256 bits : ",base58.b58encode(Child_data_pub).decode())
print("\nChild Private KEY : ",base58.b58encode(Child_clé_privée).decode())
print("\nChild Public KEY : ",base58.b58encode(Child_clé_publique).decode())




