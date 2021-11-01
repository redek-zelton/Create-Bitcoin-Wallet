# Generate Bitcoin Wallet with BIP39-BIP32

## Wallets
The word "wallet" is used to describe a few different things in bitcoin.
A tool where all your UTXO are in.
Three type of wallet: Cold Wallet, Hot Wallet, Hardware Wallet

### Nondeterministic Wallet
Each key is independently generated from a random number. The keys are not related to each other. This type of wallet is also known as a JBOK wallet from the phrase "Just a Bunch Of Keys."

### Deterministic Wallet
All the keys are derived from a single master key, known as the seed. All the keys in this type of wallet are related to each other and can be generated again if one has the original seed. There are a number of different key derivation methods used in deterministic wallets.

## BIP_39-BIP_32
### Generating mnemonic words
- Create a random sequence (entropy) of 128 to 256 bits.
```
Un entier aléatoire (seed):  204048516592372993657375166504414623270
Seed en binaire :  10011001100000100101000010011000001000010000011110111001010111111100100100010010100000000111011101001001100001100011011000100110
L'entropy :  998250982107b95fc912807749863626
Encode :  b'\x99\x82P\x98!\x07\xb9_\xc9\x12\x80wI\x866&'
```
- Create a checksum of the random sequence by taking the first (entropy-length/32) bits of its SHA256 hash, add the checksum to the end of the random sequence, and split the result into 11-bit length segments.
```
Lot de 11 bits :  ['10011001100', '00010010100', '00100110000', '01000010000', '01111011100', '10101111111', '00100100010', '01010000000', '01110111010', '01001100001', '10001101100', '01001100001']
```
- Map each 11-bit value to a word from the predefined dictionary of 2048 words, and the mnemonic code is the sequence of words.
```
office barely champion dragon knee quiz cattle exotic jar equip mirror equip
```

- PBKDF2 stretches the mnemonic and salt parameters using 2048 rounds of hashing with the HMAC-SHA512 algorithm, producing a 512-bit value as its final output. That 512-bit value is the seed.
```
BIP39 Seed :  df7bcd73885db87c5cc56c47e17f5c8375685459353a5fece40e7f59fe5be9187e44440a652b421eeb0db7a57b049dbfa4fe1837a18e771ac5bf514bbdfd5504
```

So then, with the BIP39 Seed, we can generate our first NonDeterministic Wallet
```
-------------Generer les informations Parent------------------------

La Master Private KEY :  C7p64v4yGDSKQfeG2YnrKF6YsmjCNjzmFWv3cxt4orbX

La Master Chain Code :  3Cjwbeo7jTKzbus1ECEYje2TJEoYkGK8XEDftVr8E3qS

La Master Public KEY :  dCYW8Y2VprhKW8WCV69feFd1c9E2rsPWYfkDu1H1J7ht

Parent Private KEY :  xprv9s21ZrQH143K2PFfLcrTcEhuhc9qipBLkNfsynTyqmHA84KPSAqgrSuNAXeEn5q4iHzyye5VEzrJtASD9XD9WMmTyEc3vpkDzefBNTRimpq

Parent Public KEY :  xpub661MyMwAqRbcEsL8SePTyNeeFdzL8GuC7bbUnAsbQ6p8zreXyi9wQFDr1mce7geS2Un16wLigeHuW6eZzWEv7v72NcyWMyFETdV1Q8G3MtH
```

And With the Master Private Key, i can generate all Deterministic Wallet
```
 ------------------Generation d'une clé enfant à l'index  3  et à la dérivation  4 ----------------

La Child Private KEY 256 bits :  6FkwurUGb8UDuH53V1NooWDNvQSurMPYFssakyJR6Tur

La Child Chain Code 256 bits :  D1RirwJG5LWjCS76itVBj24n5ZofVLobCiPe1wx87mA

La Child Public KEY 256 bits :  ekWzgomU4VFHQx1DVAV5NtYFqoDfGUt9V7fJxvJjhSM3

Child Private KEY :  xprv9xfR9CxLdy4Jj3W1kutDutFFr5iQYBBFiQXzrLMd6P9TEoYXXCTHJ1yJGPKVFgwZgNVRRLSujxsr3aQPd4rtZRduA37DsdgXqDRV1TrvRDS

Child Public KEY :  xpub6BemYiVEULcbwXaUrwREH2BzQ7Ytwdu75dTbeimEeigS7bsg4jmXqpHn7YJB1r6dRYVhxVD8JaRttBVZBoPRgmoU9EiN79qCRyprm2vWsX4
```
