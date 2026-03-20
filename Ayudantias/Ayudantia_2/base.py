
# funcion para puntuar un posible caracter de llave
def score_function(text_bytes):
    pass

# funcion para obtener la llave sabiendo el largo de la llave previamente.
def recover_key(cipher_bytes, key_len):
    pass

# funcion para desencriptar el texto
def decrypt(cipher_bytes, key):
    return bytes((b - key[i % len(key)]) % 128 for i, b in enumerate(cipher_bytes))


with open("cipher.txt", "rb") as f:
    cipher_bytes = list(f.read())

key_len = 30
key = recover_key(cipher_bytes, key_len)

print("Recovered key: ", key)

# Decrypt with the key
plaintext = decrypt(cipher_bytes, key)

print("Decrypted preview:\n", plaintext.decode('ascii', errors='replace'))