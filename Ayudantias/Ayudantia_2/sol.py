
# funcion para puntuar un posible caracter de llave
def score_function(text_bytes):
    score = 0
    for b in text_bytes:
        if 32 <= b <= 126: # Asignamos puntaje si el caracter es imprimible
            score += 1
            if 97 <= b <= 122: # Asignamos mas puntaje si es una letra minuscula
                score += 1
                if chr(b) in 'aeiou': # Asignamos mas puntaje si es vocal
                    score += 0.5
            if b == 32: # Asignamos puntaje si es un espacio
                score += 2
    return score

# funcion para obtener la llave sabiendo el largo de la llave previamente.
def recover_key(cipher_bytes, key_len):
    key = [] # arreglo de bytes que representara la llave candidata

    for i in range(key_len): # iteramos por el largo de la llave
        column = cipher_bytes[i::key_len]
        best_score = float('-inf')
        best_key_byte = 0
        for k in range(128): # iteramos por todos los bytes posibles para cada caracter de la llave
            decrypted_column = [(b - k) % 128 for b in column] # arreglo que contiene todos los caracteres deencriptados con la misma posicion de la llave
            score = score_function(decrypted_column)
            if score > best_score:
                best_score = score
                best_key_byte = k
        key.append(best_key_byte) # agregamos el mejor candidato para la posicion de la llave
    return key

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