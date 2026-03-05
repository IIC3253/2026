from hashlib import sha256

def hash_password(key: str) -> str:
    assert len(key) <= 32, "La clave debe tener a lo más 32 caracteres"
    for c in key:
        assert(32 <= ord(c) <= 126), "La clave sólo debe contener caracteres imprimibles"
    alg = sha256()
    alg.update(key.encode())
    return alg.hexdigest()

# Ejemplo de uso
mi_clave = "hola1234"
hash_mi_clave = hash_password(mi_clave)

# La siguiente instrucción debe imprimir 3e6dc62f220c57f4e44e3dd541c175b3a4fd22986bafa16d47ce3d4c2b224ac8
print(hash_mi_clave)