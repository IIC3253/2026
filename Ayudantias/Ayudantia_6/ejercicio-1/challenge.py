# Fuente: https://aes.cryptohack.org/ecb_oracle/
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = "?"
FLAG = "?"

def encrypt(plaintext):
    plaintext = bytes.fromhex(plaintext)

    padded = pad(plaintext + FLAG.encode(), 16)
    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        encrypted = cipher.encrypt(padded)
    except ValueError as e:
        return {"error": str(e)}

    return {"ciphertext": encrypted.hex()}
