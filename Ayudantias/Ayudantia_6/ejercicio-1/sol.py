import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def main():
    base_url = "http://aes.cryptohack.org/ecb_oracle/encrypt/"
    # r = requests.get(url=base_url + payload)
    # res = r.json()

if __name__ == "__main__":
    main()
