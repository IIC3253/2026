from sage.all import *

p = -1
bit_length = 2048
while True:
    n = 2
    while int(n).bit_length() < bit_length:
        cur = random_prime(100)
        n *= cur
    
    p = n + 1
    if is_prime(p):
        break

print(p)