import random
from hashlib import sha256


def _is_natural_power(n):
    search_exponent = 2
    avoid_exponents = set()

    while pow(2, search_exponent) <= n:
        if search_exponent not in avoid_exponents:
            search_start = 2
            i = 2
            while search_start ** search_exponent < n:
                search_start *= 2
                avoid_exponents.add(search_exponent * i)
                i += 1

            upper = search_start
            lower = search_start // 2

            while lower != upper:
                mid = (upper + lower) // 2
                result = pow(mid, search_exponent)
                if result < n:
                    lower = mid + 1
                elif result > n:
                    upper = mid
                else:
                    return True

            if pow(upper, search_exponent) == n:
                return True

        search_exponent += 1

    return False


def _extended_euclid(a, b):
    if a > b:
        return _extended_euclid_base(a, b)
    return _extended_euclid_base(b, a)


def _extended_euclid_base(a, b):
    prev_r, r = a, b
    prev_s, s = 1, 0
    prev_t, t = 0, 1

    while r != 0:
        q = prev_r // r
        prev_r, r = r, prev_r % r
        prev_s, s = s, prev_s - q * s
        prev_t, t = t, prev_t - q * t

    return prev_r, prev_s, prev_t


def is_probably_prime(n, iterations=100):
    if n == 2:
        return True
    if n % 2 == 0 or n == 1:
        return False
    if _is_natural_power(n):
        return False

    found_negative = False
    for _ in range(iterations):
        a = random.randint(1, n - 1)
        if _extended_euclid(a, n)[0] > 1:
            return False
        b = pow(a, (n - 1) // 2, n)
        if b == n - 1:
            found_negative = True
        elif b != 1:
            return False

    return found_negative


def _assert_valid_group(g, q, p):
    """Validación de init compartida: p primo, q primo y |<g>| == q.

    q primo => el orden de g divide a q => el orden es 1 o q. orden == 1 sii
    g % p == 1, así que `pow(g, q, p) == 1 and g % p != 1` es exactamente |<g>| == q.
    """
    assert is_probably_prime(p)
    assert is_probably_prime(q)
    assert pow(g, q, p) == 1
    assert g % p != 1


class TraceableRingSignatureParticipant():
    def __init__(self, g: int, q: int, p: int, reduce_challenge: bool = True):
        _assert_valid_group(g, q, p)
        self.g = g
        self.q = q
        self.p = p

        # El enunciado fija str(n) y la convención de hash-al-GRUPO (% p) pero NO
        # si el challenge escalar se reduce mod q. reduce_challenge deja que la
        # referencia emita cualquiera de las dos formas (igual de válidas) de firma:
        #   True  -> c_i = hash % q       (convención propia de esta referencia)
        #   False -> c_i = hash plano     (convención común de los estudiantes)
        # Un verifier correcto de cualquiera de las dos convenciones acepta AMBAS,
        # porque el challenge solo importa módulo q (es un exponente de elementos de
        # orden q, y las implementaciones auto-consistentes lo comparan de forma consistente).
        self.reduce_challenge = reduce_challenge

        self.secret_key = random.randint(1, q - 1)
        self.public_key = pow(g, self.secret_key, p)

    def get_public_key(self):
        return self.public_key

    def _challenge(self, digest_int):
        return digest_int % self.q if self.reduce_challenge else digest_int

    def generate_traceable_ring_signature(self, public_keys, tag, message):
        q = self.q
        g = self.g
        p = self.p
        n = len(public_keys)

        T_preimage = "".join([str(y) for y in public_keys]) + tag
        T = pow(int.from_bytes(sha256(T_preimage.encode()).digest()), (p - 1) // q, p)
        assert T != 1
        assert pow(T, q, p) == 1
        f = pow(T, self.secret_key, p)

        my_r = random.randint(1, q - 1)
        my_index = public_keys.index(self.public_key)

        signatures = [0] * len(public_keys)
        challenges = [0] * len(public_keys)
        preimage = str(pow(g, my_r, p)) + message + str(pow(T, my_r, p))
        challenges[(my_index + 1) % n] = self._challenge(int.from_bytes(sha256(preimage.encode()).digest()))

        for i in range(1, n):
            index = (my_index + i) % n
            signatures[index] = random.randint(1, q - 1)
            # (q - c) % q mantiene el exponente correcto esté c reducido o no.
            exp = (q - challenges[index]) % q
            R = (pow(g, signatures[index], p) * pow(public_keys[index], exp, p)) % p
            S = (pow(T, signatures[index], p) * pow(f, exp, p)) % p
            preimage = (str(R) + message + str(S)).encode()
            challenges[(index + 1) % n] = self._challenge(int.from_bytes(sha256(preimage).digest()))

        signatures[my_index] = (my_r + challenges[my_index] * self.secret_key) % q

        return signatures, challenges[0], f


class Verifier:
    def __init__(self, g, q, p):
        _assert_valid_group(g, q, p)
        self.g = g
        self.q = q
        self.p = p
        self.seen_tag_signatures = {}  # mapea un tag al conjunto de f vistos bajo él

    def verify_signature(self, public_keys, message, tag, signature):
        signatures, c, f = signature
        q = self.q
        g = self.g
        p = self.p
        n = len(public_keys)

        T_preimage = "".join([str(y) for y in public_keys]) + tag
        T = pow(int.from_bytes(sha256(T_preimage.encode()).digest()), (p - 1) // q, p)

        # T degenerado (orden 1): ningún firmante honesto lo produce -> rechazar,
        # y no guardar ningún estado de enlazabilidad para él.
        if T == 1:
            return False, False

        current_c = c
        for i in range(1, n + 1):
            R = (pow(g, signatures[i - 1], p) * pow(public_keys[i - 1], (q - current_c), p)) % p
            S = (pow(T, signatures[i - 1], p) * pow(f, (q - current_c), p)) % p
            preimage = (str(R) + message + str(S)).encode()
            current_c = int.from_bytes(sha256(preimage).digest()) % q

        valid = (current_c % q == c % q)

        first_seen = True
        if tag in self.seen_tag_signatures:
            if f in self.seen_tag_signatures[tag]:
                first_seen = False
            self.seen_tag_signatures[tag].add(f)
        else:
            self.seen_tag_signatures[tag] = {f}

        return valid, first_seen
