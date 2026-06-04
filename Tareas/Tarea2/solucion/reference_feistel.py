from __future__ import annotations
from typing import Callable, Optional, Tuple
from random import randint


class Feistel:
    def __init__(
        self,
        block_length: int,
        number_rounds: int,
        hash_function: Callable[[bytes], bytes],
        secret_key: bytes,
    ) -> None:
        if block_length % 2 != 0:
            raise ValueError("even")
        if number_rounds <= 0:
            raise ValueError("gr 0")
        self.block_length = block_length
        self.number_rounds = number_rounds
        self.hash_function = hash_function
        self.secret_key = secret_key

    @staticmethod
    def _xor(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    def _random_iv(self) -> bytes:
        iv = b""
        for i in range(self.block_length):
            iv += randint(0, 255).to_bytes(1, byteorder="big")
        return iv

    def key_schedule(self, i: int) -> bytes:
        return self.hash_function(self.secret_key + str(i).encode())

    def enc_block(self, m: bytes) -> bytes:
        if len(m) != self.block_length:
            raise ValueError("bad block")
        half = self.block_length // 2
        L, R = m[:half], m[half:]
        for i in range(1, self.number_rounds + 1):
            K_i = self.key_schedule(i)
            L, R = R, self._xor(L, self.hash_function(K_i + R))
        return L + R

    def dec_block(self, c: bytes) -> bytes:
        if len(c) != self.block_length:
            raise ValueError("bad block")
        half = self.block_length // 2
        L, R = c[:half], c[half:]
        for i in range(self.number_rounds, 0, -1):
            K_i = self.key_schedule(i)
            L, R = self._xor(R, self.hash_function(K_i + L)), L
        return L + R

    def pad(self, m: bytes) -> bytes:
        padded = m + b"1"
        remainder = len(padded) % self.block_length
        if remainder != 0:
            padded += b"0" * (self.block_length - remainder)
        return padded

    def unpad(self, m: bytes) -> bytes:
        if len(m) % self.block_length != 0:
            raise ValueError("padding not multiple")
        idx = m.rfind(b"1")
        if idx == -1:
            raise ValueError("Invalid")
        if any(b != 48 for b in m[idx + 1 :]):
            raise ValueError("Invalid")
        return m[:idx]

    def enc(
        self, m: bytes, mode: str, IV: Optional[bytes] = None
    ) -> bytes | Tuple[bytes, bytes]:
        padded = self.pad(m)
        blocks = [
            padded[i : i + self.block_length]
            for i in range(0, len(padded), self.block_length)
        ]
        if mode == "ECB":
            return b"".join(self.enc_block(block) for block in blocks)
        if mode == "CBC":
            actual_iv = IV if IV is not None else self._random_iv()
            result = []
            prev = actual_iv
            for block in blocks:
                encrypted = self.enc_block(self._xor(block, prev))
                result.append(encrypted)
                prev = encrypted
            return (b"".join(result), actual_iv)
        raise ValueError("mode")

    def dec(self, c: bytes, mode: str, IV: Optional[bytes] = None) -> bytes:
        if len(c) % self.block_length != 0:
            raise ValueError("len")
        blocks = [
            c[i : i + self.block_length] for i in range(0, len(c), self.block_length)
        ]
        if mode == "ECB":
            plaintext = b"".join(self.dec_block(block) for block in blocks)
            return self.unpad(plaintext)
        if mode == "CBC":
            if IV is None:
                raise ValueError("iv req")
            result = []
            prev = IV
            for block in blocks:
                decrypted = self._xor(self.dec_block(block), prev)
                result.append(decrypted)
                prev = block
            return self.unpad(b"".join(result))
        raise ValueError("mode")
