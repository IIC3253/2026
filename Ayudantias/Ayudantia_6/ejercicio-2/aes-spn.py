#!/usr/bin/env python3
import numpy as np
from PIL import Image
import matplotlib.pyplot as plt

AES_SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

def bytes2matrix(text):
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    return b"".join([b"".join([chr(i).encode() for i in x]) for x  in matrix])

# Fuente: https://cryptohack.org/courses/symmetric/aes6/
def expand_key(master_key, n_rounds=10):
    # Round constants https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
    r_con = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
        0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    )

    # Initialize round keys with raw key material.
    key_columns = bytes2matrix(master_key)
    iteration_size = len(master_key) // 4

    # Each iteration has exactly as many columns as the key material.
    i = 1
    while len(key_columns) < (n_rounds + 1) * 4:
        # Copy previous word.
        word = list(key_columns[-1])

        # Perform schedule_core once every "row".
        if len(key_columns) % iteration_size == 0:
            # Circular shift.
            word.append(word.pop(0))
            # Map to S-BOX.
            word = [AES_SBOX[b] for b in word]
            # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
            word[0] ^= r_con[i]
            i += 1
        elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
            # Run word through S-box in the fourth iteration when using a
            # 256-bit key.
            word = [AES_SBOX[b] for b in word]

        # XOR with equivalent word from previous iteration.
        word = bytes(i^j for i, j in zip(word, key_columns[-iteration_size]))
        key_columns.append(word)

    # Group key words in 4x4 byte matrices.
    key_matrices = [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]
    return [b"".join(matrix) for matrix in key_matrices[1:]]

def add_round_key(data, round_key):
    flat_data = data.flatten()

    result = []

    key = np.frombuffer(round_key, dtype=np.uint8)
    key_state = key.reshape(4, 4, order="F")

    for i in range(0, len(flat_data), 16):
        block = flat_data[i:i+16]

        if len(block) < 16:
            # pad last block (same style as permutation layer)
            padding = 16 - len(block)
            block = np.concatenate([block, np.zeros(padding, dtype=np.uint8)])

        state = block.reshape(4, 4, order="F")

        state = np.bitwise_xor(state, key_state)

        result.extend(state.flatten(order="F"))

    result = np.array(result, dtype=np.uint8)
    return result[:data.size].reshape(data.shape)

def substitute_bytes(data):
    return np.array([AES_SBOX[byte] for byte in data.flatten()], dtype=np.uint8).reshape(data.shape)

def shift_rows_on_state(state):
    result = state.copy()
    result[1] = np.roll(state[1], -1)
    result[2] = np.roll(state[2], -2)
    result[3] = np.roll(state[3], -3)
    return result

# Fuente: http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
def mix_columns_on_state(state):
    def gmul(a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p & 0xFF
    
    result = np.zeros_like(state)
    for c in range(4):
        s0, s1, s2, s3 = state[:, c]
        result[0, c] = gmul(2, s0) ^ gmul(3, s1) ^ s2 ^ s3
        result[1, c] = s0 ^ gmul(2, s1) ^ gmul(3, s2) ^ s3
        result[2, c] = s0 ^ s1 ^ gmul(2, s2) ^ gmul(3, s3)
        result[3, c] = gmul(3, s0) ^ s1 ^ s2 ^ gmul(2, s3)
    return result

def apply_permutation_layer(data):
    flat_data = data.flatten()
    
    remainder = len(flat_data) % 16
    if remainder != 0:
        padding = 16 - remainder
        flat_data = np.concatenate([flat_data, np.zeros(padding, dtype=np.uint8)])
    
    result = []
    
    for i in range(0, len(flat_data), 16):
        block = flat_data[i:i+16]
        state = block.reshape(4, 4, order="F")
        
        state = shift_rows_on_state(state)
        state = mix_columns_on_state(state)
        
        result.extend(state.flatten(order="F"))
    
    result = np.array(result, dtype=np.uint8)
    return result[:data.size].reshape(data.shape)

def create_test_image(size=256):
    img = np.zeros((size, size), dtype=np.uint8)
    
    for i in range(size):
        img[i, :] = i
    
    img[50:100, 50:100] = 255
    
    center = (size // 2, size // 2)
    y, x = np.ogrid[:size, :size]
    mask = (x - center[0])**2 + (y - center[1])**2 <= 40**2
    img[mask] = 128
    
    for i in range(size):
        if i < size:
            img[i, i] = 200
            if size - i - 1 >= 0:
                img[i, size - i - 1] = 200
    
    return img

def demonstrate_spn_layers(image_path=None, n_layers=1, master_key=None):
    if master_key:
        if len(master_key) != 16 or type(master_key) != bytes:
            print("Master key must be 16 bytes")
            return
    
        round_keys = expand_key(master_key, n_layers)

    if image_path:
        img = Image.open(image_path).convert("L")
        img_array = np.array(img)
    else:
        img_array = create_test_image()

    if master_key:
        base = add_round_key(img_array, master_key)
    else:
        base = img_array

    substituted = substitute_bytes(base)
    permuted = apply_permutation_layer(base)
    both = apply_permutation_layer(substituted)
    for i in range(n_layers - 1):
        if master_key:
            substituted = add_round_key(substituted, round_keys[i])
            permuted = add_round_key(permuted, round_keys[i])
            both = add_round_key(both, round_keys[i])

        substituted = substitute_bytes(substituted)
        permuted = apply_permutation_layer(permuted)

        both = substitute_bytes(both)
        both = apply_permutation_layer(both)
    
    fig, axes = plt.subplots(1, 4, figsize=(15, 5))
    
    axes[0].imshow(img_array, cmap="gray", vmin=0, vmax=255)
    axes[0].set_title("Original", fontsize=14, fontweight="bold")
    axes[0].axis("off")
    
    axes[1].imshow(substituted, cmap="gray", vmin=0, vmax=255)
    axes[1].set_title("Only Substitution (S-box)\nConfusion without Diffusion", fontsize=14, fontweight="bold")
    axes[1].axis("off")
    
    axes[2].imshow(permuted, cmap="gray", vmin=0, vmax=255)
    axes[2].set_title("Only Permutation (ShiftRows + MixColumns)\nDiffusion without Confusion", fontsize=14, fontweight="bold")
    axes[2].axis("off")

    axes[3].imshow(both, cmap="gray", vmin=0, vmax=255)
    axes[3].set_title("Both", fontsize=14, fontweight="bold")
    axes[3].axis("off")
    
    plt.tight_layout()
    plt.savefig(f"aes_spn_comparison-{n_layers}-layers.png", dpi=150, bbox_inches="tight")
    
    # Save individual images for closer inspection
    Image.fromarray(img_array).save("original.png")
    Image.fromarray(substituted).save(f"substitution-{n_layers}-layers.png")
    Image.fromarray(permuted).save(f"permutation-{n_layers}-layers.png")
    Image.fromarray(both).save(f"both-{n_layers}-layers.png")

if __name__ == "__main__":
    demonstrate_spn_layers()
