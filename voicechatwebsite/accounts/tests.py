def sub_bytes(state):
    return [sbox_lookup(byte) for byte in state]

def shift_rows(state):
    return [
        state[0], state[5], state[10], state[15],
        state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7],
        state[12], state[1], state[6], state[11]
    ]

def mix_columns(state):
    # Placeholder (implement Galois field multiplication for production)
    return state

def add_round_key(state, key):
    return [state[i] ^ key[i] for i in range(16)]

def aes_encrypt(plaintext, key):
    if len(plaintext) != 16 or len(key) != 16:
        raise ValueError("Plaintext and key must be 16 bytes")
    state = list(plaintext)
    state = add_round_key(state, key)
    for _ in range(9):  # 10 rounds for AES-128
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, key)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, key)
    return bytes(state)

def aes_decrypt(ciphertext, key):
    # Placeholder (implement inverse SubBytes, ShiftRows, etc. for production)
    return ciphertext  # Simplified for demo

# Manual RSA implementation (educational, not secure)
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_prime(min_value, max_value):
    prime = random.randint(min_value, max_value)
    while not is_prime(prime):
        prime = random.randint(min_value, max_value)
    return prime

def mod_inverse(e, phi):
    for d in range(3, phi):
        if (d * e) % phi == 1:
            return d
    raise ValueError("mod_inverse does not exist")

def generate_keypair():
    p = generate_prime(100, 1000)
    q = generate_prime(100, 1000)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Common public exponent
    d = mod_inverse(e, phi)
    return (e, n), (d, n)  # (public_key, private_key)
