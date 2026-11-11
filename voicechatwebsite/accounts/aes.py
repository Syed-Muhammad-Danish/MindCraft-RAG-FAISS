# Manual AES implementation in ECB mode

# S-box and inverse S-box for SubBytes step
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# Round constants for key expansion
RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
]

# MixColumns transformation matrix
MIX_COLUMNS_MATRIX = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02]
]

INV_MIX_COLUMNS_MATRIX = [
    [0x0e, 0x0b, 0x0d, 0x09],
    [0x09, 0x0e, 0x0b, 0x0d],
    [0x0d, 0x09, 0x0e, 0x0b],
    [0x0b, 0x0d, 0x09, 0x0e]
]

def gf_multiply(a, b):
    """Multiply two numbers in GF(2^8) using the irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        high_bit_set = a & 0x80
        a <<= 1
        if high_bit_set:
            a ^= 0x11b
        a &= 0xff
        b >>= 1
    return p

# PKCS7 padding functions
def pad(data, block_size):
    """Apply PKCS7 padding to the data."""
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def unpad(data, block_size):
    """Remove PKCS7 padding from the data."""
    if len(data) % block_size != 0:
        raise ValueError("Data length must be a multiple of block size")
    padding_len = data[-1]
    if padding_len > block_size or padding_len == 0:
        raise ValueError("Invalid padding")
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding")
    return data[:-padding_len]

class AES:
    def __init__(self, key):
        self.block_size = 16  # AES block size is 16 bytes
        self.rounds = 10  # AES-128 has 10 rounds
        self.key = key[:16]  # Ensure key is 16 bytes for AES-128
        self.round_keys = self._expand_key()

    def _expand_key(self):
        """Expand the 128-bit key into 11 round keys (4x4 matrices)."""
        key_bytes = list(self.key)
        # Initial round key (first 16 bytes as a 4x4 matrix)
        round_keys = []
        temp_key = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                temp_key[j][i] = key_bytes[i * 4 + j]
        round_keys.append(temp_key)

        # Expand into 11 round keys (176 bytes total)
        words = [key_bytes[i:i+4] for i in range(0, 16, 4)]
        for i in range(4, 4 * (self.rounds + 1)):
            temp = words[i-1][:]
            if i % 4 == 0:
                # Rotate word
                temp = temp[1:] + temp[:1]
                # SubBytes
                temp = [SBOX[b] for b in temp]
                # XOR with Rcon
                temp[0] ^= RCON[i//4 - 1]
            prev_word = words[i-4]
            words.append([temp[j] ^ prev_word[j] for j in range(4)])

            # Convert every 4 words into a 4x4 matrix
            if i % 4 == 3:
                round_key = [[0 for _ in range(4)] for _ in range(4)]
                for col in range(4):
                    word = words[i - 3 + col]
                    for row in range(4):
                        round_key[row][col] = word[row]
                round_keys.append(round_key)

        return round_keys

    def _sub_bytes(self, state):
        """Apply the SubBytes transformation using the S-box."""
        return [[SBOX[state[i][j]] for j in range(4)] for i in range(4)]

    def _inv_sub_bytes(self, state):
        """Apply the inverse SubBytes transformation using the inverse S-box."""
        return [[INV_SBOX[state[i][j]] for j in range(4)] for i in range(4)]

    def _shift_rows(self, state):
        """Apply the ShiftRows transformation."""
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]
        return state

    def _inv_shift_rows(self, state):
        """Apply the inverse ShiftRows transformation."""
        state[1] = state[1][-1:] + state[1][:-1]
        state[2] = state[2][-2:] + state[2][:-2]
        state[3] = state[3][-3:] + state[3][:-3]
        return state

    def _mix_columns(self, state):
        """Apply the MixColumns transformation."""
        new_state = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                for k in range(4):
                    new_state[i][j] ^= gf_multiply(MIX_COLUMNS_MATRIX[i][k], state[k][j])
        return new_state

    def _inv_mix_columns(self, state):
        """Apply the inverse MixColumns transformation."""
        new_state = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                for k in range(4):
                    new_state[i][j] ^= gf_multiply(INV_MIX_COLUMNS_MATRIX[i][k], state[k][j])
        return new_state

    def _add_round_key(self, state, round_key):
        """XOR the state with the round key."""
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i][j]
        return state

    def _bytes_to_state(self, block):
        """Convert a 16-byte block to a 4x4 state matrix."""
        state = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                state[j][i] = block[i * 4 + j]
        return state

    def _state_to_bytes(self, state):
        """Convert a 4x4 state matrix to a 16-byte block."""
        block = [0] * 16
        for i in range(4):
            for j in range(4):
                block[i * 4 + j] = state[j][i]
        return bytes(block)

    def _encrypt_block(self, block):
        """Encrypt a single 16-byte block."""
        state = self._bytes_to_state(block)
        round_keys = self.round_keys

        # Initial round
        state = self._add_round_key(state, round_keys[0])

        # Main rounds
        for round in range(1, self.rounds):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, round_keys[round])

        # Final round
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, round_keys[self.rounds])

        return self._state_to_bytes(state)

    def _decrypt_block(self, block):
        """Decrypt a single 16-byte block."""
        state = self._bytes_to_state(block)
        round_keys = self.round_keys

        # Initial round (undo final round)
        state = self._add_round_key(state, round_keys[self.rounds])
        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)

        # Main rounds
        for round in range(self.rounds - 1, 0, -1):
            state = self._add_round_key(state, round_keys[round])
            state = self._inv_mix_columns(state)
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)

        # Final round
        state = self._add_round_key(state, round_keys[0])

        return self._state_to_bytes(state)

    def encrypt(self, data):
        """Encrypt data with automatic padding."""
        # Apply PKCS7 padding
        padded_data = pad(data, self.block_size)

        encrypted = bytearray()
        for i in range(0, len(padded_data), self.block_size):
            block = padded_data[i:i + self.block_size]
            encrypted_block = self._encrypt_block(block)
            encrypted.extend(encrypted_block)
        return bytes(encrypted)

    def decrypt(self, encrypted_data):
        """Decrypt data and remove padding."""
        if len(encrypted_data) % self.block_size != 0:
            raise ValueError("Encrypted data length must be a multiple of block size (16 bytes)")

        decrypted = bytearray()
        for i in range(0, len(encrypted_data), self.block_size):
            block = encrypted_data[i:i + self.block_size]
            decrypted_block = self._decrypt_block(block)
            decrypted.extend(decrypted_block)

        # Remove PKCS7 padding
        return unpad(decrypted, self.block_size)