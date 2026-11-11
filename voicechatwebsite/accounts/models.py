from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.conf import settings
import base64

# AES Implementation (AES-128, ECB mode)
# Complete S-box for SubBytes transformation
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

# Complete Inverse S-box for InvSubBytes transformation
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

# Round constant (Rcon) for key expansion
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

# Galois Field (GF) multiplication for MixColumns
def gf_multiply(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1B  # AES polynomial x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return p & 0xFF

# Helper functions for AES transformations
def sub_bytes(state):
    return [[SBOX[byte] for byte in row] for row in state]

def inv_sub_bytes(state):
    return [[INV_SBOX[byte] for byte in row] for row in state]

def shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]
    return state

def inv_shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][3], state[1][0], state[1][1], state[1][2]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][1], state[3][2], state[3][3], state[3][0]
    return state

def mix_columns(state):
    for i in range(4):
        s0, s1, s2, s3 = state[i]
        state[i][0] = gf_multiply(0x02, s0) ^ gf_multiply(0x03, s1) ^ s2 ^ s3
        state[i][1] = s0 ^ gf_multiply(0x02, s1) ^ gf_multiply(0x03, s2) ^ s3
        state[i][2] = s0 ^ s1 ^ gf_multiply(0x02, s2) ^ gf_multiply(0x03, s3)
        state[i][3] = gf_multiply(0x03, s0) ^ s1 ^ s2 ^ gf_multiply(0x02, s3)
    return state

def inv_mix_columns(state):
    for i in range(4):
        s0, s1, s2, s3 = state[i]
        state[i][0] = gf_multiply(0x0E, s0) ^ gf_multiply(0x0B, s1) ^ gf_multiply(0x0D, s2) ^ gf_multiply(0x09, s3)
        state[i][1] = gf_multiply(0x09, s0) ^ gf_multiply(0x0E, s1) ^ gf_multiply(0x0B, s2) ^ gf_multiply(0x0D, s3)
        state[i][2] = gf_multiply(0x0D, s0) ^ gf_multiply(0x09, s1) ^ gf_multiply(0x0E, s2) ^ gf_multiply(0x0B, s3)
        state[i][3] = gf_multiply(0x0B, s0) ^ gf_multiply(0x0D, s1) ^ gf_multiply(0x09, s2) ^ gf_multiply(0x0E, s3)
    return state

def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state

# Key expansion for AES-128 (10 rounds + initial key)
def key_expansion(key):
    key = [byte for byte in key]
    round_keys = []
    for i in range(4):
        round_keys.append(key[i*4:(i+1)*4])

    for i in range(4, 44):
        temp = round_keys[i-1][:]
        if i % 4 == 0:
            # Rotate word
            temp = temp[1:] + temp[:1]
            # Sub word
            temp = [SBOX[byte] for byte in temp]
            # XOR with Rcon
            temp[0] ^= RCON[i//4 - 1]
        round_keys.append([])
        for j in range(4):
            round_keys[i].append(round_keys[i-4][j] ^ temp[j])

    return [[round_keys[i*4+j] for j in range(4)] for i in range(11)]

# AES class for encryption and decryption
class AES:
    def __init__(self, key):
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes long for AES-128")
        self.round_keys = key_expansion(key)

    def encrypt_block(self, block):
        # Convert block to 4x4 state matrix
        state = [[block[i*4+j] for j in range(4)] for i in range(4)]

        # Initial round
        state = add_round_key(state, self.round_keys[0])

        # 9 main rounds
        for round in range(1, 10):
            state = sub_bytes(state)
            state = shift_rows(state)
            state = mix_columns(state)
            state = add_round_key(state, self.round_keys[round])

        # Final round (no MixColumns)
        state = sub_bytes(state)
        state = shift_rows(state)
        state = add_round_key(state, self.round_keys[10])

        # Convert state back to 16-byte block
        return bytes([state[i][j] for i in range(4) for j in range(4)])

    def decrypt_block(self, block):
        print(f"Decrypting block: {block.hex()}")
        # Convert block to 4x4 state matrix
        state = [[block[i*4+j] for j in range(4)] for i in range(4)]
        print(f"Initial state: {state}")

        # Initial round (inverse)
        state = add_round_key(state, self.round_keys[10])
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)

        # 9 main rounds (inverse)
        for round in range(9, 0, -1):
            state = add_round_key(state, self.round_keys[round])
            state = inv_mix_columns(state)
            state = inv_shift_rows(state)
            state = inv_sub_bytes(state)

        # Final round (inverse)
        state = add_round_key(state, self.round_keys[0])

        # Convert state back to 16-byte block
        result = bytes([state[i][j] for i in range(4) for j in range(4)])
        print(f"Decrypted block: {result.hex()}")
        return result

def pad(data):
    length = 16 - (len(data) % 16)
    return data + (chr(length) * length).encode()

def unpad(data):
    return data[:-data[-1]]

# CustomUser model with manual AES encryption/decryption
class CustomUserManager(BaseUserManager):
    def create_user(self, username, first_name, last_name, unique_11_digit_number, cnic, password=None, **extra_fields):
        if not username:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(username)
        user = self.model(
            username=email,
            first_name=first_name,
            last_name=last_name,
            unique_11_digit_number=unique_11_digit_number,
            cnic=cnic,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        user.encrypt_first_name()
        user.encrypt_last_name()
        user.encrypt_cnic()
        user.encrypt_unique_11_digit_number()
        return user

    def create_superuser(self, username, first_name, last_name, unique_11_digit_number, cnic, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(username, first_name, last_name, unique_11_digit_number, cnic, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=255, unique=True)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    unique_11_digit_number = models.CharField(max_length=255, unique=True)
    cnic = models.CharField(max_length=255)
    date_joined = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'unique_11_digit_number', 'cnic']

    def __str__(self):
        return self.username

    def encrypt_first_name(self):
        key = settings.AES_KEY.encode('utf-8')
        print(f"Encrypting first_name - AES Key: {settings.AES_KEY}")
        aes = AES(key)
        padded_first_name = pad(self.first_name.encode('utf-8'))
        print(f"Padded first_name: {padded_first_name.hex()}")
        encrypted_first_name = b""
        for i in range(0, len(padded_first_name), 16):
            block = padded_first_name[i:i+16]
            encrypted_first_name += aes.encrypt_block(block)
        self.first_name = base64.b64encode(encrypted_first_name).decode('utf-8')
        print(f"Encrypted first_name: {self.first_name}")
        self.save()

    def decrypt_first_name(self):
        key = settings.AES_KEY.encode('utf-8')
        print(f"Decrypting first_name - AES Key: {settings.AES_KEY}")
        aes = AES(key)
        encrypted_first_name = base64.b64decode(self.first_name.encode('utf-8'))
        print(f"Encrypted first_name (raw): {encrypted_first_name.hex()}")
        decrypted_first_name = b""
        for i in range(0, len(encrypted_first_name), 16):
            block = encrypted_first_name[i:i+16]
            decrypted_first_name += aes.decrypt_block(block)
        decrypted_first_name = unpad(decrypted_first_name)
        result = decrypted_first_name.decode('utf-8')
        print(f"Decrypted first_name: {result}")
        return result

    def encrypt_last_name(self):
        key = settings.AES_KEY.encode('utf-8')
        print(f"Encrypting last_name - AES Key: {settings.AES_KEY}")
        aes = AES(key)
        padded_last_name = pad(self.last_name.encode('utf-8'))
        print(f"Padded last_name: {padded_last_name.hex()}")
        encrypted_last_name = b""
        for i in range(0, len(padded_last_name), 16):
            block = padded_last_name[i:i+16]
            encrypted_last_name += aes.encrypt_block(block)
        self.last_name = base64.b64encode(encrypted_last_name).decode('utf-8')
        print(f"Encrypted last_name: {self.last_name}")
        self.save()

    def decrypt_last_name(self):
        key = settings.AES_KEY.encode('utf-8')
        print(f"Decrypting last_name - AES Key: {settings.AES_KEY}")
        aes = AES(key)
        encrypted_last_name = base64.b64decode(self.last_name.encode('utf-8'))
        print(f"Encrypted last_name (raw): {encrypted_last_name.hex()}")
        decrypted_last_name = b""
        for i in range(0, len(encrypted_last_name), 16):
            block = encrypted_last_name[i:i+16]
            decrypted_last_name += aes.decrypt_block(block)
        decrypted_last_name = unpad(decrypted_last_name)
        result = decrypted_last_name.decode('utf-8')
        print(f"Decrypted last_name: {result}")
        return result

    def encrypt_unique_11_digit_number(self):
        key = settings.AES_KEY.encode('utf-8')
        print(f"Encrypting unique_11_digit_number - AES Key: {settings.AES_KEY}")
        aes = AES(key)
        padded_unique_11_digit_number = pad(self.unique_11_digit_number.encode('utf-8'))
        print(f"Padded unique_11_digit_number: {padded_unique_11_digit_number.hex()}")
        encrypted_unique_11_digit_number = b""
        for i in range(0, len(padded_unique_11_digit_number), 16):
            block = padded_unique_11_digit_number[i:i+16]
            encrypted_unique_11_digit_number += aes.encrypt_block(block)
        self.unique_11_digit_number = base64.b64encode(encrypted_unique_11_digit_number).decode('utf-8')
        print(f"Encrypted unique_11_digit_number: {self.unique_11_digit_number}")
        self.save()

    def decrypt_unique_11_digit_number(self):
        key = settings.AES_KEY.encode('utf-8')
        print(f"Decrypting unique_11_digit_number - AES Key: {settings.AES_KEY}")
        aes = AES(key)
        encrypted_unique_11_digit_number = base64.b64decode(self.unique_11_digit_number.encode('utf-8'))
        print(f"Encrypted unique_11_digit_number (raw): {encrypted_unique_11_digit_number.hex()}")
        decrypted_unique_11_digit_number = b""
        for i in range(0, len(encrypted_unique_11_digit_number), 16):
            block = encrypted_unique_11_digit_number[i:i+16]
            decrypted_unique_11_digit_number += aes.decrypt_block(block)
        decrypted_unique_11_digit_number = unpad(decrypted_unique_11_digit_number)
        result = decrypted_unique_11_digit_number.decode('utf-8')
        print(f"Decrypted unique_11_digit_number: {result}")
        return result

    def encrypt_cnic(self):
        key = settings.AES_KEY.encode('utf-8')
        print(f"Encrypting cnic - Raw CNIC: {self.cnic}, AES Key: {settings.AES_KEY}")
        aes = AES(key)
        padded_cnic = pad(self.cnic.encode('utf-8'))
        print(f"Padded cnic: {padded_cnic.hex()}")
        encrypted_cnic = b""
        for i in range(0, len(padded_cnic), 16):
            block = padded_cnic[i:i+16]
            encrypted_cnic += aes.encrypt_block(block)
        self.cnic = base64.b64encode(encrypted_cnic).decode('utf-8')
        print(f"Encrypted cnic: {self.cnic}")
        self.save()

    def decrypt_cnic(self):
        key = settings.AES_KEY.encode('utf-8')
        print(f"Decrypting cnic - Encrypted CNIC: {self.cnic}, AES Key: {settings.AES_KEY}")
        aes = AES(key)
        encrypted_cnic = base64.b64decode(self.cnic.encode('utf-8'))
        print(f"Encrypted cnic (raw): {encrypted_cnic.hex()}")
        decrypted_cnic = b""
        for i in range(0, len(encrypted_cnic), 16):
            block = encrypted_cnic[i:i+16]
            decrypted_cnic += aes.decrypt_block(block)
        decrypted_cnic = unpad(decrypted_cnic)
        result = decrypted_cnic.decode('utf-8')
        print(f"Decrypted cnic: {result}")
        return result

class OTP(models.Model):
    email = models.CharField(max_length=255)
    otp = models.CharField(max_length=6)
    action = models.CharField(max_length=10)  # 'signup' or 'login'
    created_at = models.DateTimeField(auto_now_add=True)
    attempts = models.IntegerField(default=0)
    is_verified = models.BooleanField(default=False)

    def is_expired(self):
        expiration_time = self.created_at + timezone.timedelta(minutes=5)
        return timezone.now() > expiration_time

    def can_attempt(self):
        return self.attempts < 3

class UserKey(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    public_key_e = models.TextField()  # RSA public exponent 'e'
    public_key_n = models.TextField()  # RSA modulus 'n'
    private_key_d = models.TextField()  # RSA private exponent 'd'
    private_key_n = models.TextField()  # RSA modulus 'n' (same as public_key_n)
    created_at = models.DateTimeField(auto_now_add=True)