import base64
import hashlib
import os


class FileEncryption:
    def __init__(self, password):
        self.key = hashlib.sha256(password.encode()).digest()[:16]  # 128-bit key
        self.block_size = 16

    def pad(self, data):
        padding_length = self.block_size - (len(data) % self.block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def unpad(self, data):
        if not data:
            raise ValueError("Cannot unpad empty data")
        padding_length = data[-1]
        if padding_length > len(data) or padding_length == 0:
            raise ValueError("Invalid padding length")
        return data[:-padding_length]

    def xor_encrypt_block(self, block, key):
        return bytes(a ^ b for a, b in zip(block, key * (len(block) // 16 + 1)))

    def encrypt(self, input_file, output_file, allowed_user_id=None):
        with open(input_file, 'rb') as f:
            plaintext = f.read()

        # Add metadata: allowed user ID (or None for only the encrypting user)
        metadata = str(allowed_user_id).encode() if allowed_user_id else b"0"
        padded_metadata = self.pad(metadata)
        padded_plaintext = self.pad(plaintext)

        # Encrypt metadata and plaintext separately
        encrypted_metadata = self.xor_encrypt_block(padded_metadata, self.key)
        ciphertext = b""
        for i in range(0, len(padded_plaintext), self.block_size):
            block = padded_plaintext[i:i + self.block_size]
            encrypted_block = self.xor_encrypt_block(block, self.key)
            ciphertext += encrypted_block

        # Combine metadata and ciphertext
        encrypted_data = encrypted_metadata + ciphertext

        with open(output_file, 'wb') as f:
            f.write(base64.b64encode(encrypted_data))

    def decrypt(self, input_file, output_file, user_id):
        with open(input_file, 'rb') as f:
            encrypted_data = base64.b64decode(f.read())

        if len(encrypted_data) < self.block_size:
            raise ValueError("Encrypted data is too short to contain metadata")

        # Extract metadata (first block, fixed size)
        encrypted_metadata = encrypted_data[:self.block_size]
        ciphertext = encrypted_data[self.block_size:]

        # Decrypt metadata
        decrypted_metadata = self.xor_encrypt_block(encrypted_metadata, self.key)
        try:
            allowed_user_id = int(self.unpad(decrypted_metadata).decode()) if decrypted_metadata != b"0" else None
        except (ValueError, UnicodeDecodeError) as e:
            raise ValueError("Decryption failed: Incorrect password or corrupted data")

        # Check user permission
        if allowed_user_id and str(user_id) != str(allowed_user_id):
            raise ValueError("You are not authorized to decrypt this file.")

        # Decrypt the file content
        plaintext = b""
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]
            decrypted_block = self.xor_encrypt_block(block, self.key)
            plaintext += decrypted_block

        try:
            plaintext = self.unpad(plaintext)
        except ValueError as e:
            raise ValueError("Decryption failed: Incorrect password or corrupted data")

        with open(output_file, 'wb') as f:
            f.write(plaintext)


if __name__ == "__main__":
    # Example encryption
    enc = FileEncryption("mypassword")
    enc.encrypt("sample.pdf", "sample_encrypted.pdf", allowed_user_id="2")

    # Example decryption
    dec = FileEncryption("mypassword")
    dec.decrypt("sample_encrypted.pdf", "sample_decrypted.pdf", user_id="2")