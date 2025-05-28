from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import constant_time
import base64

class CryptoHandler:
    @staticmethod
    def aes_encrypt(data: str, key: bytes, iv: bytes) -> str:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padded_data = data + (16 - len(data) % 16) * chr(16 - len(data) % 16)
        ct = encryptor.update(padded_data.encode()) + encryptor.finalize()
        return base64.b64encode(ct).decode()

    @staticmethod
    def secure_compare(a: str, b: str) -> bool:
      return constant_time.bytes_eq(a.encode(), b.encode())