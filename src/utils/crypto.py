from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
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
    def generate_signature(app_id: str, secret: str, timestamp: str) -> str:
        signer = hmac.HMAC(secret.encode(), hashes.SHA256())
        signer.update(f"{app_id}{timestamp}".encode())
        return base64.b64encode(signer.finalize()).decode()