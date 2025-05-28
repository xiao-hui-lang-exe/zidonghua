import base64
import hmac
import hashlib
import os
import time
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time

class CryptoUtils:
    @staticmethod
    def aes_encrypt(data: str, key: bytes, iv: bytes) -> str:
        """AES-CBC加密（返回Base64字符串）"""
        # 创建PKCS7填充器（padder - 正确拼写）
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        # 填充数据
        padded_data = padder.update(data.encode('utf-8')) + padder.finalize()

        # 创建加密器
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        # 加密并返回Base64编码
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(encrypted).decode('utf-8')

    @staticmethod
    def generate_signature(app_id: str, secret: str, timestamp: str, nonce: str) -> str:
        """生成请求签名 (HMAC-SHA256)"""
        message = f"{app_id}{timestamp}{nonce}".encode('utf-8')
        signature = hmac.new(
            secret.encode('utf-8'),
            message,
            digestmod=hashlib.sha256
        ).digest()
        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def secure_compare(a: str, b: str) -> bool:
        """安全比较字符串，防止时序攻击"""
        try:
            return constant_time.bytes_eq(a.encode('utf-8'), b.encode('utf-8'))
        except (TypeError, ValueError):
            return False

    @staticmethod
    def generate_nonce(length: int = 16) -> str:
        """生成随机nonce值"""
        return os.urandom(length).hex()

    @staticmethod
    def get_current_timestamp() -> str:
        """获取当前时间戳"""
        return str(int(time.time()))
