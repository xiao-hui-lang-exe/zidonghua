import time  # 添加缺失的导入
import requests
from src.utils.crypto import CryptoHandler
from config.settings import Config
from src.core.exceptions import SignatureVerificationError  # 确保导入异常类

class FineAPIClient:
    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update(self._build_headers())

    def _build_headers(self) -> dict:
        timestamp = str(int(time.time()))  # 使用导入的time模块
        return {
            "App-Id": self.config.app_id,
            "Timestamp": timestamp,
            "Signature": CryptoHandler.generate_signature(  # 确保正确引用
                self.config.app_id,
                self.config.app_secret,
                timestamp
            )
        }

    def post_encrypted(self, endpoint: str, payload: dict) -> dict:
        encrypted_data = {
            k: CryptoHandler.aes_encrypt(v, self.config.aes_key, self.config.aes_iv)
            if k in ["password", "token"] else v
            for k, v in payload.items()
        }
        response = self.session.post(
            f"{self.config.base_url}/{endpoint}",
            json=encrypted_data
        )
        response.raise_for_status()
        return response.json()