import os
import base64  # 添加缺失的导入
from dotenv import load_dotenv


class Config:
    def __init__(self, env='test'):
        load_dotenv()
        self.base_url = os.getenv("BASE_URL", "https://api.fine-system.com")
        self.app_id = os.getenv("FINE_APP_ID")
        self.app_secret = os.getenv("FINE_APP_SECRET")

        # 使用导入的base64模块
        aes_key_str = os.getenv("AES_KEY", "")
        self.aes_key = base64.b64decode(aes_key_str) if aes_key_str else b""

        aes_iv_str = os.getenv("AES_IV", "")
        self.aes_iv = base64.b64decode(aes_iv_str) if aes_iv_str else b""

    @property
    def public_key_path(self):
        return os.path.join("config/security", "public_key.pem")