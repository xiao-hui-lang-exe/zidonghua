import os
import base64
from dotenv import load_dotenv
from cryptography.exceptions import InvalidKey  # 新增导入


class Config:
    def __init__(self, env='test'):
        # 加载对应环境的.env文件
        env_file = f".env.{env}"
        if os.path.exists(env_file):
            load_dotenv(env_file)
        else:
            load_dotenv()  # 加载默认的.env文件

        self.base_url = os.getenv("BASE_URL", "https://api.fine-system.com")
        self.app_id = os.getenv("FINE_APP_ID")
        self.app_secret = os.getenv("FINE_APP_SECRET")

        # 处理AES密钥和IV
        aes_key_str = os.getenv("AES_KEY", "")
        self.aes_key = base64.b64decode(aes_key_str) if aes_key_str else b""

        aes_iv_str = os.getenv("AES_IV", "")
        self.aes_iv = base64.b64decode(aes_iv_str) if aes_iv_str else b""

        # 新增：验证AES密钥长度
        if self.aes_key and len(self.aes_key) not in [16, 24, 32]:
            raise InvalidKey(f"无效的AES密钥长度: {len(self.aes_key)}字节。必须是16, 24或32字节")

        self.timeout = int(os.getenv("TIMEOUT", "10"))
        self.enable_ssl_verify = os.getenv("ENABLE_SSL_VERIFY", "true").lower() == "true"

    @property
    def public_key_path(self):
        return os.path.join("config", "security", "public_key.pem")

    @property
    def private_key_path(self):
        return os.path.join("config", "security", "private_key.pem")