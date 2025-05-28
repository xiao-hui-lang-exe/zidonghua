import os
from dotenv import load_dotenv

class Config:
    def __init__(self, env='test'):
        self.env = env
        load_dotenv()  # 从.env加载敏感信息
        self.base_url = os.getenv("BASE_URL", "https://api.fine-system.com")
        self.app_id = os.getenv("FINE_APP_ID")
        self.app_secret = os.getenv("FINE_APP_SECRET")
        self.aes_key = base64.b64decode(os.getenv("AES_KEY"))
        self.aes_iv = base64.b64decode(os.getenv("AES_IV"))

    @property
    def public_key_path(self):
        return os.path.join("config/security", "public_key.pem")
