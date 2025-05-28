import requests
import logging
import json
from typing import Dict, Optional, Any
from src.core.crypto_utils import CryptoUtils
# 移除未使用的 import: from src.core.exceptions import SignatureVerificationError
from src.core.exceptions import APIRequestError, EncryptionError  # 只导入需要的异常
from config.settings import Config


# 配置日志
logger = logging.getLogger('api_client')
logger.setLevel(logging.INFO)


class FineAPIClient:
    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()
        self.token: Optional[str] = None
        self.logger = logger

        # 配置SSL验证
        self.session.verify = config.enable_ssl_verify

        # 设置默认超时
        self.timeout = config.timeout

    def _build_headers(self) -> Dict[str, str]:
        """构建包含签名信息的请求头"""
        timestamp = CryptoUtils.get_current_timestamp()
        nonce = CryptoUtils.generate_nonce()

        return {
            "App-Id": self.config.app_id,
            "Timestamp": timestamp,
            "Nonce": nonce,
            "Signature": CryptoUtils.generate_signature(
                self.config.app_id,
                self.config.app_secret,
                timestamp,
                nonce
            ),
            "Content-Type": "application/json"
        }

    def _handle_response(self, response: requests.Response) -> Dict[str, Any]:
        """统一处理API响应"""
        try:
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            error_msg = f"HTTP错误: {e.response.status_code} - {e.response.text}"
            self.logger.error(error_msg)
            raise APIRequestError(
                error_msg,
                status_code=e.response.status_code,
                response=e.response
            )
        except json.JSONDecodeError:
            error_msg = "响应JSON解析失败"
            self.logger.error(error_msg)
            raise APIRequestError(error_msg, response=response)

    def _encrypt_sensitive_fields(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """加密敏感字段"""
        if not self.config.aes_key or not self.config.aes_iv:
            raise EncryptionError("缺少AES密钥或IV配置")

        encrypted_payload = {}
        for key, value in payload.items():
            if key in ["password", "token", "credit_card", "ssn"]:  # 需要加密的字段
                try:
                    encrypted_payload[key] = CryptoUtils.aes_encrypt(
                        str(value),
                        self.config.aes_key,
                        self.config.aes_iv
                    )
                except Exception as e:
                    raise EncryptionError(f"加密字段 {key} 失败: {str(e)}")
            else:
                encrypted_payload[key] = value
        return encrypted_payload

    def login(self, username: str, password: str) -> str:
        """用户登录并获取token"""
        url = f"{self.config.base_url}/auth/login"

        # 构建请求体并加密敏感字段
        payload = {
            "username": username,
            "password": password
        }
        encrypted_payload = self._encrypt_sensitive_fields(payload)

        # 添加公共参数
        full_payload = {
            **encrypted_payload,
            "app_id": self.config.app_id,
            "timestamp": CryptoUtils.get_current_timestamp()
        }

        # 发送请求
        headers = self._build_headers()
        self.logger.info(f"登录请求: {url}, 请求头: {headers}")

        try:
            response = self.session.post(
                url,
                json=full_payload,
                headers=headers,
                timeout=self.timeout
            )
            result = self._handle_response(response)
            self.token = result.get("data", {}).get("token")
            if not self.token:
                raise APIRequestError("响应中未包含token")
            return self.token
        except Exception as e:
            self.logger.error(f"登录失败: {str(e)}")
            raise

    def get(self, endpoint: str, params: Optional[Dict] = None, headers: Optional[Dict] = None) -> Dict:
        """发送GET请求"""
        url = f"{self.config.base_url}/{endpoint.lstrip('/')}"

        # 合并请求头
        base_headers = self._build_headers()
        if self.token:
            base_headers["Authorization"] = f"Bearer {self.token}"
        merged_headers = {**base_headers, **(headers or {})}

        self.logger.info(f"GET请求: {url}, 参数: {params}")

        try:
            response = self.session.get(
                url,
                params=params,
                headers=merged_headers,
                timeout=self.timeout
            )
            return self._handle_response(response)
        except Exception as e:
            self.logger.error(f"GET请求失败: {str(e)}")
            raise

    def post(self, endpoint: str, data: Dict, headers: Optional[Dict] = None) -> Dict:
        """发送POST请求"""
        url = f"{self.config.base_url}/{endpoint.lstrip('/')}"

        # 合并请求头
        base_headers = self._build_headers()
        if self.token:
            base_headers["Authorization"] = f"Bearer {self.token}"
        merged_headers = {**base_headers, **(headers or {})}

        # 加密敏感字段
        encrypted_data = self._encrypt_sensitive_fields(data)

        self.logger.info(f"POST请求: {url}, 数据: {encrypted_data}")

        try:
            response = self.session.post(
                url,
                json=encrypted_data,
                headers=merged_headers,
                timeout=self.timeout
            )
            return self._handle_response(response)
        except Exception as e:
            self.logger.error(f"POST请求失败: {str(e)}")
            raise