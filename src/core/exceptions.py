class SecurityError(Exception):
    """安全相关异常基类"""
    pass

class SignatureVerificationError(SecurityError):
    """签名验证失败异常"""
    pass

class EncryptionError(SecurityError):
    """加密/解密失败异常"""
    pass

class ConfigurationError(Exception):
    """配置错误异常"""
    pass

class APIRequestError(Exception):
    """API请求异常"""
    def __init__(self, message, status_code=None, response=None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response