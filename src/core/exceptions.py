class SecurityError(Exception):
    """安全相关异常基类"""
    pass

class SignatureVerificationError(SecurityError):
    """签名验证失败异常"""
    pass

class EncryptionError(SecurityError):
    """加密/解密失败异常"""
    pass