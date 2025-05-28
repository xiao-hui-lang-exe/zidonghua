from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.backends.openssl import backend as ossl

print("=== OpenSSL 信息 ===")
print(f"OpenSSL 版本: {backend.openssl_version_text()}")

# 检查是否支持 TLS 1.3
try:
    # 新方法：通过 _lib 直接检查 OpenSSL 功能
    has_tls1_3 = bool(ossl._lib.Cryptography_HAS_TLSv1_3)
except AttributeError:
    # 回退方法：通过版本号判断
    # TLS 1.3 从 OpenSSL 1.1.1 开始支持
    version_text = backend.openssl_version_text().lower()
    if "openssl" in version_text:
        version_str = version_text.split()[1]
        major, minor, patch = map(int, version_str.split('.'))
        # 将版本号转换为可比较的整数：主版本*10000 + 次版本*100 + 修订号
        version_num = major * 10000 + minor * 100 + patch
        has_tls1_3 = version_num >= 10101  # 1.1.1 对应 10101
    else:
        has_tls1_3 = False

print(f"支持TLS 1.3: {'是' if has_tls1_3 else '否'}")