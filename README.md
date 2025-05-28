api_automation/
├── .github/                  # GitHub Actions配置
│   └── workflows/
│       └── ci.yml            # 持续集成配置:cite[9]
├── config/
│   ├── __init__.py
│   ├── settings.py           # 主配置类（环境变量+配置文件）
│   └── security/            # 加密相关配置
│       ├── public_key.pem
│       └── private_key.pem
├── src/
│   ├── core/
│   │   ├── api_client.py     # 增强版API客户端（含加密/签名）
│   │   └── request_factory.py# 请求工厂模式:cite[10]
│   ├── utils/
│   │   ├── crypto.py         # 加密工具（AES/RSA/HMAC）
│   │   ├── logger.py         # 日志模块
│   │   └── data_loader.py    # 数据加载器（YAML/JSON）
│   └── models/
│       └── response.py       # 统一响应模型
├── tests/
│   ├── conftest.py           # 全局fixture配置
│   ├── test_login.py         # 登录测试用例
│   └── data/
│       └── login_cases.yaml  # 参数化测试数据:cite[8]
├── .gitignore                # 忽略证书/日志等敏感文件:cite[1]:cite[7]
├── requirements.txt          # 依赖清单（含安全版本锁定）:cite[1]:cite[5]
└── README.md                 # 工程说明（含安全注意事项）