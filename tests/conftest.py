import pytest
import yaml
from pathlib import Path
from typing import List, Dict, Any  # 添加显式类型导入
from config.settings import Config
from src.core.api_client import FineAPIClient


def load_test_data(filename: str) -> List[Dict[str, Any]]:  # 添加显式返回类型
    """加载测试数据文件"""
    data_path = Path(__file__).parent / "data" / filename
    try:
        with open(data_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            return data if data else []  # 确保始终返回列表
    except Exception as e:
        pytest.fail(f"加载测试数据失败: {str(e)}")
        return []  # 添加显式return语句


@pytest.fixture(scope="session")
def config() -> Config:  # 添加返回类型注解
    """配置对象fixture"""
    return Config(env='test')  # 显式return语句


@pytest.fixture(scope="module")
def api_client(config: Config) -> FineAPIClient:  # 添加类型注解
    """API客户端fixture"""
    client = FineAPIClient(config)

    # 修复拼写：使用 'test_user' 代替 'testuser'
    username = config.app_id + "_test_user"  # 修正拼写错误
    password = "TestPassword123!"

    try:
        token = client.login(username, password)
        assert token, "登录失败，未获取到token"
        return client  # 显式return语句
    except Exception as e:
        pytest.fail(f"API客户端初始化失败: {str(e)}")
        return client  # 添加显式return语句