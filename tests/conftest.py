import pytest
import yaml
from pathlib import Path
from typing import List, Dict, Any
from config.settings import Config
from src.core.api_client import FineAPIClient


def load_test_data(filename: str, app_id: str) -> List[Dict[str, Any]]:
    """加载测试数据文件并动态替换占位符"""
    data_path = Path(__file__).parent / "data" / filename
    try:
        with open(data_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

            # 动态替换占位符
            for item in data:
                if 'username' in item and '${APP_ID}' in item['username']:
                    item['username'] = item['username'].replace('${APP_ID}', app_id)

            return data if data else []
    except Exception as e:
        pytest.fail(f"加载测试数据失败: {str(e)}")
        return []


@pytest.fixture(scope="session")
def config() -> Config:
    """配置对象fixture"""
    return Config(env='test')


@pytest.fixture(scope="module")
def api_client(config: Config) -> FineAPIClient:
    """API客户端fixture"""
    client = FineAPIClient(config)
    username = config.app_id + "_test_user"  # 修复拼写错误
    password = "TestPassword123!"

    try:
        token = client.login(username, password)
        assert token, "登录失败，未获取到token"
        return client
    except Exception as e:
        pytest.fail(f"API客户端初始化失败: {str(e)}")
        return client


# 新增：每个测试函数使用的客户端fixture
@pytest.fixture(scope="function")
def test_client(config: Config) -> FineAPIClient:
    """为每个测试函数创建独立的API客户端"""
    return FineAPIClient(config)