import pytest
import yaml  # 添加缺失的导入
from pathlib import Path
from src.core.api_client import FineAPIClient
from config.settings import Config

# 实现缺失的load_test_data函数
def load_test_data(filename: str) -> list:
    data_path = Path(__file__).parent / "data" / filename
    with open(data_path, 'r') as f:
        return yaml.safe_load(f)

@pytest.fixture(scope="module")
def api_client():
    return FineAPIClient(Config())

@pytest.mark.parametrize("case", load_test_data("login_cases.yaml"))
def test_login(api_client, case):
    response = api_client.post_encrypted("/auth/login", case["payload"])
    assert response["code"] == case["expected_code"]
    if case["should_have_token"]:
        assert len(response["data"]["token"]) > 0