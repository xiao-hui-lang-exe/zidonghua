import pytest
from tests.conftest import load_test_data
from typing import Dict, Any


# 使用参数化加载测试数据
@pytest.mark.parametrize("test_case", load_test_data("login_cases.yaml"))
def test_login_scenarios(api_client, test_case: Dict[str, Any]):  # 添加类型注解
    """测试不同登录场景"""
    from config.settings import Config
    from src.core.api_client import FineAPIClient
    client = FineAPIClient(Config())

    try:
        # 尝试登录
        token = client.login(test_case['username'], test_case['password'])

        # 验证预期成功的情况
        if test_case['expected_status'] == 200:
            assert token, "登录成功但未返回token"
            # 修复类型警告：使用isinstance检查类型
            assert isinstance(token, str), "token应为字符串类型"
            assert len(token) > 20, "token长度不足"
        else:
            pytest.fail(f"预期失败但登录成功，token: {token}")

    except Exception as e:
        # 验证预期失败的情况
        if test_case['expected_status'] == 200:
            pytest.fail(f"预期成功但登录失败: {str(e)}")
        else:
            # 修复类型警告：将状态码转换为字符串进行比较
            assert str(test_case['expected_status']) in str(e), f"错误类型不匹配: {str(e)}"


def test_protected_resource_access(api_client):
    """测试访问需要认证的资源"""
    try:
        # 访问用户信息端点
        response = api_client.get("/user/profile")

        # 修复类型警告：添加类型检查
        assert isinstance(response, dict), "响应应为字典类型"
        assert 'data' in response, "响应缺少data字段"
        assert isinstance(response['data'], dict), "data字段应为字典类型"

        user_data = response['data']
        assert 'user_id' in user_data, "响应缺少user_id"
        assert 'username' in user_data, "响应缺少username"
        assert 'email' in user_data, "响应缺少email"

    except Exception as e:
        pytest.fail(f"访问受保护资源失败: {str(e)}")


def test_invalid_token_access():
    """测试使用无效token访问资源"""
    from config.settings import Config
    from src.core.api_client import FineAPIClient

    client = FineAPIClient(Config())
    client.token = "invalid_token_1234567890"

    with pytest.raises(Exception) as exc_info:
        client.get("/user/profile")

    # 修复类型警告：确保比较的是字符串
    error_msg = str(exc_info.value)
    assert "401" in error_msg or "Unauthorized" in error_msg, "预期401未授权错误"