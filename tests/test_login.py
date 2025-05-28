import pytest
from tests.conftest import load_test_data, test_client
from src.core.exceptions import APIRequestError
from config.settings import Config
from typing import Dict, Any


# 使用参数化加载测试数据
@pytest.mark.parametrize("test_case", load_test_data("login_cases.yaml", Config().app_id))
def test_login_scenarios(test_client, test_case: Dict[str, Any]):
    """测试不同登录场景"""
    try:
        # 尝试登录
        token = test_client.login(test_case['username'], test_case['password'])

        # 验证预期成功的情况
        if test_case['expected_status'] == 200:
            assert token, "登录成功但未返回token"
            assert isinstance(token, str), "token应为字符串类型"
            assert len(token) > 20, "token长度不足"
        else:
            pytest.fail(f"预期失败但登录成功，token: {token}")

    except APIRequestError as e:  # 精确捕获API请求异常
        # 验证预期失败的情况
        if test_case['expected_status'] == 200:
            pytest.fail(f"预期成功但登录失败: {str(e)}")
        else:
            # 检查状态码是否匹配
            assert e.status_code == test_case['expected_status'], (
                f"预期状态码 {test_case['expected_status']}，实际 {e.status_code}"
            )


def test_protected_resource_access(api_client):
    """测试访问需要认证的资源"""
    try:
        # 访问用户信息端点
        response = api_client.get("/user/profile")

        # 验证响应结构
        assert isinstance(response, dict), "响应应为字典类型"
        assert 'data' in response, "响应缺少data字段"
        assert isinstance(response['data'], dict), "data字段应为字典类型"

        user_data = response['data']
        assert 'user_id' in user_data, "响应缺少user_id"
        assert 'username' in user_data, "响应缺少username"
        assert 'email' in user_data, "响应缺少email"

    except Exception as e:
        pytest.fail(f"访问受保护资源失败: {str(e)}")


def test_invalid_token_access(test_client):
    """测试使用无效token访问资源"""
    test_client.token = "invalid_token_1234567890"

    with pytest.raises(APIRequestError) as exc_info:
        test_client.get("/user/profile")

    # 验证状态码
    assert exc_info.value.status_code == 401, "预期401未授权错误"