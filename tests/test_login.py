import pytest
from src.core.api_client import FineAPIClient
from config.settings import Config

@pytest.fixture(scope="module")
def api_client():
    return FineAPIClient(Config())

@pytest.mark.parametrize("case", load_test_data("login_cases.yaml"))
def test_login(api_client, case):
    response = api_client.post_encrypted("/auth/login", case["payload"])
    assert response["code"] == case["expected_code"]
    if case["should_have_token"]:
        assert len(response["data"]["token"]) > 0