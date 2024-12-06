import pytest
import requests
import logging
from api_tester import BASE_URL, LOGIN_ENDPOINT, TRANSACTION_ENDPOINT

# Configure logging
logging.basicConfig(filename="api_test.log", level=logging.INFO)

def log_test_results(test_name, result):
    """
    Logs the results of each test to a file.
    """
    logging.info(f"{test_name}: {result}")

# Define test fixtures for reusable test data
@pytest.fixture
def valid_credentials():
    """
    Provides valid credentials for testing login functionality.
    """
    return {"username": "admin", "password": "password123"}

@pytest.fixture
def invalid_credentials():
    """
    Provides invalid credentials for testing login functionality.
    """
    return {"username": "admin", "password": "wrongpassword"}

@pytest.fixture
def tampered_token():
    """
    Provides a tampered token for testing unauthorized access.
    """
    return "tampered_token"

@pytest.fixture
def valid_token():
    """
    Provides a valid token for testing authorized access.
    """
    return "valid_token"

# Test login functionality
def test_login_with_valid_credentials(valid_credentials):
    """
    Test the /login endpoint with valid credentials.
    Expect a 200 status code and a valid token in the response.
    """
    response = requests.post(LOGIN_ENDPOINT, json=valid_credentials)
    result = "PASS" if response.status_code == 200 and "token" in response.json() else "FAIL"
    log_test_results("test_login_with_valid_credentials", result)
    assert response.status_code == 200
    assert "token" in response.json()

def test_login_with_invalid_credentials(invalid_credentials):
    """
    Test the /login endpoint with invalid credentials.
    Expect a 401 status code and an error message.
    """
    response = requests.post(LOGIN_ENDPOINT, json=invalid_credentials)
    result = "PASS" if response.status_code == 401 and "error" in response.json() else "FAIL"
    log_test_results("test_login_with_invalid_credentials", result)
    assert response.status_code == 401
    assert "error" in response.json()
    assert response.json()["error"] == "Invalid credentials"

# Test token validation
def test_transaction_with_valid_token(valid_token):
    """
    Test the /transaction endpoint with a valid token.
    Expect a 200 status code and a success message.
    """
    headers = {"Authorization": valid_token}
    response = requests.post(TRANSACTION_ENDPOINT, headers=headers)
    result = "PASS" if response.status_code == 200 and response.json()["status"] == "Transaction successful" else "FAIL"
    log_test_results("test_transaction_with_valid_token", result)
    assert response.status_code == 200
    assert response.json()["status"] == "Transaction successful"

def test_transaction_with_tampered_token(tampered_token):
    """
    Test the /transaction endpoint with a tampered token.
    Expect a 403 status code and an error message.
    """
    headers = {"Authorization": tampered_token}
    response = requests.post(TRANSACTION_ENDPOINT, headers=headers)
    result = "PASS" if response.status_code == 403 and response.json()["error"] == "Unauthorized" else "FAIL"
    log_test_results("test_transaction_with_tampered_token", result)
    assert response.status_code == 403
    assert response.json()["error"] == "Unauthorized"

def test_transaction_without_token():
    """
    Test the /transaction endpoint without any token.
    Expect a 403 status code and an error message.
    """
    response = requests.post(TRANSACTION_ENDPOINT)
    result = "PASS" if response.status_code == 403 and response.json()["error"] == "Unauthorized" else "FAIL"
    log_test_results("test_transaction_without_token", result)
    assert response.status_code == 403
    assert response.json()["error"] == "Unauthorized"

# Parametrized test for token validation
@pytest.mark.parametrize("token", [
    "valid_token",
    "expired_token",
    "tampered_token",
    None  # No token
])
def test_api_tokens(token):
    """
    Tests the /transaction endpoint with various token scenarios:
    - valid_token: Should return 200
    - expired_token: Should return 403
    - tampered_token: Should return 403
    - None (no token): Should return 403
    """
    headers = {"Authorization": token} if token else {}
    response = requests.post(TRANSACTION_ENDPOINT, headers=headers)
    if token == "valid_token":
        result = "PASS" if response.status_code == 200 else "FAIL"
    else:
        result = "PASS" if response.status_code == 403 else "FAIL"
    log_test_results(f"test_api_tokens_{token}", result)

    if token == "valid_token":
        assert response.status_code == 200
        assert response.json()["status"] == "Transaction successful"
    else:
        assert response.status_code == 403
        assert response.json()["error"] == "Unauthorized"
