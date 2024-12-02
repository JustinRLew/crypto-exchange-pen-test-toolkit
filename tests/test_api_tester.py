import pytest
import requests
from api_tester import BASE_URL, LOGIN_ENDPOINT, TRANSACTION_ENDPOINT

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
    assert response.status_code == 200
    assert "token" in response.json()

def test_login_with_invalid_credentials(invalid_credentials):
    """
    Test the /login endpoint with invalid credentials.
    Expect a 401 status code and an error message.
    """
    response = requests.post(LOGIN_ENDPOINT, json=invalid_credentials)
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
    assert response.status_code == 200
    assert response.json()["status"] == "Transaction successful"

def test_transaction_with_tampered_token(tampered_token):
    """
    Test the /transaction endpoint with a tampered token.
    Expect a 403 status code and an error message.
    """
    headers = {"Authorization": tampered_token}
    response = requests.post(TRANSACTION_ENDPOINT, headers=headers)
    assert response.status_code == 403
    assert response.json()["error"] == "Unauthorized"

def test_transaction_without_token():
    """
    Test the /transaction endpoint without any token.
    Expect a 403 status code and an error message.
    """
    response = requests.post(TRANSACTION_ENDPOINT)
    assert response.status_code == 403
    assert response.json()["error"] == "Unauthorized"
