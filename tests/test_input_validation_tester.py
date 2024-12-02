import pytest
import requests
from input_validation_tester import BASE_URL

# Define the validation endpoint
VALIDATE_ENDPOINT = f"{BASE_URL}/validate"

# Define test fixtures for input payloads
@pytest.fixture
def sql_injection_payload():
    """
    Provides a payload designed to simulate an SQL injection attack.
    """
    return "' OR '1'='1'; --"

@pytest.fixture
def xss_payload():
    """
    Provides a payload designed to simulate a Cross-Site Scripting (XSS) attack.
    """
    return "<script>alert('XSS')</script>"

@pytest.fixture
def large_payload():
    """
    Provides a payload designed to simulate a buffer overflow or oversized input attack.
    """
    return "A" * 5000  # Payload with 5000 characters

@pytest.fixture
def valid_payload():
    """
    Provides a valid, harmless payload for testing successful input validation.
    """
    return "This is a valid input."

@pytest.fixture
def empty_payload():
    """
    Provides an empty payload to test handling of missing inputs.
    """
    return ""

# Test SQL Injection payload
def test_sql_injection(sql_injection_payload):
    """
    Test the /validate endpoint with an SQL injection payload.
    Expect a 400 status code and a specific error message.
    """
    response = requests.post(VALIDATE_ENDPOINT, json={"input": sql_injection_payload})
    assert response.status_code == 400
    assert "error" in response.json()
    assert response.json()["error"] == "Potential SQL injection detected"

# Test XSS payload
def test_xss_attack(xss_payload):
    """
    Test the /validate endpoint with an XSS payload.
    Expect a 400 status code and a specific error message.
    """
    response = requests.post(VALIDATE_ENDPOINT, json={"input": xss_payload})
    assert response.status_code == 400
    assert "error" in response.json()
    assert response.json()["error"] == "Potential XSS detected"

# Test large payload
def test_large_payload(large_payload):
    """
    Test the /validate endpoint with a large payload.
    Expect a 400 status code and a specific error message.
    """
    response = requests.post(VALIDATE_ENDPOINT, json={"input": large_payload})
    assert response.status_code == 400
    assert "error" in response.json()
    assert response.json()["error"] == "Input too large"

# Test valid payload
def test_valid_input(valid_payload):
    """
    Test the /validate endpoint with a valid payload.
    Expect a 200 status code and a success message.
    """
    response = requests.post(VALIDATE_ENDPOINT, json={"input": valid_payload})
    assert response.status_code == 200
    assert "status" in response.json()
    assert response.json()["status"] == "Input is valid"

# Test empty payload
def test_empty_input(empty_payload):
    """
    Test the /validate endpoint with an empty payload.
    Expect a 400 status code and a specific error message.
    """
    response = requests.post(VALIDATE_ENDPOINT, json={"input": empty_payload})
    assert response.status_code == 400
    assert "error" in response.json()
    assert response.json()["error"] == "Input fields cannot be empty"
