import requests
import logging

# Configure logging
logging.basicConfig(filename="api_test.log", level=logging.INFO)

def log_test_results(test_name, result):
    """
    Logs the results of each test to a file.
    """
    logging.info(f"{test_name}: {result}")

# Define base URL and endpoints
BASE_URL = "http://127.0.0.1:5000"
LOGIN_ENDPOINT = f"{BASE_URL}/login"
TRANSACTION_ENDPOINT = f"{BASE_URL}/transaction"

# Function to test token validation
def test_token_validation():
    """
    This function tests if the API properly validates different types of tokens.
    It simulates a scenario where tokens can be valid, expired, or tampered.
    """
    tokens = {
        "valid": "valid_token",          # Correct token expected to work
        "expired": "expired_token",      # Simulates a token that has expired
        "tampered": "tampered_token"    # Simulates a token that has been altered
    }

    print("Testing Token Validation:")
    for token_type, token in tokens.items():
        # Send POST request to the transaction endpoint with a token
        response = requests.post(
            TRANSACTION_ENDPOINT,
            headers={"Authorization": token}
        )
        # Log and print the response for each token type
        result = "PASS" if token_type == "valid" and response.status_code == 200 else "FAIL"
        log_test_results(f"test_token_validation_{token_type}", result)
        print(f"Token Type: {token_type}, Status Code: {response.status_code}, Response: {response.json()}")

# Function to test unauthorized access
def test_unauthorized_access():
    """
    This function tests if the API blocks access when no token is provided.
    Unauthorized requests should return a 403 status code.
    """
    print("\nTesting Unauthorized Access:")
    # Send POST request without authorization header
    response = requests.post(TRANSACTION_ENDPOINT)
    # Log and print the response for unauthorized access
    result = "PASS" if response.status_code == 403 else "FAIL"
    log_test_results("test_unauthorized_access", result)
    print(f"Unauthorized Access Test: Status Code: {response.status_code}, Response: {response.json()}")

# Function to test login functionality
def test_login_functionality():
    """
    This function tests the login endpoint with valid and invalid credentials.
    It checks whether the API correctly handles login attempts.
    """
    test_cases = [
        {"username": "admin", "password": "password123"},  # Valid credentials
        {"username": "admin", "password": "wrongpassword"},  # Invalid credentials
        {"username": "unknown", "password": "password123"}   # Nonexistent user
    ]

    print("\nTesting Login Functionality:")
    for credentials in test_cases:
        # Send POST request to the login endpoint with test credentials
        response = requests.post(LOGIN_ENDPOINT, json=credentials)
        # Log and print the response for each set of credentials
        result = "PASS" if credentials["username"] == "admin" and response.status_code == 200 else "FAIL"
        log_test_results(f"test_login_functionality_{credentials['username']}", result)
        print(f"Credentials: {credentials}, Status Code: {response.status_code}, Response: {response.json()}")

# Main function to run all tests
if __name__ == "__main__":
    """
    This script can be run directly to test the API endpoints.
    It sequentially executes all the test functions defined above.
    """
    test_token_validation()          # Test token validation
    test_unauthorized_access()       # Test unauthorized access
    test_login_functionality()       # Test login functionality
