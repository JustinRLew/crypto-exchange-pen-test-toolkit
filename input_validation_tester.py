import requests

# Define base URL and endpoint for testing
BASE_URL = "http://127.0.0.1:5000"
LOGIN_ENDPOINT = f"{BASE_URL}/login"

# Define payloads to test input validation
payloads = [
    "' OR '1'='1'; --",              # SQL Injection
    "<script>alert('XSS')</script>", # Cross-Site Scripting (XSS)
    "A" * 5000                       # Buffer Overflow (oversized input)
]

def test_input_validation():
    """
    This function tests the API's ability to handle various types of malicious inputs.
    It sends each payload to the login endpoint and observes the response.
    """
    print("Testing Input Validation:")
    for payload in payloads:
        # Send a POST request with the payload as the username
        response = requests.post(
            LOGIN_ENDPOINT,
            json={"username": payload, "password": "password123"}
        )
        # Print the result for each payload
        print(f"Payload: {payload}, Status Code: {response.status_code}, Response: {response.json()}")

def test_large_payload_handling():
    """
    This function tests how the API handles unusually large inputs.
    Such inputs can lead to performance issues or buffer overflow attacks.
    """
    oversized_input = "A" * 10000  # Input with 10,000 characters
    print("\nTesting Large Payload Handling:")
    response = requests.post(
        LOGIN_ENDPOINT,
        json={"username": oversized_input, "password": "password123"}
    )
    # Print the result for the oversized input
    print(f"Large Payload Status Code: {response.status_code}, Response: {response.json()}")

def test_empty_input():
    """
    This function tests how the API responds to empty input fields.
    APIs should handle empty inputs gracefully and return an appropriate error message.
    """
    print("\nTesting Empty Input Handling:")
    response = requests.post(
        LOGIN_ENDPOINT,
        json={"username": "", "password": ""}
    )
    # Print the result for empty inputs
    print(f"Empty Input Status Code: {response.status_code}, Response: {response.json()}")

# Main function to run all input validation tests
if __name__ == "__main__":
    """
    This script can be run directly to test the API's input validation.
    It executes all test functions sequentially and prints the results.
    """
    test_input_validation()          # Test for SQL injection, XSS, and buffer overflow
    test_large_payload_handling()    # Test for handling oversized inputs
    test_empty_input()               # Test for handling empty input fields
