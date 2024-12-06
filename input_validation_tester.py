import requests
import logging

# Set up logging
logging.basicConfig(filename="input_validation.log", level=logging.INFO)

def log_input_test(payload, response):
    """
    Logs the input payload and the corresponding API response.
    """
    logging.info(f"Payload: {payload}, Response: {response.json()}")

# Base URL and endpoint for the mock API
BASE_URL = "http://127.0.0.1:5000"
VALIDATE_ENDPOINT = f"{BASE_URL}/validate"

# Test various payloads
def test_input_validation():
    """
    Test the /validate endpoint with various payloads for input validation.
    """
    payloads = [
        "' OR '1'='1'; --",                # SQL injection payload
        "<script>alert('XSS')</script>",   # XSS payload
        "A" * 5000,                        # Large payload
        "Valid input",                     # Valid input
        ""                                 # Empty input
    ]

    for payload in payloads:
        response = requests.post(VALIDATE_ENDPOINT, json={"input": payload})
        log_input_test(payload, response)  # Log the test payload and response

        if payload == "Valid input":
            assert response.status_code == 200
            assert response.json()["status"] == "Input is valid"
        elif payload == "":
            assert response.status_code == 400
            assert response.json()["error"] == "Input fields cannot be empty"
        elif len(payload) > 1000:
            assert response.status_code == 400
            assert response.json()["error"] == "Input too large"
        elif "' OR '" in payload or "--" in payload:
            assert response.status_code == 400
            assert response.json()["error"] == "Potential SQL injection detected"
        elif "<script>" in payload:
            assert response.status_code == 400
            assert response.json()["error"] == "Potential XSS detected"

# Run the test function
if __name__ == "__main__":
    test_input_validation()
