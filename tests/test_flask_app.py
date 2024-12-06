import pytest
from flask import Flask
from flask.testing import FlaskClient
from flask_app.app import app # Import the Flask app from app.py

@pytest.fixture
def client():
    """
    Provides a test client for the Flask application.
    """
    app.testing = True  # Enable testing mode for Flask
    with app.test_client() as client:
        yield client

# Test the /health endpoint
def test_health_check(client: FlaskClient):
    """
    Test the /health endpoint to ensure the API is running.
    Expect a 200 status code and a success message.
    """
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json == {"status": "API is running"}

# Test the /login endpoint with valid credentials
def test_login_valid(client: FlaskClient):
    """
    Test the /login endpoint with valid credentials.
    Expect a 200 status code and a valid token in the response.
    """
    response = client.post("/login", json={"username": "admin", "password": "password123"})
    assert response.status_code == 200
    assert "token" in response.json

# Test the /login endpoint with invalid credentials
def test_login_invalid(client: FlaskClient):
    """
    Test the /login endpoint with invalid credentials.
    Expect a 401 status code and an error message.
    """
    response = client.post("/login", json={"username": "admin", "password": "wrongpassword"})
    assert response.status_code == 401
    assert "error" in response.json
    assert response.json["error"] == "Invalid credentials"

# Test the /transaction endpoint with a valid token
def test_transaction_valid_token(client: FlaskClient):
    """
    Test the /transaction endpoint with a valid token.
    Expect a 200 status code and a success message.
    """
    headers = {"Authorization": "valid_token"}
    response = client.post("/transaction", headers=headers)
    assert response.status_code == 200
    assert response.json == {"status": "Transaction successful"}

# Test the /transaction endpoint with an invalid token
def test_transaction_invalid_token(client: FlaskClient):
    """
    Test the /transaction endpoint with an invalid token.
    Expect a 403 status code and an error message.
    """
    headers = {"Authorization": "tampered_token"}
    response = client.post("/transaction", headers=headers)
    assert response.status_code == 403
    assert response.json == {"error": "Unauthorized"}

# Test the /validate endpoint with valid input
def test_validate_valid_input(client: FlaskClient):
    """
    Test the /validate endpoint with valid input.
    Expect a 200 status code and a success message.
    """
    response = client.post("/validate", json={"input": "This is valid input."})
    assert response.status_code == 200
    assert response.json == {"status": "Input is valid"}

# Test the /validate endpoint with SQL injection input
def test_validate_sql_injection(client: FlaskClient):
    """
    Test the /validate endpoint with an SQL injection payload.
    Expect a 400 status code and an error message.
    """
    response = client.post("/validate", json={"input": "' OR '1'='1'; --"})
    assert response.status_code == 400
    assert response.json == {"error": "Potential SQL injection detected"}

# Test the /validate endpoint with XSS input
def test_validate_xss(client: FlaskClient):
    """
    Test the /validate endpoint with an XSS payload.
    Expect a 400 status code and an error message.
    """
    response = client.post("/validate", json={"input": "<script>alert('XSS')</script>"})
    assert response.status_code == 400
    assert response.json == {"error": "Potential XSS detected"}

# Test the /validate endpoint with large input
def test_validate_large_input(client: FlaskClient):
    """
    Test the /validate endpoint with a large input payload.
    Expect a 400 status code and an error message.
    """
    response = client.post("/validate", json={"input": "A" * 5000})
    assert response.status_code == 400
    assert response.json == {"error": "Input too large"}
