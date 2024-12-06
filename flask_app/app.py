from flask import Flask, request, jsonify

# Initialize the Flask app
app = Flask(__name__)

# In-memory storage for simplicity (mock database)
USERS = {
    "admin": "password123",  # Example user with username 'admin' and password 'password123'
}
VALID_TOKEN = "valid_token"  # A valid token for testing purposes

# Route: Login
@app.route('/login', methods=['POST'])
def login():
    """
    Simulates a login endpoint.
    Validates user credentials and returns a token if successful.
    """
    data = request.json  # Get the JSON payload from the request
    username = data.get("username")
    password = data.get("password")

    # Check if username exists and password matches
    if username in USERS and USERS[username] == password:
        return jsonify({"token": VALID_TOKEN})  # Return a valid token
    return jsonify({"error": "Invalid credentials"}), 401  # Return error for invalid credentials

# Route: Transaction
@app.route('/transaction', methods=['POST'])
def transaction():
    """
    Simulates a transaction endpoint.
    Requires a valid token to authorize the request.
    """
    token = request.headers.get("Authorization")  # Get the token from the Authorization header

    # Check if the token is valid
    if token == VALID_TOKEN:
        return jsonify({"status": "Transaction successful"})  # Simulate a successful transaction
    return jsonify({"error": "Unauthorized"}), 403  # Return error for unauthorized access

# Route: Health Check
@app.route('/health', methods=['GET'])
def health_check():
    """
    A simple health check endpoint.
    Returns a success message to indicate the API is running.
    """
    return jsonify({"status": "API is running"}), 200

# Route: Input Validation Test
@app.route('/validate', methods=['POST'])
def validate_input():
    """
    Simulates input validation for testing purposes.
    Rejects SQL injection, XSS, or oversized input payloads.
    """
    data = request.json  # Get the JSON payload
    user_input = data.get("input", "")

    # Check for SQL injection pattern
    if "' OR '" in user_input or "--" in user_input:
        return jsonify({"error": "Potential SQL injection detected"}), 400

    # Check for XSS pattern
    if "<script>" in user_input:
        return jsonify({"error": "Potential XSS detected"}), 400

    # Check for oversized input
    if len(user_input) > 1000:
        return jsonify({"error": "Input too large"}), 400

    # If input is valid
    return jsonify({"status": "Input is valid"}), 200

# Run the Flask app
if __name__ == "__main__":
    """
    Runs the Flask development server.
    Accessible at http://127.0.0.1:5000 by default.
    """
    app.run(debug=True)
