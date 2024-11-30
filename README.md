# Crypto Exchange Penetration Testing Toolkit

## Overview
The Crypto Exchange Penetration Testing Toolkit is designed to test and identify security vulnerabilities in cryptocurrency exchanges. This toolkit targets common exploits such as:
- **API vulnerabilities** (e.g., weak token validation, unauthorized access)
- **Improper input validation** (e.g., SQL injection, XSS attacks)
- **Weakness reporting** with severity rankings and recommendations.

---

## Features
1. **API Testing Module (`api_tester.py`)**
   - Tests for token validation, unauthorized access, and rate-limiting issues.

2. **Input Validation Testing Module (`input_validation_tester.py`)**
   - Identifies risks like SQL injection, cross-site scripting (XSS), and buffer overflow.

3. **Reporting Module (`report_generator.py`)**
   - Generates detailed reports in JSON format.
   - Visualizes vulnerabilities by severity using bar charts.

4. **Mock Cryptocurrency Exchange API (`flask_app/app.py`)**
   - Simulates a cryptocurrency exchange for safe testing.

---

## File Structure
```plaintext
crypto-exchange-pen-test-toolkit/
├── api_tester.py
├── input_validation_tester.py
├── report_generator.py
├── flask_app/
│   ├── app.py
│   └── requirements.txt
├── tests/
│   ├── test_api_tester.py
│   ├── test_input_validation_tester.py
│   └── test_flask_app.py
├── logs/
│   ├── api_test.log
│   ├── input_validation.log
│   └── server.log
├── reports/
│   └── test_report.json
├── README.md
└── LICENSE

```

---

## Installation
### Prerequisites
- Python 3.8+
- Flask
- `pip` (Python package manager)

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/JustinRLew/crypto-exchange-pen-test-toolkit.git
   cd crypto-exchange-pen-test-toolkit

2. Create a virtual environment and activate it:

bash
python3 -m venv venv
source venv/bin/activate

3. Install dependencies:

bash
pip install -r flask_app/requirements.txt

4. Run the mock API:
bash
python flask_app/app.py

5. Run the test modules:
bash
python api_tester.py
python input_validation_tester.py
python report_generator.py

## Usage
- **API Testing**: Detect issues like unauthorized access or token tampering.
- **Input Validation Testing**: Identify vulnerabilities from malicious payloads.
- **Reporting**: Generate JSON reports and visualize severity rankings.

## Example Use Case
The toolkit can detect vulnerabilities such as:

- **Weak Token Validation**: Prevent hackers from tampering with tokens to gain unauthorized access.
- **SQL Injection**: Identify input fields susceptible to SQL injection, potentially leaking sensitive data.
- **Unauthorized API Access**: Test endpoints for insufficient access controls.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
