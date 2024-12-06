import json
import matplotlib.pyplot as plt
from api_tester import test_token_validation, test_unauthorized_access
from input_validation_tester import test_input_validation

# Define the report structure as a dictionary
report = {
    "tests": []
}

def add_test_result(test_name, details, severity, recommendation):
    """
    Adds a test result to the report.

    Args:
    - test_name (str): The name of the test performed.
    - details (str): A description of the issue identified.
    - severity (str): The severity level (Low, Medium, High).
    - recommendation (str): Suggested actions to fix the issue.
    """
    report["tests"].append({
        "test_name": test_name,
        "details": details,
        "severity": severity,
        "recommendation": recommendation
    })

def generate_json_report(filename="test_report.json"):
    """
    Generates a JSON report from the collected test results.

    Args:
    - filename (str): The name of the JSON file to save the report.
    """
    with open(filename, "w") as file:
        json.dump(report, file, indent=4)
    print(f"Report saved as {filename}")

def visualize_severity():
    """
    Visualizes the severity levels of vulnerabilities as a bar chart.
    """
    # Count the occurrences of each severity level
    severities = [test["severity"] for test in report["tests"]]
    severity_counts = {s: severities.count(s) for s in set(severities)}

    # Create a bar chart
    plt.bar(severity_counts.keys(), severity_counts.values())
    plt.title("Vulnerability Severity Distribution")
    plt.xlabel("Severity Level")
    plt.ylabel("Number of Vulnerabilities")
    plt.show()

def summarize_report():
    """
    Prints a summary of the report to the console.
    """
    print("\nReport Summary:")
    for test in report["tests"]:
        print(f"Test: {test['test_name']}")
        print(f"Details: {test['details']}")
        print(f"Severity: {test['severity']}")
        print(f"Recommendation: {test['recommendation']}")
        print("-" * 40)

def integrate_results():
    """
    Integrates results from different test modules into a single report.
    """
    # Integrate results from API tests
    add_test_result(
        test_name="Token Validation Test",
        details="API accepts tampered tokens.",
        severity="High",
        recommendation="Ensure proper token verification mechanisms are in place."
    )

    add_test_result(
        test_name="Unauthorized Access Test",
        details="API blocks access without a token.",
        severity="Low",
        recommendation="Continue enforcing strict authentication policies."
    )

    # Integrate results from input validation tests
    add_test_result(
        test_name="Input Validation Test",
        details="Detected SQL injection vulnerability.",
        severity="High",
        recommendation="Sanitize all user inputs and validate payloads."
    )

# Example usage: Adding test results and generating reports
if __name__ == "__main__":
    """
    This script can be run directly to integrate results, generate a JSON report, 
    visualize severity levels, and print a summary.
    """
    # Integrate results from various tests
    integrate_results()

    # Generate and save the JSON report
    generate_json_report()

    # Visualize severity distribution
    visualize_severity()

    # Print a summary of the report
    summarize_report()
