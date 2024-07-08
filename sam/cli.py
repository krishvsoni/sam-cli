import argparse
import os
from .main import *

def run_analysis(file_path):
    with open(file_path, 'r') as file:
        code = file.read()

    analyze_return(code)
    analyze_overflow_and_return(code)
    analyze_underflow_and_return(code)
    analyze_reentrancy(code)
    check_private_key_exposure(code)
    analyze_floating_pragma(code)
    analyze_denial_of_service(code)
    analyze_unchecked_external_calls(code)
    analyze_greedy_suicidal_functions(code)

    print_vulnerabilities()

    report_file_path = "report.json"
    save_report(report_file_path)
    print(f"\nVulnerability report saved to {report_file_path}\n")

def main():
    parser = argparse.ArgumentParser(description="Lua Vulnerability Analyzer")
    parser.add_argument("file", help="Path to Lua code file")
    parser.add_argument("--function", help="Specify a function to run (e.g., --function analyze_return)")

    args = parser.parse_args()

    if os.path.isfile(args.file):
        print(f"Analyzing file: {args.file}")
        run_analysis(args.file)
    else:
        print("File not found. Please enter a valid file path.")

if __name__ == "__main__":
    main()
