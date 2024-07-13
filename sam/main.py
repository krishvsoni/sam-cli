from luaparser import ast, astnodes
import os
import json
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

INT_MAX = 2147483647
INT_MIN = -2147483648

vulnerabilities = []

def add_vulnerability(name, description, pattern, severity, line):
    vulnerabilities.append({
        "name": name,
        "description": description,
        "pattern": pattern,
        "severity": severity,
        "line": line
    })

def is_potential_overflow(number):
    return number >= INT_MAX or number <= INT_MIN

def is_potential_underflow(number):
    return number <= INT_MIN or number >= INT_MAX

def get_line_number(node):
    if hasattr(node, 'line') and node.line is not None:
        return node.line
    if hasattr(node, '_parent'):
        return get_line_number(node._parent)
    return None

def analyze_overflow_in_node(node):
    if isinstance(node, (astnodes.AddOp, astnodes.SubOp, astnodes.MultOp)):
        left_operand = node.left
        right_operand = node.right

        if isinstance(left_operand, astnodes.Number) and is_potential_overflow(left_operand.n):
            add_vulnerability(
                "Integer Overflow",
                "Potential integer overflow detected with left operand.",
                "overflow",
                "high",
                get_line_number(left_operand)
            )

        if isinstance(right_operand, astnodes.Number) and is_potential_overflow(right_operand.n):
            add_vulnerability(
                "Integer Overflow",
                "Potential integer overflow detected with right operand.",
                "overflow",
                "high",
                get_line_number(right_operand)
            )

    if isinstance(node, astnodes.LocalAssign):
        for value in node.values:
            if isinstance(value, astnodes.Number) and is_potential_overflow(value.n):
                add_vulnerability(
                    "Integer Overflow",
                    "Potential integer overflow detected with local variable assignment.",
                    "overflow",
                    "high",
                    get_line_number(value)
                )

    if isinstance(node, astnodes.Function):
        for arg in node.args:
            if isinstance(arg, astnodes.Number) and is_potential_overflow(arg.n):
                add_vulnerability(
                    "Integer Overflow",
                    "Potential integer overflow detected with function argument.",
                    "overflow",
                    "high",
                    get_line_number(arg)
                )

def analyze_underflow_in_node(node):
    if isinstance(node, (astnodes.AddOp, astnodes.SubOp, astnodes.MultOp)):
        left_operand = node.left
        right_operand = node.right

        if isinstance(left_operand, astnodes.Number) and is_potential_underflow(left_operand.n):
            add_vulnerability(
                "Integer Underflow",
                "Potential integer underflow detected with left operand.",
                "underflow",
                "high",
                get_line_number(left_operand)
            )

        if isinstance(right_operand, astnodes.Number) and is_potential_underflow(right_operand.n):
            add_vulnerability(
                "Integer Underflow",
                "Potential integer underflow detected with right operand.",
                "underflow",
                "high",
                get_line_number(right_operand)
            )

    if isinstance(node, astnodes.LocalAssign):
        for value in node.values:
            if isinstance(value, astnodes.Number) and is_potential_underflow(value.n):
                add_vulnerability(
                    "Integer Underflow",
                    "Potential integer underflow detected with local variable assignment.",
                    "underflow",
                    "high",
                    get_line_number(value)
                )

    if isinstance(node, astnodes.Function):
        for arg in node.args:
            if isinstance(arg, astnodes.Number) and is_potential_underflow(arg.n):
                add_vulnerability(
                    "Integer Underflow",
                    "Potential integer underflow detected with function argument.",
                    "underflow",
                    "high",
                    get_line_number(arg)
                )

def analyze_overflow_and_return(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        analyze_overflow_in_node(node)

        if isinstance(node, astnodes.Function):
            for body_node in ast.walk(node.body):
                analyze_overflow_in_node(body_node)

            if node.name.id == 'another_example':
                for n in node.body.body:
                    if isinstance(n, astnodes.Return):
                        for ret_val in n.values:
                            if isinstance(ret_val, astnodes.Number) and is_potential_overflow(ret_val.n):
                                add_vulnerability(
                                    "Integer Overflow",
                                    f"Potential integer overflow detected in return statement of function '{node.name.id}'.",
                                    "overflow",
                                    "high",
                                    get_line_number(ret_val)
                                )

def analyze_underflow_and_return(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        analyze_underflow_in_node(node)

        if isinstance(node, astnodes.Function):
            for body_node in ast.walk(node.body):
                analyze_underflow_in_node(body_node)

            if node.name.id == 'another_example':
                for n in node.body.body:
                    if isinstance(n, astnodes.Return):
                        for ret_val in n.values:
                            if isinstance(ret_val, astnodes.Number) and is_potential_underflow(ret_val.n):
                                add_vulnerability(
                                    "Integer Underflow",
                                    f"Potential integer underflow detected in return statement of function '{node.name.id}'.",
                                    "underflow",
                                    "high",
                                    get_line_number(ret_val)
                                )

def analyze_return(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            has_return = any(isinstance(n, astnodes.Return) for n in node.body.body)
            if not has_return:
                add_vulnerability(
                    "Missing Return Statement",
                    "A function is missing a return statement.",
                    "missing_return",
                    "low",
                    get_line_number(node)
                )

def check_private_key_exposure(code):
    tree = ast.parse(code)
    private_key_words = ["privatekey", "private_key", "secretkey", "secret_key", "keypair", "key_pair", "api_key"]

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Assign):
            for target in node.targets:
                if isinstance(target, astnodes.Name) and target.id.lower() in private_key_words:
                    add_vulnerability(
                        "Private Key Exposure",
                        f"Potential exposure of private key in variable '{target.id}'.",
                        "private_key_exposure",
                        "high",
                        get_line_number(node)
                    )

def analyze_reentrancy(code):
    tree = ast.parse(code)

    def is_external_call(node):
        return isinstance(node, astnodes.Call) and isinstance(node.func, astnodes.Name) and node.func.id == "external_call"

    def has_state_change(node):
        return isinstance(node, astnodes.Assign)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            body = node.body.body
            for i, n in enumerate(body):
                if is_external_call(n):
                    for subsequent_node in body[i+1:]:
                        if has_state_change(subsequent_node):
                            add_vulnerability(
                                "Reentrancy",
                                f"Reentrancy vulnerability detected in function '{node.name.id}'.",
                                "reentrancy",
                                "high",
                                get_line_number(node)
                            )

def analyze_floating_pragma(code):
    tree = ast.parse(code)
    deprecated_functions = ["setfenv", "getfenv"]

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Call) and isinstance(node.func, astnodes.Name) and node.func.id in deprecated_functions:
            add_vulnerability(
                "Floating Pragma",
                f"Deprecated function '{node.func.id}' used.",
                "floating_pragma",
                "medium",
                get_line_number(node)
            )

def analyze_denial_of_service(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            body = node.body.body
            for n in body:
                if isinstance(n, astnodes.Fornum):
                    if isinstance(n.body[0], astnodes.Call):
                        add_vulnerability(
                            "Denial of Service",
                            f"Potential denial of service detected in function '{node.name.id}' due to expensive operation in loop.",
                            "denial_of_service",
                            "high",
                            get_line_number(node)
                        )

def analyze_unchecked_external_calls(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            for body_node in ast.walk(node.body):
                if isinstance(body_node, astnodes.Call) and isinstance(body_node.func, astnodes.Attribute):
                    if body_node.func.attr == "some_function":
                        add_vulnerability(
                            "Unchecked External Call",
                            f"Unchecked external call in function '{node.name.id}'.",
                            "unchecked_external_call",
                            "high",
                            get_line_number(body_node)
                        )

def analyze_greedy_suicidal_functions(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            for body_node in ast.walk(node.body):
                if isinstance(body_node, astnodes.Call) and isinstance(body_node.func, astnodes.Name) and body_node.func.id == "transfer":
                    add_vulnerability(
                        "Greedy/Suicidal Function",
                        f"Function '{node.name.id}' includes a transfer of funds.",
                        "greedy_suicidal_function",
                        "high",
                        get_line_number(body_node)
                    )

def analyze_code_for_vulnerabilities(code):
    analyze_overflow_and_return(code)
    analyze_underflow_and_return(code)
    analyze_return(code)
    check_private_key_exposure(code)
    analyze_reentrancy(code)
    analyze_floating_pragma(code)
    analyze_denial_of_service(code)
    analyze_unchecked_external_calls(code)
    analyze_greedy_suicidal_functions(code)

def process_files_in_directory(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.lua'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    code = f.read()

                code_lines = code.split('\n')
                code_lines = [line for line in code_lines if not line.startswith('require')]
                cleaned_code = '\n'.join(code_lines)

                analyze_code_for_vulnerabilities(cleaned_code)

def generate_vulnerability_report(output_file, vulnerabilities):
    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template('report_template.html')

    html_content = template.render(vulnerabilities=vulnerabilities)

    with open(output_file, 'w') as f:
        f.write(html_content)

def main():
    directory = input("Enter the directory containing Lua files: ")
    process_files_in_directory(directory)

    output_file = 'vulnerability_report.html'
    generate_vulnerability_report(output_file, vulnerabilities)
    print(f"Vulnerability report generated: {output_file}")

if __name__ == "__main__":
    main()
