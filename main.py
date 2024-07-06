from luaparser import ast, astnodes
import os

# Constants for integer overflow detection
INT_MAX = 2147483647
INT_MIN = -2147483648

def analyze_return(code):
    tree = ast.parse(code)
    
    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            has_return = any(isinstance(n, astnodes.Return) for n in node.body.body)
            if not has_return:
                print(f"Function '{node.name.id}' has no return statement at line {get_line_number(node)}")

def is_potential_overflow(number):
    return number >= INT_MAX or number <= INT_MIN

def get_line_number(node):
    if hasattr(node, 'line'):
        return node.line
    return 'unknown'

def analyze_overflow_in_node(node):
    if isinstance(node, (astnodes.AddOp, astnodes.SubOp, astnodes.MultOp)):
        left_operand = node.left
        right_operand = node.right

        if isinstance(left_operand, astnodes.Number) and is_potential_overflow(left_operand.n):
            print(f"Potential integer overflow/underflow detected with left operand at line {get_line_number(node)}")

        if isinstance(right_operand, astnodes.Number) and is_potential_overflow(right_operand.n):
            print(f"Potential integer overflow/underflow detected with right operand at line {get_line_number(node)}")
    
    if isinstance(node, astnodes.LocalAssign):
        for value in node.values:
            if isinstance(value, astnodes.Number) and is_potential_overflow(value.n):
                print(f"Potential integer overflow/underflow detected with local variable assignment at line {get_line_number(node)}")
    
    if isinstance(node, astnodes.Function):
        for arg in node.args:
            if isinstance(arg, astnodes.Number) and is_potential_overflow(arg.n):
                print(f"Potential integer overflow/underflow detected with function argument at line {get_line_number(node)}")

def analyze_overflow_and_return(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        analyze_overflow_in_node(node)
        
        if isinstance(node, astnodes.Function):
            for body_node in ast.walk(node.body):
                analyze_overflow_in_node(body_node)
        
        if isinstance(node, astnodes.Function) and node.name.id == 'another_example':
            for n in node.body.body:
                if isinstance(n, astnodes.Return):
                    for ret_val in n.values:
                        if isinstance(ret_val, astnodes.Number) and is_potential_overflow(ret_val.n):
                            print(f"Potential integer overflow/underflow detected in return statement of function '{node.name.id}' at line {get_line_number(n)}")

def check_private_key_exposure(code):
    tree = ast.parse(code)
    private_key_words = ["privatekey", "private_key", "secretkey", "secret_key", "keypair", "key_pair"]
    
    for node in ast.walk(tree):
        if isinstance(node, astnodes.Assign):
            for target in node.targets:
                if isinstance(target, astnodes.Name) and target.id.lower() in private_key_words:
                    print(f"Potential exposure of private key in variable '{target.id}' at line {get_line_number(node)}")

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
                    # Check subsequent statements for state changes
                    for subsequent_node in body[i+1:]:
                        if has_state_change(subsequent_node):
                            print(f"Potential reentrancy vulnerability detected in function '{node.name.id}' at line {get_line_number(node)}")

def analyze_floating_pragma(code):
    deprecated_functions = ["setfenv", "getfenv"]
    tree = ast.parse(code)
    
    for node in ast.walk(tree):
        if isinstance(node, astnodes.Call) and isinstance(node.func, astnodes.Name):
            if node.func.id in deprecated_functions:
                print(f"Floating pragma issue detected with function '{node.func.id}' at line {get_line_number(node)}")

def main():
    while True:
        file_path = input("Enter the path to the Lua code file (or 'exit' to quit): ").strip()
        if file_path.lower() == 'exit':
            break
        
        if not os.path.isfile(file_path):
            print("File not found. Please enter a valid file path.")
            continue
        
        with open(file_path, 'r') as file:
            code = file.read()
        
        print("Analyzing the provided Lua code for vulnerabilities:")
        analyze_return(code)
        analyze_overflow_and_return(code)
        analyze_reentrancy(code)
        check_private_key_exposure(code)
        analyze_floating_pragma(code)

if __name__ == "__main__":
    main()
