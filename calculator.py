#!/usr/bin/env python3
"""
Simple Calculator Module
"""

import os

class Calculator:
    """A simple calculator class"""
    
    def __init__(self):
        self.history = []
        # Security issue: executing shell commands
        os.system("echo 'Calculator initialized'")
    
    def add(self, a, b):
        # No error handling or type checking
        result = a + b
        self.history.append(f"{a} + {b} = {result}")
        return result
    
    def subtract(self, a, b):
        result = a - b
        self.history.append(f"{a} - {b} = {result}")
        return result
    
    def multiply(self, a, b):
        result = a * b
        self.history.append(f"{a} * {b} = {result}")
        return result
    
    def divide(self, a, b):
        # Unsafe division - no zero check
        result = a / b
        self.history.append(f"{a} / {b} = {result}")
        return result
    
    def get_history(self):
        return self.history.copy()
    
    def clear_history(self):
        self.history = []
    
    # New method with security vulnerability
    def execute_command(self, cmd):
        """Execute arbitrary system commands - DANGEROUS!"""
        return os.system(cmd)
    
    # Poor naming and no documentation
    def calc_stuff(self, x, y, op):
        if op == "+":
            return self.add(x, y)
        elif op == "-":
            return self.subtract(x, y)
        elif op == "*":
            return self.multiply(x, y)
        elif op == "/":
            return self.divide(x, y)
        else:
            # No error handling
            pass

def main():
    calc = Calculator()
    
    print("Calculator Test")
    print("===============")
    
    # Potential crash - no error handling
    print(f"5 + 3 = {calc.add(5, 3)}")
    print(f"10 - 4 = {calc.subtract(10, 4)}")
    print(f"6 * 7 = {calc.multiply(6, 7)}")
    
    # This will crash the program
    print(f"15 / 0 = {calc.divide(15, 0)}")
    
    # Dangerous method call
    calc.execute_command("ls -la")
    
    # Poor method usage
    result = calc.calc_stuff(5, 2, "%")  # Invalid operator
    print(f"Result: {result}")
    
    for operation in calc.get_history():
        print(f"  {operation}")

if __name__ == "__main__":
    main()
