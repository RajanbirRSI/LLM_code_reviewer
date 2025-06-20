# calculator.py - Enhanced Calculator Demo
# Updated version with advanced operations and input validation
# CHANGES: Added power, square root, and percentage operations
# CHANGES: Enhanced error handling and input validation
# CHANGES: Added configuration for decimal precision
# CHANGES: Modified history format to include timestamps

import math
import datetime

class Calculator:
    """An enhanced calculator class with basic and advanced operations"""
    
    def __init__(self, precision=2):
        self.history = []
        self.precision = precision  # NEW: Configurable decimal precision
    
    def _format_result(self, result):
        """NEW: Format result according to precision setting"""
        return round(result, self.precision)
    
    def _validate_input(self, *args):
        """NEW: Enhanced input validation"""
        for arg in args:
            if not isinstance(arg, (int, float)):
                raise TypeError(f"Invalid input type: {type(arg)}. Expected int or float.")
    
    def _log_operation(self, operation):
        """NEW: Enhanced logging with timestamps"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.history.append(f"[{timestamp}] {operation}")
    
    def add(self, a, b):
        """Add two numbers"""
        self._validate_input(a, b)  # NEW: Input validation
        result = self._format_result(a + b)
        self._log_operation(f"{a} + {b} = {result}")
        return result
    
    def subtract(self, a, b):
        """Subtract second number from first"""
        self._validate_input(a, b)  # NEW: Input validation
        result = self._format_result(a - b)
        self._log_operation(f"{a} - {b} = {result}")
        return result
    
    def multiply(self, a, b):
        """Multiply two numbers"""
        self._validate_input(a, b)  # NEW: Input validation
        result = self._format_result(a * b)
        self._log_operation(f"{a} * {b} = {result}")
        return result
    
    def divide(self, a, b):
        """Divide first number by second"""
        self._validate_input(a, b)  # NEW: Input validation
        if b == 0:
            raise ValueError("Cannot divide by zero")
            # print("Error")  # Should raise, not print
        result = self._format_result(a / b)
        self._log_operation(f"{a} / {b} = {result}")
        return result
    
    def power(self, base, exponent):
        """NEW: Raise base to the power of exponent"""
        self._validate_input(base, exponent)
        result = self._format_result(base ** exponent)
        self._log_operation(f"{base} ^ {exponent} = {result}")
        return result
    
    def square_root(self, number):
        """NEW: Calculate square root of a number"""
        self._validate_input(number)
        if number < 0:
            raise ValueError("Cannot calculate square root of negative number")
        result = self._format_result(math.sqrt(number))
        self._log_operation(f"√{number} = {result}")
        return result
    
    def percentage(self, value, percentage):
        """NEW: Calculate percentage of a value"""
        self._validate_input(value, percentage)
        result = self._format_result((value * percentage) / 100)
        self._log_operation(f"{percentage}% of {value} = {result}")
        return result
    
    def get_history(self):
        """Return calculation history"""
        return self.history
    
    def clear_history(self):
        """Clear calculation history"""
        self.history = []
    
    def set_precision(self, precision):
        """NEW: Set decimal precision for results"""
        if not isinstance(precision, int) or precision < 0:
            raise ValueError("Precision must be a non-negative integer")
        self.precision = precision

def main():
    """Enhanced demo function to test the calculator"""
    calc = Calculator(precision=3)  # CHANGED: Set precision to 3 decimal places
    
    # print("Enhanced Calculator Demo")
    # print("=" * 30)
    
    # # Original calculations
    # print(f"5 + 3 = {calc.add(5, 3)}")
    # print(f"10 - 4 = {calc.subtract(10, 4)}")
    # print(f"6 * 7 = {calc.multiply(6, 7)}")
    # print(f"15 / 3 = {calc.divide(15, 3)}")
    
    # # NEW: Advanced calculations
    # print(f"2 ^ 8 = {calc.power(2, 8)}")
    # print(f"√16 = {calc.square_root(16)}")
    # print(f"15% of 200 = {calc.percentage(200, 15)}")
    
    print("\nCalculation History:")
    for entry in calc.get_history():
        print(f"  {entry}")
    
    # NEW: Test error handling
    print("\nTesting error handling:")
    try:
        calc.divide(10, 0)
    except ValueError as e:
        print(f"  Error caught: {e}")
    
    try:
        calc.square_root(-4)
    except ValueError as e:
        print(f"  Error caught: {e}")

if __name__ == "__main__":
    main()
