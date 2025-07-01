#!/usr/bin/env python3
"""
Simple Calculator Module
A basic calculator with arithmetic operations and enhanced features
"""

import logging
from typing import List, Union

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Calculator:
    """A simple calculator class with enhanced error handling and features"""
    
    def __init__(self):
        """Initialize calculator"""
        self.history: List[str] = []
        logger.info("Calculator initialized")
    
    def add(self, a: Union[int, float], b: Union[int, float]) -> Union[int, float]:
        """
        Add two numbers
        
        Args:
            a: First number
            b: Second number
            
        Returns:
            Sum of a and b
        """
        if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
            raise TypeError("Arguments must be numbers")
            
        result = a + b
        operation = f"{a} + {b} = {result}"
        self.history.append(operation)
        logger.debug(f"Addition performed: {operation}")
        return result
    
    def subtract(self, a: Union[int, float], b: Union[int, float]) -> Union[int, float]:
        """
        Subtract b from a
        
        Args:
            a: First number
            b: Second number
            
        Returns:
            Difference of a and b
        """
        if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
            raise TypeError("Arguments must be numbers")
            
        result = a - b
        operation = f"{a} - {b} = {result}"
        self.history.append(operation)
        logger.debug(f"Subtraction performed: {operation}")
        return result
    
    def multiply(self, a: Union[int, float], b: Union[int, float]) -> Union[int, float]:
        """
        Multiply two numbers
        
        Args:
            a: First number
            b: Second number
            
        Returns:
            Product of a and b
        """
        if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
            raise TypeError("Arguments must be numbers")
            
        result = a * b
        operation = f"{a} * {b} = {result}"
        self.history.append(operation)
        logger.debug(f"Multiplication performed: {operation}")
        return result
    
    def divide(self, a: Union[int, float], b: Union[int, float]) -> float:
        """
        Divide a by b
        
        Args:
            a: Dividend
            b: Divisor
            
        Returns:
            Quotient of a and b
            
        Raises:
            ValueError: If b is zero
            TypeError: If arguments are not numbers
        """
        if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
            raise TypeError("Arguments must be numbers")
            
        if b == 0:
            logger.error("Attempted division by zero")
            raise ValueError("Cannot divide by zero")
            
        result = a / b
        operation = f"{a} / {b} = {result}"
        self.history.append(operation)
        logger.debug(f"Division performed: {operation}")
        return result
    
    def power(self, base: Union[int, float], exponent: Union[int, float]) -> Union[int, float]:
        """
        Calculate base raised to the power of exponent
        
        Args:
            base: Base number
            exponent: Exponent
            
        Returns:
            base^exponent
        """
        if not isinstance(base, (int, float)) or not isinstance(exponent, (int, float)):
            raise TypeError("Arguments must be numbers")
            
        result = base ** exponent
        operation = f"{base} ^ {exponent} = {result}"
        self.history.append(operation)
        logger.debug(f"Power operation performed: {operation}")
        return result
    
    def get_history(self) -> List[str]:
        """
        Get calculation history
        
        Returns:
            Copy of calculation history
        """
        return self.history.copy()
    
    def clear_history(self) -> None:
        """Clear calculation history"""
        self.history.clear()
        logger.info("Calculator history cleared")
    
    def get_last_result(self) -> str:
        """
        Get the last calculation result
        
        Returns:
            Last calculation or empty string if no history
        """
        return self.history[-1] if self.history else ""

def main():
    """Main function for testing"""
    calc = Calculator()
    
    print("Enhanced Calculator Test")
    print("========================")
    
    try:
        # Test basic operations with error handling
        print(f"5 + 3 = {calc.add(5, 3)}")
        print(f"10 - 4 = {calc.subtract(10, 4)}")
        print(f"6 * 7 = {calc.multiply(6, 7)}")
        print(f"15 / 3 = {calc.divide(15, 3)}")
        print(f"2 ^ 3 = {calc.power(2, 3)}")
        
        # Test new feature
        print(f"Last result: {calc.get_last_result()}")
        
        # Show history
        print("\nCalculation History:")
        for operation in calc.get_history():
            print(f"  {operation}")
            
    except (ValueError, TypeError) as e:
        logger.error(f"Calculation error: {e}")
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
