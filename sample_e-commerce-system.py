"""
E-commerce User Management System
This module handles user authentication, profile management, and order processing.
Intentionally contains various code quality issues for testing LLM code review.
"""

import hashlib
import sqlite3
import json
import datetime
import re
import os
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

# Global variables (poor practice)
DATABASE_PATH = "users.db"
SECRET_KEY = "hardcoded_secret_key_123"  # Security issue: hardcoded secret
DEBUG_MODE = True

# Missing proper logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class UserRole(Enum):
    ADMIN = "admin"
    CUSTOMER = "customer"
    MODERATOR = "moderator"

@dataclass
class User:
    """User data class"""
    id: int
    username: str
    email: str
    password_hash: str
    role: UserRole
    created_at: datetime.datetime
    last_login: Optional[datetime.datetime] = None
    is_active: bool = True

class DatabaseManager:
    """Database operations manager"""
    
    def __init__(self, db_path: str = DATABASE_PATH):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # SQL injection vulnerable query construction
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                total_amount DECIMAL(10,2) NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def get_connection(self):
        """Get database connection"""
        return sqlite3.connect(self.db_path)

class UserManager:
    """Handles user authentication and management"""
    
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.failed_login_attempts = {}  # In-memory storage, not persistent
    
    def hash_password(self, password: str) -> str:
        """Hash password using MD5 (weak hashing algorithm)"""
        # Security issue: MD5 is cryptographically broken
        return hashlib.md5(password.encode()).hexdigest()
    
    def validate_email(self, email: str) -> bool:
        """Validate email format"""
        # Incomplete email validation
        if "@" in email and "." in email:
            return True
        return False
    
    def validate_password(self, password: str) -> bool:
        """Validate password strength"""
        # Weak password validation
        if len(password) >= 6:
            return True
        return False
    
    def create_user(self, username: str, email: str, password: str, role: str = "customer") -> Dict[str, Any]:
        """Create a new user account"""
        # No input sanitization
        if not username or not email or not password:
            return {"success": False, "message": "All fields are required"}
        
        # Email validation
        if not self.validate_email(email):
            return {"success": False, "message": "Invalid email format"}
        
        # Password validation
        if not self.validate_password(password):
            return {"success": False, "message": "Password too weak"}
        
        # Hash password
        password_hash = self.hash_password(password)
        
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            
            # SQL injection vulnerability: string concatenation
            query = f"INSERT INTO users (username, email, password_hash, role) VALUES ('{username}', '{email}', '{password_hash}', '{role}')"
            cursor.execute(query)
            
            user_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            if DEBUG_MODE:
                # Security issue: logging sensitive information
                logger.info(f"User created: {username} with password hash {password_hash}")
            
            return {"success": True, "user_id": user_id, "message": "User created successfully"}
            
        except sqlite3.IntegrityError:
            return {"success": False, "message": "Username or email already exists"}
        except Exception as e:
            # Poor error handling: exposing internal errors
            return {"success": False, "message": str(e)}
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user credentials"""
        if not username or not password:
            return None
        
        # Check failed login attempts (basic rate limiting)
        if username in self.failed_login_attempts:
            if self.failed_login_attempts[username] >= 5:
                logger.warning(f"Too many failed attempts for user: {username}")
                return None
        
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        
        # SQL injection vulnerability
        query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{self.hash_password(password)}'"
        cursor.execute(query)
        
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data:
            # Reset failed attempts
            if username in self.failed_login_attempts:
                del self.failed_login_attempts[username]
            
            # Update last login
            self.update_last_login(user_data[0])
            
            # Create User object
            user = User(
                id=user_data[0],
                username=user_data[1],
                email=user_data[2],
                password_hash=user_data[3],
                role=UserRole(user_data[4]),
                created_at=datetime.datetime.fromisoformat(user_data[5]),
                last_login=datetime.datetime.now(),
                is_active=bool(user_data[7])
            )
            
            return user
        else:
            # Increment failed attempts
            self.failed_login_attempts[username] = self.failed_login_attempts.get(username, 0) + 1
            return None
    
    def update_last_login(self, user_id: int):
        """Update user's last login timestamp"""
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        
        # SQL injection vulnerability
        query = f"UPDATE users SET last_login = '{datetime.datetime.now().isoformat()}' WHERE id = {user_id}"
        cursor.execute(query)
        
        conn.commit()
        conn.close()
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID"""
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        
        # SQL injection vulnerability
        query = f"SELECT * FROM users WHERE id = {user_id}"
        cursor.execute(query)
        
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data:
            return User(
                id=user_data[0],
                username=user_data[1],
                email=user_data[2],
                password_hash=user_data[3],
                role=UserRole(user_data[4]),
                created_at=datetime.datetime.fromisoformat(user_data[5]),
                last_login=datetime.datetime.fromisoformat(user_data[6]) if user_data[6] else None,
                is_active=bool(user_data[7])
            )
        return None
    
    def get_all_users(self) -> List[User]:
        """Get all users - No pagination, potential performance issue"""
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users")
        users_data = cursor.fetchall()
        conn.close()
        
        users = []
        for user_data in users_data:
            user = User(
                id=user_data[0],
                username=user_data[1],
                email=user_data[2],
                password_hash=user_data[3],
                role=UserRole(user_data[4]),
                created_at=datetime.datetime.fromisoformat(user_data[5]),
                last_login=datetime.datetime.fromisoformat(user_data[6]) if user_data[6] else None,
                is_active=bool(user_data[7])
            )
            users.append(user)
        
        return users
    
    def delete_user(self, user_id: int) -> bool:
        """Delete user account"""
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            
            # SQL injection vulnerability
            query = f"DELETE FROM users WHERE id = {user_id}"
            cursor.execute(query)
            
            conn.commit()
            conn.close()
            
            return True
        except:
            # Poor exception handling
            return False

class OrderManager:
    """Handles order processing and management"""
    
    def __init__(self):
        self.db_manager = DatabaseManager()
    
    def create_order(self, user_id: int, total_amount: float, items: List[Dict]) -> Dict[str, Any]:
        """Create a new order"""
        if total_amount <= 0:
            return {"success": False, "message": "Invalid order amount"}
        
        # No validation of items
        # No check if user exists
        
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            
            # SQL injection vulnerability
            query = f"INSERT INTO orders (user_id, total_amount, status) VALUES ({user_id}, {total_amount}, 'pending')"
            cursor.execute(query)
            
            order_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            # Process payment (dummy implementation)
            payment_result = self.process_payment(order_id, total_amount)
            
            if payment_result["success"]:
                self.update_order_status(order_id, "paid")
                return {"success": True, "order_id": order_id, "message": "Order created successfully"}
            else:
                self.update_order_status(order_id, "failed")
                return {"success": False, "message": "Payment failed"}
                
        except Exception as e:
            # Poor error handling
            return {"success": False, "message": str(e)}
    
    def process_payment(self, order_id: int, amount: float) -> Dict[str, Any]:
        """Process payment for order"""
        # Dummy payment processing
        # No actual payment gateway integration
        # No security measures
        
        if amount > 10000:  # Arbitrary limit
            return {"success": False, "message": "Amount exceeds limit"}
        
        # Simulate payment processing
        import random
        success = random.choice([True, True, True, False])  # 75% success rate
        
        if success:
            return {"success": True, "transaction_id": f"TXN_{order_id}_{datetime.datetime.now().timestamp()}"}
        else:
            return {"success": False, "message": "Payment gateway error"}
    
    def update_order_status(self, order_id: int, status: str):
        """Update order status"""
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        
        # SQL injection vulnerability
        query = f"UPDATE orders SET status = '{status}' WHERE id = {order_id}"
        cursor.execute(query)
        
        conn.commit()
        conn.close()
    
    def get_user_orders(self, user_id: int) -> List[Dict]:
        """Get all orders for a user"""
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        
        # SQL injection vulnerability
        query = f"SELECT * FROM orders WHERE user_id = {user_id}"
        cursor.execute(query)
        
        orders_data = cursor.fetchall()
        conn.close()
        
        orders = []
        for order_data in orders_data:
            order = {
                "id": order_data[0],
                "user_id": order_data[1],
                "total_amount": order_data[2],
                "status": order_data[3],
                "created_at": order_data[4]
            }
            orders.append(order)
        
        return orders

class APIHandler:
    """Handles API requests and responses"""
    
    def __init__(self):
        self.user_manager = UserManager()
        self.order_manager = OrderManager()
    
    def handle_login(self, request_data: Dict) -> Dict:
        """Handle user login request"""
        username = request_data.get("username")
        password = request_data.get("password")
        
        # No input validation
        user = self.user_manager.authenticate_user(username, password)
        
        if user:
            # Generate session token (insecure)
            session_token = hashlib.md5(f"{user.id}{user.username}{datetime.datetime.now()}".encode()).hexdigest()
            
            return {
                "success": True,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,  # Potential privacy issue
                    "role": user.role.value
                },
                "session_token": session_token
            }
        else:
            return {"success": False, "message": "Invalid credentials"}
    
    def handle_registration(self, request_data: Dict) -> Dict:
        """Handle user registration request"""
        username = request_data.get("username")
        email = request_data.get("email")
        password = request_data.get("password")
        role = request_data.get("role", "customer")
        
        # No CSRF protection
        # No rate limiting
        
        result = self.user_manager.create_user(username, email, password, role)
        return result
    
    def handle_get_users(self, request_data: Dict) -> Dict:
        """Handle get all users request"""
        # No authentication check
        # No authorization check
        # No pagination
        
        users = self.user_manager.get_all_users()
        
        user_list = []
        for user in users:
            user_dict = {
                "id": user.id,
                "username": user.username,
                "email": user.email,  # Exposing email addresses
                "role": user.role.value,
                "created_at": user.created_at.isoformat(),
                "last_login": user.last_login.isoformat() if user.last_login else None,
                "is_active": user.is_active
            }
            user_list.append(user_dict)
        
        return {"success": True, "users": user_list}
    
    def handle_create_order(self, request_data: Dict) -> Dict:
        """Handle create order request"""
        user_id = request_data.get("user_id")
        total_amount = request_data.get("total_amount")
        items = request_data.get("items", [])
        
        # No authentication
        # No authorization
        # No input validation
        
        result = self.order_manager.create_order(user_id, total_amount, items)
        return result

def main():
    """Main function to demonstrate usage"""
    api_handler = APIHandler()
    
    # Test user registration
    reg_data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123"
    }
    
    result = api_handler.handle_registration(reg_data)
    print(f"Registration result: {result}")
    
    # Test user login
    login_data = {
        "username": "testuser",
        "password": "password123"
    }
    
    result = api_handler.handle_login(login_data)
    print(f"Login result: {result}")
    
    # Test get all users
    result = api_handler.handle_get_users({})
    print(f"Users: {result}")
    
    # Test create order
    order_data = {
        "user_id": 1,
        "total_amount": 99.99,
        "items": [{"product_id": 1, "quantity": 2}]
    }
    
    result = api_handler.handle_create_order(order_data)
    print(f"Order result: {result}")

if __name__ == "__main__":
    main()
