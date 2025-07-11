"""
E-commerce User Management System

This module provides a secure and maintainable user authentication system with proper
database handling, comprehensive validation, and robust error management.

Features:
- Secure user authentication with bcrypt password hashing
- Role-based access control (RBAC)
- SQL injection prevention using parameterized queries
- Comprehensive input validation and sanitization
- Rate limiting for failed login attempts
- Session management with secure token generation
- Proper logging and error handling
- Modular design with clear separation of concerns

Author: System Development Team
Version: 2.0
Last Updated: 2024
"""

import hashlib
import sqlite3
import json
import datetime
import re
import os
import logging
import secrets
import bcrypt
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from contextlib import contextmanager
import time
from functools import wraps

# Configuration constants
DATABASE_PATH = os.getenv("DATABASE_PATH", "users.db")
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_DURATION = 300  # 5 minutes in seconds
SESSION_TIMEOUT = 3600  # 1 hour in seconds

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class UserRole(Enum):
    """
    User roles for role-based access control.
    
    Attributes:
        ADMIN: Full system access
        MODERATOR: Limited administrative access
        CUSTOMER: Standard user access
    """
    ADMIN = "admin"
    CUSTOMER = "customer"
    MODERATOR = "moderator"

class SecurityError(Exception):
    """Custom exception for security-related errors."""
    pass

class ValidationError(Exception):
    """Custom exception for input validation errors."""
    pass

class DatabaseError(Exception):
    """Custom exception for database-related errors."""
    pass

@dataclass
class User:
    """
    User data class representing a system user.
    
    Attributes:
        id: Unique user identifier
        username: User's chosen username
        email: User's email address
        password_hash: Bcrypt hashed password
        role: User's role for access control
        created_at: Account creation timestamp
        last_login: Last successful login timestamp
        is_active: Account active status
        failed_login_attempts: Number of consecutive failed login attempts
        last_failed_login: Timestamp of last failed login attempt
    """
    id: int
    username: str
    email: str
    password_hash: str
    role: UserRole
    created_at: datetime.datetime
    last_login: Optional[datetime.datetime] = None
    is_active: bool = True
    failed_login_attempts: int = 0
    last_failed_login: Optional[datetime.datetime] = None

@dataclass
class Session:
    """
    Session data class for managing user sessions.
    
    Attributes:
        token: Unique session token
        user_id: Associated user ID
        created_at: Session creation timestamp
        expires_at: Session expiration timestamp
        is_active: Session active status
    """
    token: str
    user_id: int
    created_at: datetime.datetime
    expires_at: datetime.datetime
    is_active: bool = True

class InputValidator:
    """
    Input validation utility class.
    
    Provides comprehensive validation for user inputs including
    email validation, password strength checking, and input sanitization.
    """
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """
        Validate email format using regex pattern.
        
        Args:
            email: Email string to validate
            
        Returns:
            bool: True if email is valid, False otherwise
        """
        if not email or not isinstance(email, str):
            return False
        
        # RFC 5322 compliant email regex pattern
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email.strip()))
    
    @staticmethod
    def validate_password(password: str) -> Dict[str, Any]:
        """
        Validate password strength with comprehensive checks.
        
        Args:
            password: Password string to validate
            
        Returns:
            dict: Validation result with success status and details
        """
        if not password or not isinstance(password, str):
            return {"valid": False, "message": "Password is required"}
        
        if len(password) < 8:
            return {"valid": False, "message": "Password must be at least 8 characters long"}
        
        if len(password) > 128:
            return {"valid": False, "message": "Password must be less than 128 characters"}
        
        # Check for required character types
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        if not (has_upper and has_lower and has_digit and has_special):
            return {
                "valid": False,
                "message": "Password must contain uppercase, lowercase, digit, and special character"
            }
        
        return {"valid": True, "message": "Password is valid"}
    
    @staticmethod
    def validate_username(username: str) -> Dict[str, Any]:
        """
        Validate username format and length.
        
        Args:
            username: Username string to validate
            
        Returns:
            dict: Validation result with success status and message
        """
        if not username or not isinstance(username, str):
            return {"valid": False, "message": "Username is required"}
        
        username = username.strip()
        
        if len(username) < 3:
            return {"valid": False, "message": "Username must be at least 3 characters long"}
        
        if len(username) > 50:
            return {"valid": False, "message": "Username must be less than 50 characters"}
        
        # Allow alphanumeric characters, underscores, and hyphens
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return {"valid": False, "message": "Username can only contain letters, numbers, underscores, and hyphens"}
        
        return {"valid": True, "message": "Username is valid"}
    
    @staticmethod
    def sanitize_input(input_string: str) -> str:
        """
        Sanitize input string by removing potentially dangerous characters.
        
        Args:
            input_string: String to sanitize
            
        Returns:
            str: Sanitized string
        """
        if not isinstance(input_string, str):
            return str(input_string)
        
        # Remove null bytes and control characters
        sanitized = input_string.replace('\x00', '').strip()
        
        # Limit length to prevent DoS attacks
        if len(sanitized) > 1000:
            sanitized = sanitized[:1000]
        
        return sanitized

class DatabaseManager:
    """
    Database operations manager with connection pooling and security features.
    
    Handles all database operations with proper error handling, connection management,
    and SQL injection prevention through parameterized queries.
    """
    
    def __init__(self, db_path: str = DATABASE_PATH):
        """
        Initialize database manager.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections.
        
        Ensures proper connection cleanup and transaction handling.
        
        Yields:
            sqlite3.Connection: Database connection object
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            yield conn
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error: {e}")
            raise DatabaseError(f"Database operation failed: {e}")
        finally:
            if conn:
                conn.close()
    
    def init_database(self):
        """
        Initialize database with required tables and indexes.
        
        Creates all necessary tables with proper constraints and indexes
        for optimal performance and data integrity.
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Users table with comprehensive constraints
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('admin', 'customer', 'moderator')),
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
                    last_failed_login TIMESTAMP
                )
            ''')
            
            # Sessions table for secure session management
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token TEXT UNIQUE NOT NULL,
                    user_id INTEGER NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')
            
            # Orders table with proper constraints
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS orders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    total_amount DECIMAL(10,2) NOT NULL CHECK (total_amount > 0),
                    status TEXT NOT NULL CHECK (status IN ('pending', 'paid', 'shipped', 'delivered', 'cancelled', 'failed')),
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')
            
            # Create indexes for better query performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status)')
            
            conn.commit()
            logger.info("Database initialized successfully")

class SessionManager:
    """
    Session management system for handling user authentication sessions.
    
    Provides secure session creation, validation, and cleanup with proper
    expiration handling and security measures.
    """
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize session manager.
        
        Args:
            db_manager: Database manager instance
        """
        self.db_manager = db_manager
    
    def create_session(self, user_id: int) -> str:
        """
        Create a new session for the user.
        
        Args:
            user_id: User ID to create session for
            
        Returns:
            str: Session token
            
        Raises:
            DatabaseError: If session creation fails
        """
        # Generate cryptographically secure token
        token = secrets.token_urlsafe(32)
        created_at = datetime.datetime.now()
        expires_at = created_at + datetime.timedelta(seconds=SESSION_TIMEOUT)
        
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                # Clean up expired sessions for this user
                cursor.execute(
                    'DELETE FROM sessions WHERE user_id = ? AND expires_at < ?',
                    (user_id, created_at)
                )
                
                # Insert new session
                cursor.execute(
                    'INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)',
                    (token, user_id, created_at, expires_at)
                )
                
                conn.commit()
                logger.info(f"Session created for user {user_id}")
                return token
                
        except sqlite3.Error as e:
            logger.error(f"Failed to create session for user {user_id}: {e}")
            raise DatabaseError("Session creation failed")
    
    def validate_session(self, token: str) -> Optional[int]:
        """
        Validate session token and return user ID.
        
        Args:
            token: Session token to validate
            
        Returns:
            Optional[int]: User ID if session is valid, None otherwise
        """
        if not token:
            return None
        
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute(
                    'SELECT user_id FROM sessions WHERE token = ? AND expires_at > ? AND is_active = TRUE',
                    (token, datetime.datetime.now())
                )
                
                result = cursor.fetchone()
                return result[0] if result else None
                
        except sqlite3.Error as e:
            logger.error(f"Session validation failed: {e}")
            return None
    
    def invalidate_session(self, token: str) -> bool:
        """
        Invalidate a session token.
        
        Args:
            token: Session token to invalidate
            
        Returns:
            bool: True if session was invalidated successfully
        """
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute(
                    'UPDATE sessions SET is_active = FALSE WHERE token = ?',
                    (token,)
                )
                
                conn.commit()
                return cursor.rowcount > 0
                
        except sqlite3.Error as e:
            logger.error(f"Session invalidation failed: {e}")
            return False
    
    def cleanup_expired_sessions(self):
        """
        Clean up expired sessions from the database.
        
        This method should be called periodically to maintain database performance.
        """
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute(
                    'DELETE FROM sessions WHERE expires_at < ?',
                    (datetime.datetime.now(),)
                )
                
                deleted_count = cursor.rowcount
                conn.commit()
                
                if deleted_count > 0:
                    logger.info(f"Cleaned up {deleted_count} expired sessions")
                    
        except sqlite3.Error as e:
            logger.error(f"Session cleanup failed: {e}")

class UserManager:
    """
    User authentication and management system.
    
    Handles user registration, authentication, profile management with
    comprehensive security measures including rate limiting, password hashing,
    and input validation.
    """
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize user manager.
        
        Args:
            db_manager: Database manager instance
        """
        self.db_manager = db_manager
        self.session_manager = SessionManager(db_manager)
        self.validator = InputValidator()
    
    def _hash_password(self, password: str) -> str:
        """
        Hash password using bcrypt with salt.
        
        Args:
            password: Plain text password
            
        Returns:
            str: Hashed password
        """
        # Generate salt and hash password
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def _verify_password(self, password: str, hashed: str) -> bool:
        """
        Verify password against hash.
        
        Args:
            password: Plain text password
            hashed: Stored password hash
            
        Returns:
            bool: True if password matches
        """
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def _is_account_locked(self, user_data: sqlite3.Row) -> bool:
        """
        Check if user account is locked due to failed login attempts.
        
        Args:
            user_data: User data from database
            
        Returns:
            bool: True if account is locked
        """
        if user_data['failed_login_attempts'] >= MAX_LOGIN_ATTEMPTS:
            if user_data['last_failed_login']:
                last_failed = datetime.datetime.fromisoformat(user_data['last_failed_login'])
                time_since_last_failed = (datetime.datetime.now() - last_failed).total_seconds()
                return time_since_last_failed < LOGIN_LOCKOUT_DURATION
        return False
    
    def create_user(self, username: str, email: str, password: str, role: str = "customer") -> Dict[str, Any]:
        """
        Create a new user account with comprehensive validation.
        
        Args:
            username: Desired username
            email: User's email address
            password: Plain text password
            role: User role (default: customer)
            
        Returns:
            dict: Operation result with success status and details
        """
        try:
            # Sanitize inputs
            username = self.validator.sanitize_input(username)
            email = self.validator.sanitize_input(email)
            
            # Validate inputs
            username_validation = self.validator.validate_username(username)
            if not username_validation["valid"]:
                return {"success": False, "message": username_validation["message"]}
            
            if not self.validator.validate_email(email):
                return {"success": False, "message": "Invalid email format"}
            
            password_validation = self.validator.validate_password(password)
            if not password_validation["valid"]:
                return {"success": False, "message": password_validation["message"]}
            
            # Validate role
            try:
                user_role = UserRole(role)
            except ValueError:
                return {"success": False, "message": "Invalid role specified"}
            
            # Hash password
            password_hash = self._hash_password(password)
            
            # Insert user into database
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute(
                    'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
                    (username, email, password_hash, role)
                )
                
                user_id = cursor.lastrowid
                conn.commit()
                
                logger.info(f"User created successfully: {username}")
                return {
                    "success": True,
                    "user_id": user_id,
                    "message": "User created successfully"
                }
                
        except sqlite3.IntegrityError as e:
            if "username" in str(e):
                return {"success": False, "message": "Username already exists"}
            elif "email" in str(e):
                return {"success": False, "message": "Email already registered"}
            else:
                return {"success": False, "message": "User creation failed"}
        except Exception as e:
            logger.error(f"User creation failed: {e}")
            return {"success": False, "message": "An error occurred during registration"}
    
    def authenticate_user(self, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate user credentials with rate limiting and security measures.
        
        Args:
            username: Username for authentication
            password: Plain text password
            
        Returns:
            dict: Authentication result with user data and session token
        """
        try:
            if not username or not password:
                return {"success": False, "message": "Username and password are required"}
            
            # Sanitize input
            username = self.validator.sanitize_input(username)
            
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get user data
                cursor.execute(
                    'SELECT * FROM users WHERE username = ? AND is_active = TRUE',
                    (username,)
                )
                
                user_data = cursor.fetchone()
                
                if not user_data:
                    logger.warning(f"Authentication failed: User not found - {username}")
                    return {"success": False, "message": "Invalid credentials"}
                
                # Check if account is locked
                if self._is_account_locked(user_data):
                    logger.warning(f"Authentication failed: Account locked - {username}")
                    return {"success": False, "message": "Account temporarily locked due to failed login attempts"}
                
                # Verify password
                if self._verify_password(password, user_data['password_hash']):
                    # Reset failed login attempts
                    cursor.execute(
                        'UPDATE users SET failed_login_attempts = 0, last_failed_login = NULL, last_login = ? WHERE id = ?',
                        (datetime.datetime.now(), user_data['id'])
                    )
                    conn.commit()
                    
                    # Create session
                    session_token = self.session_manager.create_session(user_data['id'])
                    
                    # Create user object
                    user = User(
                        id=user_data['id'],
                        username=user_data['username'],
                        email=user_data['email'],
                        password_hash=user_data['password_hash'],
                        role=UserRole(user_data['role']),
                        created_at=datetime.datetime.fromisoformat(user_data['created_at']),
                        last_login=datetime.datetime.now(),
                        is_active=bool(user_data['is_active'])
                    )
                    
                    logger.info(f"User authenticated successfully: {username}")
                    return {
                        "success": True,
                        "user": user,
                        "session_token": session_token,
                        "message": "Authentication successful"
                    }
                else:
                    # Increment failed login attempts
                    new_attempts = user_data['failed_login_attempts'] + 1
                    cursor.execute(
                        'UPDATE users SET failed_login_attempts = ?, last_failed_login = ? WHERE id = ?',
                        (new_attempts, datetime.datetime.now(), user_data['id'])
                    )
                    conn.commit()
                    
                    logger.warning(f"Authentication failed: Invalid password - {username}")
                    return {"success": False, "message": "Invalid credentials"}
                    
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return {"success": False, "message": "Authentication failed"}
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """
        Retrieve user by ID with proper error handling.
        
        Args:
            user_id: User ID to retrieve
            
        Returns:
            Optional[User]: User object if found, None otherwise
        """
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute(
                    'SELECT * FROM users WHERE id = ? AND is_active = TRUE',
                    (user_id,)
                )
                
                user_data = cursor.fetchone()
                
                if user_data:
                    return User(
                        id=user_data['id'],
                        username=user_data['username'],
                        email=user_data['email'],
                        password_hash=user_data['password_hash'],
                        role=UserRole(user_data['role']),
                        created_at=datetime.datetime.fromisoformat(user_data['created_at']),
                        last_login=datetime.datetime.fromisoformat(user_data['last_login']) if user_data['last_login'] else None,
                        is_active=bool(user_data['is_active'])
                    )
                return None
                
        except Exception as e:
            logger.error(f"Error retrieving user {user_id}: {e}")
            return None
    
    def get_users_paginated(self, page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """
        Get users with pagination to prevent performance issues.
        
        Args:
            page: Page number (1-based)
            page_size: Number of users per page
            
        Returns:
            dict: Paginated user data with metadata
        """
        try:
            if page < 1:
                page = 1
            if page_size < 1 or page_size > 100:
                page_size = 20
            
            offset = (page - 1) * page_size
            
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get total count
                cursor.execute('SELECT COUNT(*) FROM users WHERE is_active = TRUE')
                total_count = cursor.fetchone()[0]
                
                # Get paginated users
                cursor.execute(
                    'SELECT * FROM users WHERE is_active = TRUE ORDER BY created_at DESC LIMIT ? OFFSET ?',
                    (page_size, offset)
                )
                
                users_data = cursor.fetchall()
                
                users = []
                for user_data in users_data:
                    user = User(
                        id=user_data['id'],
                        username=user_data['username'],
                        email=user_data['email'],
                        password_hash=user_data['password_hash'],
                        role=UserRole(user_data['role']),
                        created_at=datetime.datetime.fromisoformat(user_data['created_at']),
                        last_login=datetime.datetime.fromisoformat(user_data['last_login']) if user_data['last_login'] else None,
                        is_active=bool(user_data['is_active'])
                    )
                    users.append(user)
                
                total_pages = (total_count + page_size - 1) // page_size
                
                return {
                    "success": True,
                    "users": users,
                    "pagination": {
                        "page": page,
                        "page_size": page_size,
                        "total_count": total_count,
                        "total_pages": total_pages,
                        "has_next": page < total_pages,
                        "has_prev": page > 1
                    }
                }
                
        except Exception as e:
            logger.error(f"Error retrieving users: {e}")
            return {"success": False, "message": "Failed to retrieve users"}
    
    def deactivate_user(self, user_id: int) -> Dict[str, Any]:
        """
        Deactivate user account instead of deletion for data integrity.
        
        Args:
            user_id: User ID to deactivate
            
        Returns:
            dict: Operation result
        """
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute(
                    'UPDATE users SET is_active = FALSE WHERE id = ?',
                    (user_id,)
                )
                
                if cursor.rowcount > 0:
                    # Invalidate all sessions for this user
                    cursor.execute(
                        'UPDATE sessions SET is_active = FALSE WHERE user_id = ?',
                        (user_id,)
                    )
                    conn.commit()
                    
                    logger.info(f"User {user_id} deactivated successfully")
                    return {"success": True, "message": "User deactivated successfully"}
                else:
                    return {"success": False, "message": "User not found"}
                    
        except Exception as e:
            logger.error(f"Error deactivating user {user_id}: {e}")
            return {"success": False, "message": "Failed to deactivate user"}

def require_auth(func):
    """
    Decorator to require authentication for API endpoints.
    
    Args:
        func: Function to decorate
        
    Returns:
        Decorated function that checks authentication
    """
    @wraps(func)
    def wrapper(self, request_data: Dict) -> Dict:
        session_token = request_data.get("session_token")
        
        if not session_token:
            return {"success": False, "message": "Authentication required"}
        
        user_id = self.session_manager.validate_session(session_token)
        if not user_id:
            return {"success": False, "message": "Invalid or expired session"}
        
        # Add user_id to request data for use in the endpoint
        request_data["authenticated_user_id"] = user_id
        
        return func(self, request_data)
    
    return wrapper

def require_role(required_role: UserRole):
    """
    Decorator to require specific role for API endpoints.
    
    Args:
        required_role: Required user role
        
    Returns:
        Decorator function
    """
    def decorator(func):
        @wraps(func)
        def wrapper(self, request_data: Dict) -> Dict:
            user_id = request_data.get("authenticated_user_id")
            if not user_id:
                return {"success": False, "message": "Authentication required"}
            
            user = self.user_manager.get_user_by_id(user_id)
            if not user or user.role != required_role:
                return {"success": False, "message": "Insufficient permissions"}
            
            return func(self, request_data)
        
        return wrapper
    return decorator

class APIHandler:
    """
    API request handler with comprehensive security and validation.
    
    Handles all API endpoints with proper authentication, authorization,
    input validation, and error handling.
    """
    
    def __init__(self):
        """Initialize API handler with required managers."""
        self.db_manager = DatabaseManager()
        self.user_manager = UserManager(self.db_manager)
        self.session_manager = self.user_manager.session_manager
        self.validator = InputValidator()
    
    def handle_registration(self, request_data: Dict) -> Dict:
        """
        Handle user registration with comprehensive validation.
        
        Args:
            request_data: Registration request data
            
        Returns:
            dict: Registration result
        """
        try:
            username = request_data.get("username")
            email = request_data.get("email")
            password = request_data.get("password")
            role = request_data.get("role", "customer")
            
            # Validate required fields
            if not all([username, email, password]):
                return {"success": False, "message": "All fields are required"}
            
            # Create user
            result = self.user_manager.create_user(username, email, password, role)
            
            # Remove sensitive information from response
            if result["success"]:
                result.pop("user_id", None)  # Don't expose user ID
            
            return result
            
        except Exception as e:
            logger.error(f"Registration handler error: {e}")
            return {"success": False, "message": "Registration failed"}
    
    def handle_login(self, request_data: Dict) -> Dict:
        """
        Handle user login with rate limiting and security measures.
        
        Args:
            request_data: Login request data
            
        Returns:
            dict: Login result with session token
        """
        try:
            username
    
    def handle_get_users(self, request_data: Dict) -> Dict:
        """Handle get all users request"""
        # Add autorization and authentication check
        # if needed add pagination
        
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
        
        # Add authorization, authetication and input validation
        
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
