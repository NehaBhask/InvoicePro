from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
import pytesseract
from PIL import Image
import os
import sqlite3
import spacy
from datetime import datetime, timedelta
import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
import io
import base64
import re
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import numpy as np
import re
# Initialize Flask app
load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')
matplotlib.use('Agg')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Load spaCy NLP model
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    print("spaCy model 'en_core_web_sm' not found. Please install it using:")
    print("python -m spacy download en_core_web_sm")
    nlp = None

# Set path to Tesseract (change if installed elsewhere)
# Windows default path:
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
# For Linux/Mac, usually it's in PATH, so you can comment the line above

# Category configuration
CATEGORIES = {
    "Office Supplies": ["pen", "pencil", "paper", "notebook", "folder", "stapler", "envelope", "printer", "ink", "toner", "cartridge"],
    "Technology": ["laptop", "computer", "software", "hardware", "monitor", "keyboard", "mouse", "tablet", "phone", "mobile"],
    "Utilities": ["electricity", "water", "gas", "internet", "wifi", "broadband", "phone bill", "mobile bill"],
    "Travel": ["flight", "hotel", "taxi", "uber", "train", "bus", "transport", "travel", "accommodation"],
    "Meals & Entertainment": ["restaurant", "food", "meal", "dinner", "lunch", "breakfast", "cafe", "coffee", "entertainment"],
    "Professional Services": ["consulting", "legal", "accounting", "audit", "professional", "service", "fee"],
    "Marketing": ["advertising", "marketing", "promotion", "social media", "ads", "campaign"],
    "Rent": ["rent", "lease", "rental"],
    "Maintenance": ["repair", "maintenance", "fix", "service"],
    "Healthcare": ["medical", "health", "insurance", "clinic", "hospital"],
    "Education": ["training", "course", "education", "workshop", "seminar"],
    "Shipping": ["shipping", "delivery", "postage", "courier", "mail"],
    "Subscriptions": ["subscription", "membership", "license", "renewal"],
    "Other": []  # Default category
}

# Vendor to category mapping
VENDOR_CATEGORIES = {
    "amazon": "Office Supplies",
    "walmart": "Office Supplies", 
    "staples": "Office Supplies",
    "best buy": "Technology",
    "apple": "Technology",
    "microsoft": "Technology",
    "dell": "Technology",
    "hp": "Technology",
    "at&t": "Utilities",
    "verizon": "Utilities",
    "comcast": "Utilities",
    "marriott": "Travel",
    "hilton": "Travel",
    "uber": "Travel",
    "lyft": "Travel",
    "starbucks": "Meals & Entertainment",
    "mcdonald": "Meals & Entertainment",
    "kfc": "Meals & Entertainment",
    "subway": "Meals & Entertainment"
}

# ---------------- DATABASE FUNCTIONS ----------------
def init_db():
    """Initialize database with enhanced schema for monthly tracking"""
    conn = sqlite3.connect('expenses.db')
    c = conn.cursor()
    
    # ---------- USERS TABLE ----------
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')
    
    # ---------- EXPENSES TABLE (Main table) ----------
    c.execute('''CREATE TABLE IF NOT EXISTS expenses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    invoice_no TEXT,
                    date TEXT,
                    amount REAL,
                    category TEXT,
                    vendor TEXT,
                    description TEXT,
                    user_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    month_year TEXT GENERATED ALWAYS AS (strftime('%Y-%m', date)),
                    year INTEGER GENERATED ALWAYS AS (strftime('%Y', date)),
                    month INTEGER GENERATED ALWAYS AS (strftime('%m', date)),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )''')
    
    # ---------- MONTHLY BUDGETS TABLE ----------
    c.execute('''CREATE TABLE IF NOT EXISTS monthly_budgets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    month_year TEXT,
                    category TEXT,
                    budget_amount REAL DEFAULT 0,
                    actual_amount REAL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    UNIQUE(user_id, month_year, category)
                )''')
    
    # ---------- EXPENSE ALERTS TABLE ----------
    c.execute('''CREATE TABLE IF NOT EXISTS expense_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    alert_type TEXT,
                    message TEXT,
                    is_read BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )''')
    
    # Create default admin user if not exists
    admin_hash = generate_password_hash('admin123')
    try:
        c.execute("INSERT OR IGNORE INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                 ('admin', 'admin@invoiceapp.com', admin_hash))
    except Exception as e:
        print(f"Error creating admin user: {e}")
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

# ---------------- AUTHENTICATION DECORATOR ----------------
def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ---------------- AUTHENTICATION ROUTES ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    """User login route"""
    if 'user_id' in session:
        return redirect(url_for('upload_invoice'))
    
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template("login.html")
        
        conn = sqlite3.connect('expenses.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['email'] = user[2]
            flash('Login successful!', 'success')
            return redirect(url_for('upload_invoice'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration route"""
    if 'user_id' in session:
        return redirect(url_for('upload_invoice'))
    
    if request.method == "POST":
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([username, email, password, confirm_password]):
            flash('All fields are required', 'error')
            return render_template("register.html")
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template("register.html")
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template("register.html")
        
        if len(username) < 3:
            flash('Username must be at least 3 characters long', 'error')
            return render_template("register.html")
        
        password_hash = generate_password_hash(password)
        
        conn = sqlite3.connect('expenses.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                     (username, email, password_hash))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'error')
        except Exception as e:
            flash(f'Registration error: {str(e)}', 'error')
        finally:
            conn.close()
    
    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    """User logout route"""
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

# ---------------- INVOICE PROCESSING FUNCTIONS ----------------

import re
from datetime import datetime

def extract_invoice_number(text):
    """
    Enhanced invoice number extraction with multiple patterns
    """
    print("\n🔍 Extracting Invoice Number...")
    
    # Pattern priority list (most specific to least specific)
    patterns = [
        # Pattern 1: Receipt Number (highest priority for receipts)
        (r'Receipt\s*(?:Number|No\.?|#|Num|ID)?\s*[:\-]?\s*([A-Z0-9\-]+)', 'Receipt Number'),
        
        # Pattern 2: Invoice Number with various formats
        (r'Invoice\s*(?:Number|No\.?|#|Num|ID)?\s*[:\-/]?\s*([A-Z0-9\-/]+)', 'Invoice Number'),
        
        # Pattern 3: Invoice No/Date combined (like "Invoice No/Date: 509")
        (r'Invoice\s*No\s*/\s*Date\s*:\s*(\d+)', 'Invoice No/Date Combined'),
        
        # Pattern 4: Bill Number
        (r'Bill\s*(?:Number|No\.?|#|Num|ID)?\s*[:\-]?\s*([A-Z0-9\-]+)', 'Bill Number'),
        
        # Pattern 5: Transaction ID
        (r'Transaction\s*(?:ID|Number|No\.?)?\s*[:\-]?\s*([A-Z0-9\-]+)', 'Transaction ID'),
        
        # Pattern 6: Order Number
        (r'Order\s*(?:Number|No\.?|#|ID)?\s*[:\-]?\s*([A-Z0-9\-]+)', 'Order Number'),
        
        # Pattern 7: Reference Number
        (r'Ref(?:erence)?\s*(?:Number|No\.?|#)?\s*[:\-]?\s*([A-Z0-9\-]+)', 'Reference Number'),
        
        # Pattern 8: Document Number
        (r'Doc(?:ument)?\s*(?:Number|No\.?|#)?\s*[:\-]?\s*([A-Z0-9\-]+)', 'Document Number'),
        
        # Pattern 9: Simple INV prefix
        (r'\bINV[:\-]?([A-Z0-9\-]+)', 'INV Prefix'),
        
        # Pattern 10: Hash followed by alphanumeric
        (r'#\s*([A-Z0-9]{4,})', 'Hash Number'),
        
        # Pattern 11: Standalone long numeric code (8+ digits)
        (r'\b(\d{8,})\b', 'Long Numeric Code'),
        
        # Pattern 12: Standalone alphanumeric code (6+ chars with mix of letters and numbers)
        (r'\b([A-Z]{2,}[0-9]{4,}|[0-9]{4,}[A-Z]{2,})\b', 'Alphanumeric Code'),
    ]
    
    # Try each pattern in order
    for pattern, pattern_name in patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)
        
        for match in matches:
            invoice_num = match.group(1).strip()
            
            # Validate the extracted number
            if validate_invoice_number(invoice_num):
                print(f"✅ Found via {pattern_name}: {invoice_num}")
                return invoice_num
    
    print("⚠️ No invoice number found")
    return None


def validate_invoice_number(invoice_num):
    """
    Validate if the extracted string is likely a valid invoice number
    """
    if not invoice_num or len(invoice_num) < 2:
        return False
    
    # Remove common noise words
    noise_words = ['invoice', 'receipt', 'bill', 'total', 'date', 'amount', 
                   'customer', 'name', 'phone', 'email', 'address', 'street',
                   'road', 'payment', 'method', 'card', 'cash']
    if invoice_num.lower() in noise_words:
        return False
    
    # Filter out common vendor names that might be picked up
    vendor_names = ['apple', 'microsoft', 'amazon', 'walmart', 'google', 
                    'facebook', 'starbucks', 'mcdonalds', 'target', 'costco']
    if invoice_num.lower() in vendor_names:
        print(f"⚠️ Rejected '{invoice_num}' - matches vendor name")
        return False
    
    # Reject if it's just a word with no digits (likely a vendor name)
    has_digit = any(c.isdigit() for c in invoice_num)
    if not has_digit and len(invoice_num) <= 15:
        print(f"⚠️ Rejected '{invoice_num}' - no digits (likely vendor name)")
        return False
    
    # Must contain at least one digit OR be all uppercase with reasonable length and digits
    is_valid_format = has_digit or (invoice_num.isupper() and len(invoice_num) >= 3 and has_digit)
    
    # Length check (reasonable range)
    if len(invoice_num) > 50:
        return False
    
    return is_valid_format


def extract_date(text):
    """
    Enhanced date extraction with multiple patterns and formats
    Handles formats like: 01-12-2025, April 9/2025, 04:11 PM / 01-12-2025
    """
    print("\n📅 Extracting Date...")
    
    lines = text.split('\n')
    
    # Pattern priority list
    date_patterns = [
        # Pattern 0: Date with time and date separator (like "04:11 PM / 01-12-2025")
        (r'\d{1,2}:\d{2}\s*(?:AM|PM)?\s*/\s*(\d{1,2}[\-/\.]\d{1,2}[\-/\.]\d{2,4})', 'Time/Date Combined'),
        
        # Pattern 1: Explicit date labels
        (r'(?:Invoice\s*)?Date\s*[:\-]?\s*(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4})', 'Invoice Date Label'),
        (r'Bill\s*Date\s*[:\-]?\s*(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4})', 'Bill Date Label'),
        (r'Transaction\s*Date\s*[:\-]?\s*(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4})', 'Transaction Date Label'),
        (r'Purchase\s*Date\s*[:\-]?\s*(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4})', 'Purchase Date Label'),
        
        # Pattern 2: Date with month name and slash (like "April 9/2025")
        (r'((?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2}\s*/\s*\d{4})', 'Month Name/Year'),
        (r'((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s*/\s*\d{4})', 'Short Month/Year'),
        
        # Pattern 3: Date with month name (standard)
        (r'(\d{1,2}[\s\-/](?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[\s\-/]\d{2,4})', 'Month Name Format'),
        (r'((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[\s\-/]\d{1,2}[\s\,/]\d{2,4})', 'Month Name First'),
        
        # Pattern 4: ISO format YYYY-MM-DD
        (r'(\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2})', 'ISO Format'),
        
        # Pattern 5: Common formats DD-MM-YYYY or MM-DD-YYYY
        (r'(\d{1,2}[\-]\d{1,2}[\-]\d{4})', 'Dash Format'),
        (r'(\d{1,2}[\/]\d{1,2}[\/]\d{2,4})', 'Slash Format'),
        (r'(\d{1,2}[\.]\d{1,2}[\.]\d{2,4})', 'Dot Format'),
    ]
    
    # First pass: Look in first 20 lines with explicit labels
    for i, line in enumerate(lines[:20]):
        for pattern, pattern_name in date_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                date_str = match.group(1)
                parsed_date = parse_date_enhanced(date_str)
                if parsed_date:
                    print(f"✅ Found via {pattern_name} in line {i}: {date_str} → {parsed_date}")
                    return parsed_date
    
    # Second pass: All patterns across entire text
    for pattern, pattern_name in date_patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)
        
        for match in matches:
            date_str = match.group(1)
            parsed_date = parse_date_enhanced(date_str)
            if parsed_date:
                print(f"✅ Found via {pattern_name}: {date_str} → {parsed_date}")
                return parsed_date
    
    print("⚠️ No date found")
    return None


def parse_date_enhanced(date_str):
    """
    Enhanced date parsing with multiple format support
    Handles: DD-MM-YYYY, MM/DD/YYYY, April 9/2025, etc.
    """
    if not date_str:
        return None
    
    # Clean the date string
    date_str = date_str.strip()
    date_str = re.sub(r'^(date|invoice date|bill date)[:\s]*', '', date_str, flags=re.IGNORECASE).strip()
    
    # Special handling for "Month Day/Year" format (like "April 9/2025")
    month_slash_pattern = r'(January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s*/\s*(\d{4})'
    match = re.match(month_slash_pattern, date_str, re.IGNORECASE)
    if match:
        month_name, day, year = match.groups()
        month_map = {
            'jan': 1, 'january': 1,
            'feb': 2, 'february': 2,
            'mar': 3, 'march': 3,
            'apr': 4, 'april': 4,
            'may': 5,
            'jun': 6, 'june': 6,
            'jul': 7, 'july': 7,
            'aug': 8, 'august': 8,
            'sep': 9, 'september': 9,
            'oct': 10, 'october': 10,
            'nov': 11, 'november': 11,
            'dec': 12, 'december': 12
        }
        month_num = month_map.get(month_name.lower())
        if month_num and 1 <= int(day) <= 31:
            return f"{year}-{month_num:02d}-{int(day):02d}"
    
    # List of date formats to try
    date_formats = [
        # ISO formats
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%Y.%m.%d",
        
        # DD-MM-YYYY formats (common in India/Europe)
        "%d-%m-%Y",
        "%d/%m/%Y",
        "%d.%m.%Y",
        
        # MM-DD-YYYY formats (US)
        "%m-%d-%Y",
        "%m/%d/%Y",
        "%m.%d.%Y",
        
        # Two-digit year formats
        "%d-%m-%y",
        "%d/%m/%y",
        "%m-%d-%y",
        "%m/%d/%y",
        
        # Month name formats
        "%d %B %Y",
        "%d %b %Y",
        "%B %d, %Y",
        "%b %d, %Y",
        "%d-%B-%Y",
        "%d-%b-%Y",
        "%B %d %Y",
        "%b %d %Y",
        "%d %b, %Y",
        "%d %B, %Y",
    ]
    
    # Try each format
    for fmt in date_formats:
        try:
            parsed = datetime.strptime(date_str, fmt)
            
            # Validate the date is reasonable (between 2000 and 2030)
            if 2000 <= parsed.year <= 2030:
                return parsed.strftime("%Y-%m-%d")
        except ValueError:
            continue
    
    # Try regex-based parsing as fallback
    date_regex = r'(\d{1,2})[\-/\.](\d{1,2})[\-/\.](\d{2,4})'
    match = re.search(date_regex, date_str)
    
    if match:
        try:
            part1, part2, year = match.groups()
            part1, part2, year = int(part1), int(part2), int(year)
            
            # Convert 2-digit year to 4-digit
            if year < 100:
                year += 2000 if year < 50 else 1900
            
            # Determine if it's DD-MM-YYYY or MM-DD-YYYY based on values
            # Default to DD-MM-YYYY (common in India, Europe)
            if part1 > 12:  # Must be DD-MM-YYYY
                day, month = part1, part2
            elif part2 > 12:  # Must be MM-DD-YYYY
                month, day = part1, part2
            else:  # Ambiguous - check if dash is used (common for DD-MM-YYYY)
                if '-' in date_str:
                    day, month = part1, part2  # DD-MM-YYYY with dash
                else:
                    day, month = part1, part2  # Default to DD-MM-YYYY
            
            # Validate
            if 1 <= month <= 12 and 1 <= day <= 31 and 2000 <= year <= 2030:
                return f"{year:04d}-{month:02d}-{day:02d}"
        except (ValueError, IndexError):
            pass
    
    return None


def extract_vendor(text):
    """Extract vendor name from invoice text"""
    lines = text.split('\n')
    vendor_indicators = ["from:", "vendor:", "supplier:", "to:", "bill to:", "sold to:", "company:", "store:"]
    
    # First, check for explicit vendor indicators
    for i, line in enumerate(lines):
        line_lower = line.lower().strip()
        
        for indicator in vendor_indicators:
            if indicator in line_lower:
                vendor = line.split(':')[-1].strip()
                if vendor and len(vendor) > 2:
                    return vendor
        
        # Look for company indicators in first 5 lines
        if i < 5 and len(line.strip()) > 3:
            if any(word in line_lower for word in ['inc', 'ltd', 'corp', 'company', 'llc', 'store', 'shop']):
                return line.strip()
        
        # Look for all caps company names in first 3 lines
        if i < 3 and line.strip().isupper() and len(line.strip()) > 3:
            # Filter out common headers
            if not any(word in line_lower for word in ['invoice', 'receipt', 'bill', 'tax']):
                return line.strip()
    
    return "Unknown Vendor"


def categorize_invoice(text, vendor=None):
    """Categorize invoice based on text content and vendor"""
    text_lower = text.lower()
    
    # Vendor-based categorization
    VENDOR_CATEGORIES = {
        "apple": "Technology",
        "microsoft": "Technology",
        "dell": "Technology",
        "hp": "Technology",
        "best buy": "Technology",
        "amazon": "Office Supplies",
        "walmart": "Office Supplies",
        "staples": "Office Supplies",
        "starbucks": "Meals & Entertainment",
        "mcdonald": "Meals & Entertainment",
    }
    
    if vendor and vendor != "Unknown Vendor":
        vendor_lower = vendor.lower()
        for vendor_key, category in VENDOR_CATEGORIES.items():
            if vendor_key in vendor_lower:
                return category
    
    # Content-based categorization
    CATEGORIES = {
        "Technology": ["laptop", "computer", "software", "macbook", "iphone", "ipad", "tablet", "phone", "mobile", "tech", "electronics"],
        "Office Supplies": ["pen", "pencil", "paper", "notebook", "folder", "stapler", "envelope", "printer", "ink", "toner"],
        "Utilities": ["electricity", "water", "gas", "internet", "wifi", "broadband"],
        "Travel": ["flight", "hotel", "taxi", "uber", "train", "bus", "transport"],
        "Meals & Entertainment": ["restaurant", "food", "meal", "dinner", "lunch", "breakfast", "cafe", "coffee"],
        "Clothing": ["clothing", "shirt", "t-shirt", "pants", "dress", "apparel", "fashion"],
    }
    
    for category, keywords in CATEGORIES.items():
        for keyword in keywords:
            if keyword in text_lower:
                return category
    
    return "Other"


def generate_description(data, text):
    """Generate a meaningful description from extracted data"""
    description_parts = []
    
    if data["Vendor"] and data["Vendor"] != "Unknown Vendor":
        description_parts.append(data["Vendor"])
    
    lines = text.split('\n')
    for line in lines:
        line = line.strip()
        if (len(line) > 10 and 
            not line.startswith('$') and 
            not line.startswith('€') and
            not any(word in line.lower() for word in ['invoice', 'bill', 'date', 'total', 'amount', 'qty', 'quantity', 'receipt'])):
            description_parts.append(line)
            break
    
    if description_parts:
        return " - ".join(description_parts[:2])
    return "Invoice Purchase"


def extract_amount_enhanced(text):
    """Enhanced amount extraction supporting multiple currencies"""
    print(f"\n💰 DEBUG: Starting amount extraction from {len(text)} chars")
    
    # Pattern 1: Look for "Total Paid" pattern
    total_paid_patterns = [
        r'Total\s*Paid\s*[€$₹]?\s*[:]?\s*([\d,]+\.?\d*)',
        r'total\s*paid\s*[€$₹]?\s*[:]?\s*([\d,]+\.?\d*)',
    ]
    
    for pattern in total_paid_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            amount_str = match.group(1)
            print(f"✅ Found via 'Total Paid' pattern: {amount_str}")
            try:
                clean_amount = amount_str.replace(',', '').strip()
                amount = float(clean_amount)
                print(f"✅ Converted to: {amount}")
                return amount
            except:
                continue
    
    # Pattern 2: Look for any "Total" pattern
    total_patterns = [
        r'Total\s*[€$₹]?\s*[:]?\s*([\d,]+\.?\d*)',
        r'total\s*[€$₹]?\s*[:]?\s*([\d,]+\.?\d*)',
    ]
    
    for pattern in total_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            amount_str = match.group(1)
            print(f"✅ Found via 'Total' pattern: {amount_str}")
            try:
                clean_amount = amount_str.replace(',', '').strip()
                amount = float(clean_amount)
                print(f"✅ Converted to: {amount}")
                return amount
            except:
                continue
    
    # Pattern 3: Look for currency amounts (€, $, ₹)
    print("⚠️ Falling back to find largest currency amount")
    currency_amounts = re.findall(r'[€$₹]\s*([\d,]+\.?\d*)', text)
    
    if currency_amounts:
        print(f"Found currency amounts: {currency_amounts}")
        max_amount = 0.0
        for amount_str in currency_amounts:
            try:
                clean_amount = amount_str.replace(',', '').strip()
                amount = float(clean_amount)
                if amount > max_amount:
                    max_amount = amount
            except:
                continue
        
        if max_amount > 0:
            print(f"✅ Selected largest currency amount: {max_amount}")
            return max_amount
    
    # Pattern 4: Look for decimal numbers
    print("⚠️ Looking for any decimal numbers")
    decimal_numbers = re.findall(r'(\d+[,.]\d{2})\b', text)
    
    if decimal_numbers:
        print(f"Found decimal numbers: {decimal_numbers}")
        max_amount = 0.0
        for amount_str in decimal_numbers:
            try:
                clean_amount = amount_str.replace(',', '.').replace(' ', '')
                amount = float(clean_amount)
                if amount > max_amount and amount < 1000000:
                    max_amount = amount
            except:
                continue
        
        if max_amount > 0:
            print(f"✅ Selected largest decimal number: {max_amount}")
            return max_amount
    
    print("❌ No amount found, using 0.0")
    return 0.0


# Updated extract_invoice_data_ner function
def extract_invoice_data_ner(text):
    """
    Extract invoice data - IMPROVED VERSION
    """
    print("\n" + "="*50)
    print("EXTRACTING INVOICE DATA")
    print("="*50)
    
    data = {
        "Invoice Number": None, 
        "Date": None, 
        "Amount": 0.0,
        "Category": "Uncategorized",
        "Vendor": None,
        "Description": None
    }

    # Extract vendor
    data["Vendor"] = extract_vendor(text)
    print(f"Vendor: {data['Vendor']}")
    
    # Extract amount
    amount = extract_amount_enhanced(text)
    data["Amount"] = amount
    print(f"Amount extracted: {data['Amount']}")
    
    # Extract invoice number
    data["Invoice Number"] = extract_invoice_number(text)
    if not data["Invoice Number"]:
        data["Invoice Number"] = f"INV-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    print(f"Invoice Number: {data['Invoice Number']}")
    
    # Extract date
    data["Date"] = extract_date(text)
    if not data["Date"]:
        data["Date"] = datetime.now().strftime("%Y-%m-%d")
    print(f"Date: {data['Date']}")
    
    # Categorize
    data["Category"] = categorize_invoice(text, data["Vendor"])
    print(f"Category: {data['Category']}")
    
    # Generate description
    data["Description"] = generate_description(data, text)
    print(f"Description: {data['Description']}")
    
    print(f"Final Amount to store in DB: {data['Amount']}")
    print("="*50 + "\n")
    
    return data

# ---------------- MAIN APPLICATION ROUTES ----------------
@app.route("/")
@login_required
def index():
    """Redirect to upload invoice page"""
    return redirect(url_for('upload_invoice'))

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_invoice():
    """Upload and process invoice route"""
    if request.method == "POST":
        if 'file' not in request.files:
            flash('No file uploaded!', 'error')
            return render_template("upload.html")
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected!', 'error')
            return render_template("upload.html")
        
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'tiff', 'bmp', 'pdf'}
        file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        if file_ext not in allowed_extensions:
            flash('Invalid file type. Please upload an image file (PNG, JPG, JPEG, GIF, TIFF, BMP).', 'error')
            return render_template("upload.html")

        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
            
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)

        try:
            img = Image.open(filepath)
            text = pytesseract.image_to_string(img)
            print("OCR Extracted Text:", text)
            
            if not text.strip():
                flash('No text could be extracted from the image. Please try a clearer image.', 'error')
                return render_template("upload.html")
                
        except Exception as e:
            flash(f'Error processing image: {str(e)}', 'error')
            if os.path.exists(filepath):
                os.remove(filepath)
            return render_template("upload.html")

        data = extract_invoice_data_ner(text)
        print("Extracted Data:", data)

        conn = sqlite3.connect('expenses.db')
        c = conn.cursor()
        c.execute("""INSERT INTO expenses 
                    (invoice_no, date, amount, category, vendor, description, user_id) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                  (data["Invoice Number"], data["Date"], data["Amount"], 
                   data["Category"], data["Vendor"], data["Description"], 
                   session['user_id']))
        
        current_month = datetime.now().strftime("%Y-%m")
        c.execute("""
            UPDATE monthly_budgets 
            SET actual_amount = (
                SELECT COALESCE(SUM(amount), 0)
                FROM expenses 
                WHERE user_id = ? AND month_year = ? AND category = ?
            ),
            updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ? AND month_year = ? AND category = ?
        """, (session['user_id'], current_month, data["Category"], 
              session['user_id'], current_month, data["Category"]))
        
        c.execute("""
            SELECT budget_amount, actual_amount 
            FROM monthly_budgets 
            WHERE user_id = ? AND month_year = ? AND category = ?
        """, (session['user_id'], current_month, data["Category"]))
        
        budget_info = c.fetchone()
        if budget_info and budget_info[0] > 0 and budget_info[1] > budget_info[0]:
            c.execute("""
                INSERT INTO expense_alerts (user_id, alert_type, message)
                VALUES (?, ?, ?)
            """, (session['user_id'], 'budget_exceeded',
                 f'Budget exceeded for {data["Category"]} in {current_month}. '
                 f'Budget: ${budget_info[0]:.2f}, Actual: ${budget_info[1]:.2f}'))
        
        conn.commit()
        conn.close()

        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except Exception as e:
            print(f"Error removing file: {e}")

        flash('Invoice processed successfully!', 'success')
        return redirect(url_for('show_expenses'))
    
    return render_template("upload.html")

@app.route("/expenses")
@login_required
def show_expenses():
    """Display all expenses for the logged-in user"""
    conn = sqlite3.connect('expenses.db')
    c = conn.cursor()
    c.execute("SELECT * FROM expenses WHERE user_id = ? ORDER BY date DESC", (session['user_id'],))
    data = c.fetchall()
    conn.close()
    return render_template("expenses.html", expenses=data, categories=list(CATEGORIES.keys()))

@app.route("/insights")
@login_required
def insights():
    """Display spending insights and charts"""
    conn = sqlite3.connect('expenses.db')
    df = pd.read_sql_query("SELECT * FROM expenses WHERE user_id = ?", conn, params=(session['user_id'],))
    conn.close()

    if df.empty or len(df) == 0:
        return render_template("insights.html", no_data=True)

    df['date'] = pd.to_datetime(df['date'], errors='coerce')
    df['amount'] = pd.to_numeric(df['amount'], errors='coerce')
    df = df.dropna(subset=['date', 'amount'])
    
    if df.empty:
        return render_template("insights.html", no_data=True)

    plots = []
    
    # 1. Spending over time
    try:
        plt.figure(figsize=(10, 6))
        df_sorted = df.sort_values('date')
        spending_over_time = df_sorted.groupby('date')['amount'].sum()
        
        if len(spending_over_time) > 0:
            spending_over_time.plot(kind='line', marker='o', color='#3498db', linewidth=2, markersize=6)
            plt.title("Spending Over Time", fontsize=16, fontweight='bold', pad=20)
            plt.xlabel("Date", fontsize=12)
            plt.ylabel("Total Amount ($)", fontsize=12)
            plt.grid(True, alpha=0.3)
            plt.xticks(rotation=45)
            plt.tight_layout()
        else:
            plt.text(0.5, 0.5, 'No time series data available', 
                    ha='center', va='center', transform=plt.gca().transAxes, fontsize=12)
        
        img1 = io.BytesIO()
        plt.savefig(img1, format='png', dpi=100, bbox_inches='tight', facecolor='white')
        img1.seek(0)
        plot_url1 = base64.b64encode(img1.getvalue()).decode()
        plots.append(plot_url1)
        plt.close()
    except Exception as e:
        print(f"Error creating line chart: {e}")
        plots.append(None)

    # 2. Category-wise spending (Pie Chart)
    try:
        plt.figure(figsize=(8, 8))
        category_totals = df.groupby('category')['amount'].sum()
        
        if len(category_totals) > 0:
            colors = plt.cm.Set3(range(len(category_totals)))
            wedges, texts, autotexts = plt.pie(category_totals.values, 
                                              labels=category_totals.index, 
                                              autopct='%1.1f%%', 
                                              startangle=90, 
                                              colors=colors,
                                              shadow=True)
            plt.title("Category-wise Spending", fontsize=16, fontweight='bold', pad=20)
            
            for autotext in autotexts:
                autotext.set_color('black')
                autotext.set_fontweight('bold')
                autotext.set_fontsize(10)
        else:
            plt.text(0.5, 0.5, 'No category data available', 
                    ha='center', va='center', transform=plt.gca().transAxes, fontsize=12)
        
        plt.tight_layout()
        img2 = io.BytesIO()
        plt.savefig(img2, format='png', dpi=100, bbox_inches='tight', facecolor='white')
        img2.seek(0)
        plot_url2 = base64.b64encode(img2.getvalue()).decode()
        plots.append(plot_url2)
        plt.close()
    except Exception as e:
        print(f"Error creating pie chart: {e}")
        plots.append(None)

    # 3. Monthly spending summary
    try:
        plt.figure(figsize=(10, 6))
        df['month'] = df['date'].dt.to_period('M').astype(str)
        monthly_totals = df.groupby('month')['amount'].sum()
        
        if len(monthly_totals) > 0:
            monthly_totals.plot(kind='bar', color='#2ecc71', edgecolor='black', alpha=0.8)
            plt.title("Monthly Spending Summary", fontsize=16, fontweight='bold', pad=20)
            plt.xlabel("Month", fontsize=12)
            plt.ylabel("Total Amount ($)", fontsize=12)
            plt.xticks(rotation=45)
            plt.grid(True, alpha=0.3, axis='y')
            
            for i, v in enumerate(monthly_totals.values):
                plt.text(i, v + max(monthly_totals.values) * 0.01, 
                        f'${v:.2f}', ha='center', va='bottom', fontweight='bold')
        else:
            plt.text(0.5, 0.5, 'No monthly data available', 
                    ha='center', va='center', transform=plt.gca().transAxes, fontsize=12)
        
        plt.tight_layout()
        img3 = io.BytesIO()
        plt.savefig(img3, format='png', dpi=100, bbox_inches='tight', facecolor='white')
        img3.seek(0)
        plot_url3 = base64.b64encode(img3.getvalue()).decode()
        plots.append(plot_url3)
        plt.close()
    except Exception as e:
        print(f"Error creating bar chart: {e}")
        plots.append(None)

    return render_template("insights.html", 
                         plot1=plots[0] if len(plots) > 0 else None,
                         plot2=plots[1] if len(plots) > 1 else None,
                         plot3=plots[2] if len(plots) > 2 else None,
                         no_data=False)

# ---------------- MONTHLY EXPENSES ROUTES ----------------
@app.route("/monthly")
@login_required
def monthly_overview():
    """Monthly expenses overview dashboard"""
    current_month = datetime.now().strftime("%Y-%m")
    
    conn = sqlite3.connect('expenses.db')
    c = conn.cursor()
    
    c.execute("""
        SELECT month_year, SUM(amount) as total, COUNT(*) as count
        FROM expenses 
        WHERE user_id = ? 
        GROUP BY month_year 
        ORDER BY month_year DESC
        LIMIT 12
    """, (session['user_id'],))
    monthly_data = c.fetchall()
    
    c.execute("""
        SELECT category, SUM(amount) as total
        FROM expenses 
        WHERE user_id = ? AND month_year = ?
        GROUP BY category
        ORDER BY total DESC
    """, (session['user_id'], current_month))
    current_month_categories = c.fetchall()
    
    c.execute("""
        SELECT category, budget_amount, actual_amount
        FROM monthly_budgets 
        WHERE user_id = ? AND month_year = ?
    """, (session['user_id'], current_month))
    budget_data = c.fetchall()
    
    budgets = {}
    for category, budget, actual in budget_data:
        budgets[category] = {
            'budget': budget if budget else 0,
            'actual': actual if actual else 0,
            'remaining': (budget - actual) if budget else None,
            'percentage': (actual / budget * 100) if budget and budget > 0 else None
        }
    
    c.execute("SELECT COUNT(*) FROM expense_alerts WHERE user_id = ? AND is_read = 0", (session['user_id'],))
    alerts_count = c.fetchone()[0]
    
    conn.close()
    
    return render_template("monthly.html",
                         current_month=current_month,
                         monthly_data=monthly_data,
                         current_month_categories=current_month_categories,
                         budgets=budgets,
                         categories=list(CATEGORIES.keys()),
                         alerts_count=alerts_count)

@app.route("/monthly/<month_year>")
@login_required
def monthly_detail(month_year):
    """Detailed view for a specific month"""
    conn = sqlite3.connect('expenses.db')
    c = conn.cursor()
    
    c.execute("""
        SELECT 
            COUNT(*) as count,
            SUM(amount) as total,
            AVG(amount) as average,
            MIN(date) as first_date,
            MAX(date) as last_date
        FROM expenses 
        WHERE user_id = ? AND month_year = ?
    """, (session['user_id'], month_year))
    
    month_stats = c.fetchone()
    
    c.execute("""
        SELECT * FROM expenses 
        WHERE user_id = ? AND month_year = ?
        ORDER BY date DESC
    """, (session['user_id'], month_year))
    
    expenses = c.fetchall()
    
    c.execute("""
        SELECT category, SUM(amount) as total, COUNT(*) as count
        FROM expenses 
        WHERE user_id = ? AND month_year = ?
        GROUP BY category
        ORDER BY total DESC
    """, (session['user_id'], month_year))
    
    category_breakdown = c.fetchall()
    
    c.execute("""
        SELECT date, SUM(amount) as daily_total
        FROM expenses 
        WHERE user_id = ? AND month_year = ?
        GROUP BY date
        ORDER BY date
    """, (session['user_id'], month_year))
    
    daily_spending = c.fetchall()
    
    conn.close()
    
    return render_template("monthly_detail.html",
                         month_year=month_year,
                         month_stats=month_stats,
                         expenses=expenses,
                         category_breakdown=category_breakdown,
                         daily_spending=daily_spending)

@app.route("/set_budget", methods=["POST"])
@login_required
def set_budget():
    """Set or update monthly budget for categories"""
    month_year = request.form.get('month_year')
    category = request.form.get('category')
    budget_amount = request.form.get('budget_amount')
    
    if not all([month_year, category, budget_amount]):
        return jsonify({"success": False, "message": "All fields are required"})
    
    try:
        budget_amount = float(budget_amount)
        
        conn = sqlite3.connect('expenses.db')
        c = conn.cursor()
        
        c.execute("""
            SELECT COALESCE(SUM(amount), 0) 
            FROM expenses 
            WHERE user_id = ? AND month_year = ? AND category = ?
        """, (session['user_id'], month_year, category))
        
        actual_amount = c.fetchone()[0]
        
        c.execute("""
            INSERT OR REPLACE INTO monthly_budgets 
            (user_id, month_year, category, budget_amount, actual_amount, updated_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (session['user_id'], month_year, category, budget_amount, actual_amount))
        
        conn.commit()
        
        if actual_amount > budget_amount:
            c.execute("""
                INSERT INTO expense_alerts (user_id, alert_type, message)
                VALUES (?, ?, ?)
            """, (session['user_id'], 'budget_exceeded', 
                 f'Budget exceeded for {category} in {month_year}. Budget: ${budget_amount:.2f}, Actual: ${actual_amount:.2f}'))
            conn.commit()
        
        conn.close()
        
        return jsonify({
            "success": True, 
            "message": "Budget updated successfully",
            "actual_amount": actual_amount
        })
        
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route("/monthly_report")
@login_required
def monthly_report():
    """Generate monthly report with insights"""
    month_year = request.args.get('month', datetime.now().strftime("%Y-%m"))
    
    conn = sqlite3.connect('expenses.db')
    
    query = """
    WITH monthly_summary AS (
        SELECT 
            category,
            COUNT(*) as transaction_count,
            SUM(amount) as total_spent,
            AVG(amount) as average_transaction,
            MIN(amount) as smallest_expense,
            MAX(amount) as largest_expense
        FROM expenses 
        WHERE user_id = ? AND strftime('%Y-%m', date) = ?
        GROUP BY category
    ),
    budget_comparison AS (
        SELECT 
            b.category,
            b.budget_amount,
            COALESCE(ms.total_spent, 0) as actual_spent,
            CASE 
                WHEN b.budget_amount > 0 THEN 
                    ROUND((COALESCE(ms.total_spent, 0) / b.budget_amount) * 100, 1)
                ELSE NULL 
            END as budget_percentage
        FROM monthly_budgets b
        LEFT JOIN monthly_summary ms ON b.category = ms.category
        WHERE b.user_id = ? AND b.month_year = ?
    )
    SELECT 
        COALESCE(ms.category, bc.category) as category,
        COALESCE(ms.transaction_count, 0) as transaction_count,
        COALESCE(ms.total_spent, 0) as total_spent,
        COALESCE(ms.average_transaction, 0) as average_transaction,
        COALESCE(ms.smallest_expense, 0) as smallest_expense,
        COALESCE(ms.largest_expense, 0) as largest_expense,
        bc.budget_amount,
        bc.actual_spent,
        bc.budget_percentage
    FROM monthly_summary ms
    FULL OUTER JOIN budget_comparison bc ON ms.category = bc.category
    ORDER BY ms.total_spent DESC
    """
    
    df = pd.read_sql_query(query, conn, params=(
        session['user_id'], month_year,
        session['user_id'], month_year
    ))
    
    # FIX: Replace NaN values with 0
    df.fillna(0, inplace=True)
    
    # Also ensure numeric columns are properly typed
    numeric_columns = ['transaction_count', 'total_spent', 'average_transaction', 
                      'smallest_expense', 'largest_expense', 'budget_amount', 
                      'actual_spent', 'budget_percentage']
    
    for col in numeric_columns:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
    
    # Debug: Check the DataFrame
    print(f"DEBUG: DataFrame after cleaning:\n{df}")
    print(f"\nDEBUG: Data types:\n{df.dtypes}")
    
    plots = generate_monthly_report_charts(df, month_year)
    
    conn.close()
    
    # Convert to list of dictionaries with proper values
    data_records = []
    for record in df.to_dict('records'):
        # Ensure all numeric values are proper Python types (not numpy)
        cleaned_record = {}
        for key, value in record.items():
            if pd.isna(value):
                cleaned_record[key] = 0
            elif isinstance(value, (np.integer, np.floating)):
                cleaned_record[key] = float(value)
            else:
                cleaned_record[key] = value
        data_records.append(cleaned_record)
    
    return render_template("monthly_report.html",
                         month_year=month_year,
                         data=data_records,
                         plots=plots)

def generate_monthly_report_charts(df, month_year):
    """Generate charts for monthly report"""
    plots = []
    
    if df.empty:
        return plots
    
    # 1. Category-wise spending (Bar chart)
    try:
        plt.figure(figsize=(12, 7))
        
        filtered_df = df[df['category'].notna()]
        
        if len(filtered_df) > 0:
            categories = filtered_df['category'].tolist()
            amounts = filtered_df['total_spent'].fillna(0).tolist()
            
            colors = []
            for idx, row in filtered_df.iterrows():
                if pd.notna(row['budget_percentage']) and row['budget_percentage'] > 100:
                    colors.append('#e74c3c')
                elif pd.notna(row['budget_percentage']) and row['budget_percentage'] > 80:
                    colors.append('#f39c12')
                else:
                    colors.append('#3498db')
            
            bars = plt.bar(categories, amounts, color=colors, edgecolor='black', alpha=0.8)
            plt.title(f'Spending by Category - {month_year}', fontsize=16, fontweight='bold')
            plt.xlabel('Category', fontsize=12)
            plt.ylabel('Amount ($)', fontsize=12)
            plt.xticks(rotation=45, ha='right')
            plt.grid(axis='y', alpha=0.3)
            
            for bar in bars:
                height = bar.get_height()
                if height > 0:
                    plt.text(bar.get_x() + bar.get_width()/2., height + max(amounts)*0.01,
                            f'${height:.2f}', ha='center', va='bottom', fontsize=9, fontweight='bold')
            
            from matplotlib.patches import Patch
            legend_elements = [
                Patch(facecolor='#3498db', label='Within Budget'),
                Patch(facecolor='#f39c12', label='Near Budget Limit'),
                Patch(facecolor='#e74c3c', label='Budget Exceeded')
            ]
            plt.legend(handles=legend_elements, loc='upper right')
        
        plt.tight_layout()
        img1 = io.BytesIO()
        plt.savefig(img1, format='png', dpi=100, bbox_inches='tight')
        img1.seek(0)
        plot_url1 = base64.b64encode(img1.getvalue()).decode()
        plots.append(plot_url1)
        plt.close()
    except Exception as e:
        print(f"Error creating bar chart: {e}")
        plots.append(None)
    
    # 2. Budget vs Actual comparison
    budget_df = df[df['budget_amount'].notna() & (df['budget_amount'] > 0)]
    if not budget_df.empty:
        try:
            plt.figure(figsize=(12, 7))
            
            categories = budget_df['category'].tolist()
            budget_vals = budget_df['budget_amount'].tolist()
            actual_vals = budget_df['actual_spent'].tolist()
            
            x = range(len(categories))
            width = 0.35
            
            plt.bar([i - width/2 for i in x], budget_vals, width, 
                   label='Budget', color='#2ecc71', alpha=0.7)
            plt.bar([i + width/2 for i in x], actual_vals, width, 
                   label='Actual', color='#3498db', alpha=0.7)
            
            plt.xlabel('Category', fontsize=12)
            plt.ylabel('Amount ($)', fontsize=12)
            plt.title(f'Budget vs Actual Spending - {month_year}', fontsize=16, fontweight='bold')
            plt.xticks(x, categories, rotation=45, ha='right')
            plt.legend()
            plt.grid(axis='y', alpha=0.3)
            
            for i, (budget, actual) in enumerate(zip(budget_vals, actual_vals)):
                if budget > 0:
                    percentage = (actual / budget) * 100
                    plt.text(i, max(budget, actual) + max(budget_vals + actual_vals) * 0.02,
                            f'{percentage:.1f}%', ha='center', fontsize=9, fontweight='bold')
            
            plt.tight_layout()
            img2 = io.BytesIO()
            plt.savefig(img2, format='png', dpi=100, bbox_inches='tight')
            img2.seek(0)
            plot_url2 = base64.b64encode(img2.getvalue()).decode()
            plots.append(plot_url2)
            plt.close()
        except Exception as e:
            print(f"Error creating budget chart: {e}")
            plots.append(None)
    
    return plots

@app.route("/monthly_comparison")
@login_required
def monthly_comparison():
    """Compare spending across months"""
    months = request.args.get('months', 3, type=int)
    
    conn = sqlite3.connect('expenses.db')
    c = conn.cursor()
    
    c.execute("""
        SELECT month_year, SUM(amount) as total, COUNT(*) as count
        FROM expenses 
        WHERE user_id = ? 
        GROUP BY month_year 
        ORDER BY month_year DESC
        LIMIT ?
    """, (session['user_id'], months))
    
    monthly_comparison = c.fetchall()
    
    c.execute("""
        WITH recent_months AS (
            SELECT DISTINCT month_year
            FROM expenses 
            WHERE user_id = ?
            ORDER BY month_year DESC
            LIMIT ?
        )
        SELECT e.month_year, e.category, SUM(e.amount) as total
        FROM expenses e
        JOIN recent_months rm ON e.month_year = rm.month_year
        WHERE e.user_id = ?
        GROUP BY e.month_year, e.category
        ORDER BY e.month_year DESC, total DESC
    """, (session['user_id'], months, session['user_id']))
    
    category_comparison = c.fetchall()
    
    conn.close()
    
    comparison_chart = generate_comparison_chart(monthly_comparison)
    
    return render_template("monthly_comparison.html",
                         monthly_comparison=monthly_comparison,
                         category_comparison=category_comparison,
                         comparison_chart=comparison_chart,
                         months=months)

def generate_comparison_chart(monthly_data):
    """Generate comparison chart for monthly data"""
    if not monthly_data:
        return None
    
    try:
        months = [row[0] for row in monthly_data]
        totals = [row[1] for row in monthly_data]
        counts = [row[2] for row in monthly_data]
        
        x = range(len(months))
        
        fig, ax1 = plt.subplots(figsize=(12, 7))
        
        color = 'tab:blue'
        ax1.set_xlabel('Month', fontsize=12)
        ax1.set_ylabel('Total Amount ($)', color=color, fontsize=12)
        bars = ax1.bar(x, totals, color=color, alpha=0.7, label='Total Amount')
        ax1.tick_params(axis='y', labelcolor=color)
        ax1.set_xticks(x)
        ax1.set_xticklabels(months, rotation=45, ha='right')
        
        ax2 = ax1.twinx()
        color = 'tab:red'
        ax2.set_ylabel('Number of Transactions', color=color, fontsize=12)
        line = ax2.plot(x, counts, color=color, marker='o', linewidth=2, label='Transaction Count')
        ax2.tick_params(axis='y', labelcolor=color)
        
        for i, (bar, total) in enumerate(zip(bars, totals)):
            ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(totals)*0.01,
                    f'${total:.0f}', ha='center', va='bottom', fontsize=9, fontweight='bold')
        
        for i, count in enumerate(counts):
            ax2.text(i, count + max(counts)*0.05, f'{count}', 
                    ha='center', va='bottom', fontsize=9, fontweight='bold', color='tab:red')
        
        plt.title('Monthly Spending Comparison', fontsize=16, fontweight='bold', pad=20)
        fig.tight_layout()
        
        img = io.BytesIO()
        plt.savefig(img, format='png', dpi=100, bbox_inches='tight')
        img.seek(0)
        plot_url = base64.b64encode(img.getvalue()).decode()
        plt.close()
        
        return plot_url
    except Exception as e:
        print(f"Error creating comparison chart: {e}")
        return None

@app.route("/export_monthly")
@login_required
def export_monthly():
    """Export monthly data to Excel"""
    month_year = request.args.get('month', datetime.now().strftime("%Y-%m"))
    
    conn = sqlite3.connect('expenses.db')
    
    df_expenses = pd.read_sql_query("""
        SELECT date, invoice_no, vendor, category, description, amount
        FROM expenses 
        WHERE user_id = ? AND month_year = ?
        ORDER BY date DESC
    """, conn, params=(session['user_id'], month_year))
    
    df_summary = pd.read_sql_query("""
        SELECT category, COUNT(*) as transactions, SUM(amount) as total
        FROM expenses 
        WHERE user_id = ? AND month_year = ?
        GROUP BY category
        ORDER BY total DESC
    """, conn, params=(session['user_id'], month_year))
    
    df_budget = pd.read_sql_query("""
        SELECT category, budget_amount, actual_amount,
               (budget_amount - actual_amount) as remaining
        FROM monthly_budgets 
        WHERE user_id = ? AND month_year = ?
    """, conn, params=(session['user_id'], month_year))
    
    conn.close()
    
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df_expenses.to_excel(writer, sheet_name='Expenses', index=False)
        df_summary.to_excel(writer, sheet_name='Category Summary', index=False)
        if not df_budget.empty:
            df_budget.to_excel(writer, sheet_name='Budget', index=False)
    
    output.seek(0)
    
    filename = f"expenses_{month_year}.xlsx"
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=filename
    )

# ---------------- ALERT MANAGEMENT ROUTES ----------------
@app.route("/alerts")
@login_required
def view_alerts():
    """View expense alerts"""
    conn = sqlite3.connect('expenses.db')
    c = conn.cursor()
    
    c.execute("""
        SELECT * FROM expense_alerts 
        WHERE user_id = ? 
        ORDER BY created_at DESC
        LIMIT 50
    """, (session['user_id'],))
    
    alerts = c.fetchall()
    
    conn.close()
    
    return render_template("alerts.html", alerts=alerts)

@app.route("/mark_alert_read/<int:alert_id>", methods=["POST"])
@login_required
def mark_alert_read(alert_id):
    """Mark a specific alert as read"""
    conn = sqlite3.connect('expenses.db')
    c = conn.cursor()
    c.execute("""
        UPDATE expense_alerts 
        SET is_read = 1 
        WHERE id = ? AND user_id = ?
    """, (alert_id, session['user_id']))
    conn.commit()
    affected = c.rowcount
    conn.close()
    
    if affected > 0:
        return jsonify({'success': True, 'message': 'Alert marked as read'})
    else:
        return jsonify({'success': False, 'message': 'Alert not found or access denied'}), 404

@app.route("/mark_all_alerts_read", methods=["POST"])
@login_required
def mark_all_alerts_read():
    """Mark all alerts as read"""
    conn = sqlite3.connect('expenses.db')
    c = conn.cursor()
    c.execute("""
        UPDATE expense_alerts 
        SET is_read = 1 
        WHERE user_id = ? AND is_read = 0
    """, (session['user_id'],))
    conn.commit()
    affected = c.rowcount
    conn.close()
    
    return jsonify({'success': True, 'message': f'{affected} alerts marked as read', 'count': affected})

@app.route("/delete_alert/<int:alert_id>", methods=["POST"])
@login_required
def delete_alert(alert_id):
    """Delete a specific alert"""
    conn = sqlite3.connect('expenses.db')
    c = conn.cursor()
    c.execute("""
        DELETE FROM expense_alerts 
        WHERE id = ? AND user_id = ?
    """, (alert_id, session['user_id']))
    conn.commit()
    affected = c.rowcount
    conn.close()
    
    if affected > 0:
        return jsonify({'success': True, 'message': 'Alert deleted'})
    else:
        return jsonify({'success': False, 'message': 'Alert not found or access denied'}), 404

@app.route("/clear_all_alerts", methods=["POST"])
@login_required
def clear_all_alerts():
    """Clear all alerts"""
    conn = sqlite3.connect('expenses.db')
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM expense_alerts WHERE user_id = ?", (session['user_id'],))
    count = c.fetchone()[0]
    
    c.execute("DELETE FROM expense_alerts WHERE user_id = ?", (session['user_id'],))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': f'Cleared {count} alerts', 'count': count})

# ---------------- OTHER ROUTES ----------------
@app.route("/update_category", methods=["POST"])
@login_required
def update_category():
    """Update category for an expense via AJAX"""
    expense_id = request.form.get('expense_id')
    new_category = request.form.get('category')
    
    if expense_id and new_category:
        conn = sqlite3.connect('expenses.db')
        c = conn.cursor()
        c.execute("UPDATE expenses SET category = ? WHERE id = ? AND user_id = ?", 
                 (new_category, expense_id, session['user_id']))
        conn.commit()
        
        if c.rowcount > 0:
            conn.close()
            return jsonify({"success": True, "message": "Category updated successfully"})
        else:
            conn.close()
            return jsonify({"success": False, "message": "Expense not found or access denied"})
    
    return jsonify({"success": False, "message": "Invalid request"})

@app.route("/delete_expense/<int:expense_id>", methods=["POST"])
@login_required
def delete_expense(expense_id):
    """Delete an expense"""
    conn = sqlite3.connect('expenses.db')
    c = conn.cursor()
    c.execute("DELETE FROM expenses WHERE id = ? AND user_id = ?", 
             (expense_id, session['user_id']))
    conn.commit()
    
    if c.rowcount > 0:
        conn.close()
        flash('Expense deleted successfully!', 'success')
    else:
        conn.close()
        flash('Expense not found or access denied.', 'error')
    
    return redirect(url_for('show_expenses'))

# ---------------- HELPER FUNCTIONS ----------------
@app.context_processor
def utility_processor():
    """Make utility functions available in templates"""
    def format_currency(value):
        try:
            if value is None:
                return "$0.00"
            return f"${float(value):,.2f}"
        except:
            return f"${value}"
    
    def format_date(value, format='%Y-%m-%d'):
        if value:
            try:
                return datetime.strptime(str(value), '%Y-%m-%d').strftime(format)
            except:
                return value
        return value
    
    def get_date_7days_ago():
        return (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
    
    def get_now():
        return datetime.now()
    
    return {
        'format_currency': format_currency,
        'format_date': format_date,
        'date_7days_ago': get_date_7days_ago(),
        'now': get_now()
    }
# ---------------- ERROR HANDLERS ----------------
@app.errorhandler(404)
def not_found_error(error):
    return "Page not found", 404

@app.errorhandler(500)
def internal_error(error):
    return "Internal server error", 500

# ---------------- MAIN ----------------
if __name__ == "__main__":
    if not os.path.exists("uploads"):
        os.makedirs("uploads")
    
    print("Starting Invoice Processing System...")
    print("Access the application at: http://localhost:5000")
    print("Default login: admin / admin123")
    print("Monthly Expenses: http://localhost:5000/monthly")
    print("Alerts: http://localhost:5000/alerts")
    
    app.run(debug=True, host='0.0.0.0', port=5000)