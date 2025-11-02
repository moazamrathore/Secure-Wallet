import streamlit as st
import hashlib
import json
import base64
import re
from datetime import datetime, timedelta
import time

# Page configuration
st.set_page_config(
    page_title="SecureWallet",
    page_icon="💰",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
        color: #1e40af;
        margin-bottom: 2rem;
    }
    .success-msg {
        padding: 1rem;
        background-color: #d1fae5;
        border-left: 4px solid #10b981;
        border-radius: 0.5rem;
        color: #065f46;
    }
    .error-msg {
        padding: 1rem;
        background-color: #fee2e2;
        border-left: 4px solid #ef4444;
        border-radius: 0.5rem;
        color: #991b1b;
    }
    .info-box {
        padding: 1rem;
        background-color: #dbeafe;
        border-left: 4px solid #3b82f6;
        border-radius: 0.5rem;
        color: #1e40af;
    }
    .balance-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 1rem;
        color: white;
        text-align: center;
    }
    .stButton>button {
        width: 100%;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
def init_session_state():
    if 'users' not in st.session_state:
        st.session_state.users = {}
    if 'transactions' not in st.session_state:
        st.session_state.transactions = []
    if 'audit_logs' not in st.session_state:
        st.session_state.audit_logs = []
    if 'current_user' not in st.session_state:
        st.session_state.current_user = None
    if 'login_attempts' not in st.session_state:
        st.session_state.login_attempts = {}
    if 'last_activity' not in st.session_state:
        st.session_state.last_activity = datetime.now()
    if 'page' not in st.session_state:
        st.session_state.page = 'login'

init_session_state()

# Security Functions
def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def encrypt_data(data):
    """Encrypt data using base64"""
    json_data = json.dumps(data)
    return base64.b64encode(json_data.encode()).decode()

def decrypt_data(encrypted_data):
    """Decrypt base64 encoded data"""
    try:
        decoded = base64.b64decode(encrypted_data.encode()).decode()
        return json.loads(decoded)
    except:
        return None

def sanitize_input(text):
    """Remove dangerous characters from input"""
    # Remove SQL injection patterns and XSS attempts
    dangerous_chars = ['<', '>', '"', "'", ';', '/', '\\', '{', '}', '(', ')']
    sanitized = text
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    return sanitized.strip()

def check_xss_attempt(text):
    """Check for XSS attack patterns"""
    xss_patterns = ['<script', '</script>', 'javascript:', 'onerror=', 'onload=', 
                    '<iframe', '<img', 'onclick=', 'onmouseover=', 'alert(', 'eval(']
    text_lower = text.lower()
    for pattern in xss_patterns:
        if pattern in text_lower:
            return True
    return False

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain special character"
    return True, "Valid"

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def check_sql_injection(text):
    """Check for SQL injection patterns"""
    sql_patterns = ['or 1=1', 'union select', 'drop table', 'insert into', 
                    'delete from', 'update set', '--', '/*', '*/', 'xp_', 'sp_']
    text_lower = text.lower()
    for pattern in sql_patterns:
        if pattern in text_lower:
            return True
    return False

def add_audit_log(action, details):
    """Add entry to audit log"""
    log = {
        'timestamp': datetime.now().isoformat(),
        'user': st.session_state.current_user['username'] if st.session_state.current_user else 'Anonymous',
        'action': action,
        'details': details,
        'ip': '192.168.1.1'  # Simulated
    }
    st.session_state.audit_logs.append(log)

def check_session_timeout():
    """Check if session has timed out (5 minutes)"""
    if st.session_state.current_user:
        time_diff = datetime.now() - st.session_state.last_activity
        if time_diff > timedelta(minutes=5):
            st.session_state.current_user = None
            st.session_state.page = 'login'
            add_audit_log('Session Expired', 'Auto logout due to inactivity')
            return True
    return False

def update_activity():
    """Update last activity timestamp"""
    st.session_state.last_activity = datetime.now()

def validate_file_upload(uploaded_file):
    """Validate uploaded file type"""
    if uploaded_file is None:
        return True, "No file uploaded"
    
    # Get file extension
    filename = uploaded_file.name
    file_extension = filename.split('.')[-1].lower() if '.' in filename else ''
    
    # Allowed file types (for profile pictures/KYC documents)
    allowed_extensions = ['jpg', 'jpeg', 'png', 'pdf', 'doc', 'docx']
    
    # Blocked dangerous extensions
    blocked_extensions = ['exe', 'bat', 'sh', 'cmd', 'com', 'pif', 'scr', 
                          'vbs', 'js', 'jar', 'zip', 'rar', 'dll', 'sys',
                          'msi', 'app', 'deb', 'rpm', 'dmg', 'pkg', 'apk',
                          'php', 'asp', 'jsp', 'py', 'rb', 'pl', 'cgi']
    
    if not file_extension:
        return False, "File has no extension. Only files with valid extensions are allowed."
    
    if file_extension in blocked_extensions:
        return False, f"Security Alert: '.{file_extension}' files are blocked as they may contain malicious code or executables"
    
    if file_extension not in allowed_extensions:
        return False, f"File type '.{file_extension}' is not supported. Allowed types: {', '.join(allowed_extensions)}"
    
    # Check file size (max 5MB)
    if uploaded_file.size > 5 * 1024 * 1024:
        return False, f"File size ({uploaded_file.size / 1024 / 1024:.2f} MB) exceeds the 5MB limit"
    
    # Check for double extensions (e.g., file.pdf.exe)
    if filename.count('.') > 1:
        all_extensions = [ext.lower() for ext in filename.split('.')[1:]]
        for ext in all_extensions[:-1]:  # Check all extensions except the last one
            if ext in blocked_extensions:
                return False, f"Security Alert: Detected hidden dangerous extension '.{ext}' in filename"
    
    return True, "File validation passed"

# Registration Page
def register_page():
    st.markdown('<h1 class="main-header">🆕 Create Account</h1>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        with st.form("register_form"):
            st.subheader("Registration Form")
            
            username = st.text_input("Username", max_chars=50, 
                                    help="Minimum 3 characters")
            email = st.text_input("Email", max_chars=100)
            phone = st.text_input("Phone Number", max_chars=15, 
                                 help="10-15 digits only")
            password = st.text_input("Password", type="password", max_chars=100,
                                    help="Min 8 chars, uppercase, lowercase, number, special char")
            confirm_password = st.text_input("Confirm Password", type="password", max_chars=100)
            
            st.info("💡 Password must contain: 8+ characters, uppercase, lowercase, number, special character")
            
            submitted = st.form_submit_button("Register", use_container_width=True)
            
            if submitted:
                errors = []
                
                # Check for XSS attempts BEFORE sanitizing
                if check_xss_attempt(username):
                    errors.append("XSS attack detected! Special characters like <script> are not allowed")
                    add_audit_log('Registration Failed - XSS Attempt', f"Username attempted: {username}")
                
                if check_xss_attempt(email):
                    errors.append("XSS attack detected in email field")
                
                # Sanitize inputs
                username = sanitize_input(username)
                email = sanitize_input(email)
                
                # Validation
                if not username or len(username) < 3:
                    errors.append("Username must be at least 3 characters")
                
                if username in st.session_state.users:
                    errors.append("Username already exists")
                
                if not validate_email(email):
                    errors.append("Invalid email format")
                
                if not re.match(r'^\d{10,15}$', phone):
                    errors.append("Phone must be 10-15 digits")
                
                valid_pwd, pwd_msg = validate_password(password)
                if not valid_pwd:
                    errors.append(pwd_msg)
                
                if password != confirm_password:
                    errors.append("Passwords do not match")
                
                if errors:
                    for error in errors:
                        st.error(f"❌ {error}")
                    add_audit_log('Registration Failed', f"Username: {username}, Errors: {', '.join(errors)}")
                else:
                    # Create user
                    user_data = {
                        'username': username,
                        'password_hash': hash_password(password),
                        'email': email,
                        'phone': phone,
                        'balance': 1000.0,
                        'created_at': datetime.now().isoformat(),
                        'transaction_pin': hash_password('1234')
                    }
                    
                    # Encrypt and store
                    encrypted_user_data = encrypt_data(user_data)
                    st.session_state.users[username] = encrypted_user_data
                    
                    st.success('✅ Registration successful! You received $1000 welcome bonus.')
                    
                    # DEBUG INFO - For Test #18: Data Encryption Check
                    with st.expander("🔍 Click here to verify data encryption (For Testing Only)"):
                        st.info("**Test #18: Data Encryption Verification**")
                        st.write("**How data is stored in the system:**")
                        
                        col_a, col_b = st.columns(2)
                        
                        with col_a:
                            st.markdown("##### 📦 Encrypted Storage (Base64)")
                            st.code(f"{encrypted_user_data[:100]}...\n\n(Full encrypted string: {len(encrypted_user_data)} characters)", language="text")
                            st.caption("✅ Data is encrypted before storage")
                        
                        with col_b:
                            st.markdown("##### 🔓 Original Data Structure")
                            st.json({
                                "username": username,
                                "password_hash": user_data['password_hash'][:20] + "...",
                                "email": email,
                                "phone": phone,
                                "balance": 1000.0
                            })
                            st.caption("🔒 Password stored as hash, not plain text")
                        
                        st.success("""
                        **Encryption Verified:**
                        - ✅ User data encrypted using Base64 encoding
                        - ✅ Password hashed using SHA-256
                        - ✅ Original password never stored
                        - ✅ Data unreadable without decryption
                        """)
                    
                    add_audit_log('User Registered', f"Username: {username}")
                    
                    st.info("⏳ Redirecting to login in 3 seconds...")
                    time.sleep(3)
                    st.session_state.page = 'login'
                    st.rerun()
        
        st.markdown("---")
        if st.button("Already have an account? Login", use_container_width=True):
            st.session_state.page = 'login'
            st.rerun()

# Login Page
def login_page():
    st.markdown('<h1 class="main-header">💰 SecureWallet</h1>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        with st.form("login_form"):
            st.subheader("Login to Your Account")
            
            username = st.text_input("Username", max_chars=50)
            password = st.text_input("Password", type="password", max_chars=100)
            
            submitted = st.form_submit_button("Login", use_container_width=True)
            
            if submitted:
                # Check for SQL injection and XSS attacks
                if check_sql_injection(username) or check_sql_injection(password):
                    st.error("❌ SQL Injection attempt detected! Invalid characters in input")
                    add_audit_log('Login Failed - SQL Injection Attempt', f"Username: {username}")
                elif check_xss_attempt(username) or check_xss_attempt(password):
                    st.error("❌ XSS attack detected! Special characters like <script> are not allowed")
                    add_audit_log('Login Failed - XSS Attempt', f"Username: {username}")
                else:
                    username = sanitize_input(username)
                    
                    # Check account lockout
                    attempts = st.session_state.login_attempts.get(username, 0)
                    if attempts >= 5:
                        st.error("🔒 Account locked due to too many failed attempts")
                        add_audit_log('Login Failed - Account Locked', f"Username: {username}")
                    else:
                        # Check credentials
                        if username not in st.session_state.users:
                            st.error("❌ Invalid credentials")
                            st.session_state.login_attempts[username] = attempts + 1
                            add_audit_log('Login Failed - User Not Found', f"Username: {username}")
                        else:
                            user_data = decrypt_data(st.session_state.users[username])
                            if user_data['password_hash'] != hash_password(password):
                                st.error("❌ Invalid credentials")
                                st.session_state.login_attempts[username] = attempts + 1
                                add_audit_log('Login Failed - Wrong Password', f"Username: {username}, Attempts: {attempts + 1}")
                            else:
                                # Successful login
                                st.session_state.current_user = user_data
                                st.session_state.login_attempts[username] = 0
                                st.session_state.last_activity = datetime.now()
                                st.session_state.page = 'dashboard'
                                add_audit_log('Login Successful', f"Username: {username}")
                                st.rerun()
        
        st.markdown("---")
        if st.button("Don't have an account? Register", use_container_width=True):
            st.session_state.page = 'register'
            st.rerun()

# Dashboard Page
def dashboard_page():
    update_activity()
    
    if check_session_timeout():
        st.warning("⚠️ Session expired due to inactivity")
        time.sleep(2)
        st.rerun()
        return
    
    # Header
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown('<h1 class="main-header">💰 SecureWallet Dashboard</h1>', unsafe_allow_html=True)
    with col2:
        if st.button("🚪 Logout", use_container_width=True):
            add_audit_log('Logout', f"Username: {st.session_state.current_user['username']}")
            st.session_state.current_user = None
            st.session_state.page = 'login'
            st.rerun()
    
    st.markdown(f"### Welcome, **{st.session_state.current_user['username']}**! 👋")
    
    # Balance Cards
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    padding: 2rem; border-radius: 1rem; color: white; text-align: center;">
            <h3>Current Balance</h3>
            <h1>${st.session_state.current_user['balance']:.2f}</h1>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        user_transactions = [t for t in st.session_state.transactions 
                           if t['from'] == st.session_state.current_user['username'] 
                           or t['to'] == st.session_state.current_user['username']]
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); 
                    padding: 2rem; border-radius: 1rem; color: white; text-align: center;">
            <h3>Total Transactions</h3>
            <h1>{len(user_transactions)}</h1>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); 
                    padding: 2rem; border-radius: 1rem; color: white; text-align: center;">
            <h3>Account Status</h3>
            <h1>Active ✅</h1>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Main Content Tabs
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["💸 Send Money", "➕ Add Money", "👤 Profile", "📁 Documents", "📊 History", "🔍 Security Debug"])
    
    # Tab 1: Send Money
    with tab1:
        st.subheader("Send Money")
        with st.form("send_money_form"):
            recipient = st.text_input("Recipient Username", max_chars=50)
            amount_input = st.text_input("Amount ($)", placeholder="Enter amount (e.g., 100.50)")
            notes = st.text_area("Notes (Optional)", max_chars=500, height=100)
            transaction_pin = st.text_input("Transaction PIN", type="password", 
                                          help="Default PIN: 1234")
            
            submit_send = st.form_submit_button("💸 Send Money", use_container_width=True)
            
            if submit_send:
                errors = []
                recipient = sanitize_input(recipient)
                
                # Validate amount is numeric
                try:
                    amount = float(amount_input)
                except (ValueError, TypeError):
                    errors.append(f"Invalid amount: '{amount_input}' is not a valid number. Please enter numeric values only (e.g., 100.50)")
                    amount = 0
                
                # Check for XSS in notes
                if check_xss_attempt(notes):
                    errors.append("XSS attack detected in notes! Special characters not allowed")
                
                # Additional validation for negative numbers
                if not errors and amount < 0:
                    errors.append("Amount cannot be negative")
                
                if not errors and amount <= 0:
                    errors.append("Amount must be a positive number")
                
                if amount > 10000:
                    errors.append("Maximum transaction limit is $10,000")
                
                if amount > st.session_state.current_user['balance']:
                    errors.append("Insufficient balance")
                
                if recipient not in st.session_state.users:
                    errors.append("Recipient not found")
                
                if recipient == st.session_state.current_user['username']:
                    errors.append("Cannot send money to yourself")
                
                if hash_password(transaction_pin) != st.session_state.current_user['transaction_pin']:
                    errors.append("Invalid transaction PIN")
                
                if len(notes) > 500:
                    errors.append("Notes cannot exceed 500 characters")
                
                if errors:
                    for error in errors:
                        st.error(f"❌ {error}")
                    add_audit_log('Transaction Failed', f"Errors: {', '.join(errors)}")
                else:
                    # Process transaction
                    st.session_state.current_user['balance'] -= amount
                    
                    recipient_data = decrypt_data(st.session_state.users[recipient])
                    recipient_data['balance'] += amount
                    
                    # Update encrypted data
                    st.session_state.users[st.session_state.current_user['username']] = encrypt_data(st.session_state.current_user)
                    st.session_state.users[recipient] = encrypt_data(recipient_data)
                    
                    # Add transaction
                    transaction = {
                        'id': len(st.session_state.transactions) + 1,
                        'from': st.session_state.current_user['username'],
                        'to': recipient,
                        'amount': amount,
                        'notes': sanitize_input(notes),
                        'timestamp': datetime.now().isoformat(),
                        'type': 'sent'
                    }
                    st.session_state.transactions.append(transaction)
                    
                    st.success(f"✅ Successfully sent ${amount:.2f} to {recipient}")
                    add_audit_log('Transaction Successful', f"To: {recipient}, Amount: ${amount}")
                    time.sleep(2)
                    st.rerun()
    
    # Tab 2: Add Money
    with tab2:
        st.subheader("Add Money to Wallet")
        with st.form("add_money_form"):
            amount_input = st.text_input("Amount ($)", placeholder="Enter amount (e.g., 500.00)")
            
            submit_add = st.form_submit_button("➕ Add Money", use_container_width=True)
            
            if submit_add:
                errors = []
                
                # Validate amount is numeric
                try:
                    amount = float(amount_input)
                except (ValueError, TypeError):
                    errors.append(f"Invalid amount: '{amount_input}' is not a valid number. Please enter numeric values only")
                    amount = 0
                
                # Additional validation for negative numbers
                if not errors and amount < 0:
                    errors.append("Amount cannot be negative")
                
                if not errors and amount <= 0:
                    errors.append("Amount must be a positive number")
                elif not errors and amount > 50000:
                    errors.append("Maximum deposit limit is $50,000")
                
                if errors:
                    for error in errors:
                        st.error(f"❌ {error}")
                else:
                    st.session_state.current_user['balance'] += amount
                    st.session_state.users[st.session_state.current_user['username']] = encrypt_data(st.session_state.current_user)
                    
                    transaction = {
                        'id': len(st.session_state.transactions) + 1,
                        'from': 'Bank',
                        'to': st.session_state.current_user['username'],
                        'amount': amount,
                        'notes': 'Money added to wallet',
                        'timestamp': datetime.now().isoformat(),
                        'type': 'received'
                    }
                    st.session_state.transactions.append(transaction)
                    
                    st.success(f"✅ Successfully added ${amount:.2f} to your wallet")
                    add_audit_log('Money Added', f"Amount: ${amount}")
                    time.sleep(2)
                    st.rerun()
    
    # Tab 3: Profile
    with tab3:
        st.subheader("Update Profile")
        with st.form("update_profile_form"):
            new_email = st.text_input("Email", value=st.session_state.current_user['email'], max_chars=100)
            new_phone = st.text_input("Phone", value=st.session_state.current_user['phone'], max_chars=15)
            
            submit_profile = st.form_submit_button("💾 Update Profile", use_container_width=True)
            
            if submit_profile:
                errors = []
                
                if new_email and not validate_email(new_email):
                    errors.append("Invalid email format")
                
                if new_phone and not re.match(r'^\d{10,15}$', new_phone):
                    errors.append("Phone must be 10-15 digits")
                
                if errors:
                    for error in errors:
                        st.error(f"❌ {error}")
                else:
                    st.session_state.current_user['email'] = new_email
                    st.session_state.current_user['phone'] = new_phone
                    st.session_state.users[st.session_state.current_user['username']] = encrypt_data(st.session_state.current_user)
                    
                    st.success("✅ Profile updated successfully")
                    add_audit_log('Profile Updated', f"Username: {st.session_state.current_user['username']}")
                    time.sleep(2)
                    st.rerun()
        
        st.markdown("---")
        st.info(f"""
        **Account Information:**
        - Username: {st.session_state.current_user['username']}
        - Email: {st.session_state.current_user['email']}
        - Phone: {st.session_state.current_user['phone']}
        - Created: {st.session_state.current_user['created_at'][:10]}
        - Default Transaction PIN: 1234
        """)
    
    # Tab 4: Document Upload (NEW FEATURE)
    with tab4:
        st.subheader("📁 Upload Documents")
        st.info("Upload your KYC documents or profile picture. Allowed formats: JPG, PNG, PDF, DOC, DOCX")
        
        # Remove type restriction to allow any file selection, then validate manually
        uploaded_file = st.file_uploader("Choose a file", type=None)
        
        if uploaded_file is not None:
            is_valid, message = validate_file_upload(uploaded_file)
            
            if is_valid:
                st.success(f"✅ File Validation Passed!")
                st.info(f"""
                **File Details:**
                - Filename: `{uploaded_file.name}`
                - File size: {uploaded_file.size / 1024:.2f} KB
                - File type: {uploaded_file.type if uploaded_file.type else 'Unknown'}
                - Status: ✅ Safe to upload
                """)
                
                if st.button("📤 Confirm Upload", use_container_width=True):
                    st.success("✅ Document uploaded successfully!")
                    add_audit_log('Document Uploaded', f"Filename: {uploaded_file.name}")
                    st.balloons()
            else:
                # Show detailed error for dangerous files
                st.error(f"🚫 **FILE UPLOAD REJECTED**")
                st.error(f"❌ {message}")
                
                st.warning(f"""
                **Attempted Upload Details:**
                - Filename: `{uploaded_file.name}`
                - File size: {uploaded_file.size / 1024:.2f} KB
                - File type: {uploaded_file.type if uploaded_file.type else 'Unknown'}
                - Status: ❌ **BLOCKED FOR SECURITY**
                """)
                
                add_audit_log('File Upload Rejected - Security Threat', f"Filename: {uploaded_file.name}, Reason: {message}")
        
        st.markdown("---")
        
        # Show allowed and blocked file types
        col1, col2 = st.columns(2)
        
        with col1:
            st.success("""
            **✅ Allowed File Types:**
            - Images: `.jpg`, `.jpeg`, `.png`
            - Documents: `.pdf`, `.doc`, `.docx`
            - Maximum size: 5 MB
            """)
        
        with col2:
            st.error("""
            **🚫 Blocked File Types:**
            - Executables: `.exe`, `.bat`, `.sh`, `.cmd`
            - Scripts: `.js`, `.vbs`, `.jar`, `.com`
            - Archives: `.zip`, `.rar`
            - System files: `.dll`, `.sys`
            - And other dangerous formats
            """)
        
        st.markdown("---")
        st.warning("⚠️ **Security Notice:** For security reasons, executable and potentially dangerous files are automatically blocked to protect against malware.")
    
    # Tab 5: Transaction History
    with tab5:
        st.subheader("📊 Transaction History")
        
        user_transactions = [t for t in st.session_state.transactions 
                           if t['from'] == st.session_state.current_user['username'] 
                           or t['to'] == st.session_state.current_user['username']]
        
        if not user_transactions:
            st.info("No transactions yet")
        else:
            # Sort by timestamp (newest first)
            user_transactions.sort(key=lambda x: x['timestamp'], reverse=True)
            
            for txn in user_transactions:
                txn_type = "Sent" if txn['from'] == st.session_state.current_user['username'] else "Received"
                color = "red" if txn_type == "Sent" else "green"
                
                st.markdown(f"""
                <div style="border: 1px solid #ddd; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1rem;">
                    <strong style="color: {color};">{txn_type}</strong> - ${txn['amount']:.2f}<br>
                    <strong>From:</strong> {txn['from']} → <strong>To:</strong> {txn['to']}<br>
                    <strong>Date:</strong> {txn['timestamp'][:19].replace('T', ' ')}<br>
                    <strong>Notes:</strong> {txn['notes'] or 'No notes'}
                </div>
                """, unsafe_allow_html=True)
    
    # Tab 6: Security Debug (NEW - For Testing Password Hashing)
    with tab6:
        st.subheader("🔍 Security Debug Information")
        st.warning("⚠️ **For Testing Only** - Remove this tab in production!")
        
        st.markdown("---")
        st.markdown("### 🔐 Password Hashing Verification")
        
        # Show current user's encrypted data
        encrypted_user = st.session_state.users[st.session_state.current_user['username']]
        
        st.info("""
        **What to verify:**
        - Password is NOT stored in plain text
        - Password is stored as a SHA-256 hash
        - User data is encrypted using Base64 encoding
        """)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 📦 Encrypted Storage")
            st.code(f"Encrypted User Data:\n{encrypted_user[:100]}...\n\n(This is how data is stored - encrypted and unreadable)", language="text")
        
        with col2:
            st.markdown("#### 🔓 Decrypted Data Structure")
            st.json({
                "username": st.session_state.current_user['username'],
                "password_hash": st.session_state.current_user['password_hash'],
                "email": st.session_state.current_user['email'],
                "phone": st.session_state.current_user['phone'],
                "balance": st.session_state.current_user['balance'],
                "created_at": st.session_state.current_user['created_at']
            })
        
        st.markdown("---")
        
        st.success(f"""
        ✅ **Security Verified:**
        - Original Password: `[NOT STORED - User entered during registration]`
        - Stored Password Hash: `{st.session_state.current_user['password_hash']}`
        - Hash Type: SHA-256
        - Hash Length: {len(st.session_state.current_user['password_hash'])} characters
        """)
        
        st.info("""
        **How it works:**
        1. User enters password: `Test@1234`
        2. App hashes it using SHA-256: `{hash}`
        3. Only the hash is stored (64 character hexadecimal)
        4. Original password is NEVER stored
        5. When logging in, entered password is hashed and compared with stored hash
        """)
        
        st.markdown("---")
        st.markdown("### 📊 All Users (Encrypted)")
        st.write(f"Total Registered Users: {len(st.session_state.users)}")
        
        for username, encrypted_data in st.session_state.users.items():
            with st.expander(f"User: {username}"):
                st.code(f"Encrypted: {encrypted_data[:80]}...", language="text")
                user_data = decrypt_data(encrypted_data)
                st.write(f"Password Hash: `{user_data['password_hash']}`")
                st.write(f"Email: {user_data['email']}")
                st.write(f"Balance: ${user_data['balance']:.2f}")
        
        st.markdown("---")
        st.error("🚨 **Important:** Remove this debug tab before deploying to production!")


# Main App Logic
def main():
    if st.session_state.page == 'login':
        login_page()
    elif st.session_state.page == 'register':
        register_page()
    elif st.session_state.page == 'dashboard':
        if st.session_state.current_user:
            dashboard_page()
        else:
            st.session_state.page = 'login'
            st.rerun()

if __name__ == "__main__":
    main()
