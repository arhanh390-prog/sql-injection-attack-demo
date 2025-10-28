import streamlit as st
import sqlite3
import pandas as pd
import re
import atexit

# --- Database Setup ---
# Use a simple file-based database.
DB_NAME = "demo.db"

# Function to initialize the database
def init_db():
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Drop the table if it already exists to start fresh each time
        cursor.execute("DROP TABLE IF EXISTS users")
        
        # Create the users table
        cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL
        )
        """)
        
        # Insert 20 mock users
        mock_users = []
        for i in range(1, 21):
            mock_users.append(
                (f"user{i}", f"pass{i*123}", f"user{i}@example.com", "user" if i > 2 else "admin")
            )
        
        cursor.executemany(
            "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
            mock_users
        )
        
        conn.commit()
        return conn
    except sqlite3.Error as e:
        st.error(f"Database error: {e}")
        return None
    finally:
        if conn:
            conn.close()

# Function to clean up the DB file on exit
def cleanup():
    import os
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)

# Initialize the database when the script starts
init_db()
# Register the cleanup function to run when the script exits
atexit.register(cleanup)

# Function to securely get a database connection
def get_db_conn():
    try:
        return sqlite3.connect(DB_NAME)
    except sqlite3.Error as e:
        st.error(f"Failed to connect to database: {e}")
        return None

# --- SQLi Detection Function ---
def detect_sqli(input_string):
    """
    A simple regex-based SQLi detector.
    This is for educational purposes and is NOT a complete solution.
    """
    # Patterns for common SQLi keywords and characters
    # This list is not exhaustive and can be bypassed, but demonstrates the concept.
    patterns = [
        r"(['\"])(\s*or\s*|\s*and\s*)\s*(\1\w+\1\s*=\s*\1\w+\1)", # ' or '1'='1
        r"(\s*or\s+|\s*and\s+)\s*\d+\s*=\s*\d+", # or 1=1
        r"(\s*or\s+|\s*and\s+)\s*true", # or true
        r"--",                        # SQL comment
        r";",                         # Query separator
        r"\b(union|select|insert|update|delete|drop|truncate|alter|exec)\b", # SQL commands
        r"(\b(like|glob|match)\b\s*['\"].*['\"])" # LIKE, GLOB, MATCH
    ]
    
    detections = []
    for pattern in patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            detections.append(pattern)
            
    return detections

# --- Streamlit App UI ---
st.set_page_config(layout="wide")
st.title("SQL Injection: Attack, Detection, and Prevention")
st.markdown("An educational app to demonstrate SQL injection vulnerabilities.")

# Use tabs to organize the application
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "Database Viewer", 
    "1. The Vulnerable Attack", 
    "2. The Secure Fix (Prevention)", 
    "3. Attack Detection Scanner",
    "About This Project"
])

# --- Tab 1: Database Viewer ---
with tab1:
    st.header("Mock User Database")
    st.write("This is the data stored in our `users` table.")
    
    try:
        conn = get_db_conn()
        if conn:
            df = pd.read_sql_query("SELECT id, username, password, email, role FROM users", conn)
            st.dataframe(df, use_container_width=True)
            conn.close()
    except Exception as e:
        st.error(f"Could not load database: {e}")

# --- Tab 2: The Vulnerable Attack ---
with tab2:
    st.header("Vulnerable Login (The Attack)")
    st.warning("This login form is **INTENTIONALLY VULNERABLE** to SQL Injection.")
    
    with st.form("vulnerable_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        
    if submitted:
        if not username or not password:
            st.error("Please enter both username and password.")
        else:
            st.write("---")
            st.subheader("Attack Result")
            
            # This is the VULNERABLE part: directly formatting a string
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            
            st.markdown("**Query Sent to Database:**")
            st.code(query, language="sql")
            
            try:
                conn = get_db_conn()
                if conn:
                    cursor = conn.cursor()
                    # We execute the dynamically (and unsafely) built query
                    cursor.execute(query)
                    user = cursor.fetchone()
                    conn.close()
                    
                    if user:
                        st.success(f"**Login Successful!** Welcome, {user[1]} (Role: {user[4]})")
                        st.write("The database found a matching record and logged you in.")
                    else:
                        st.error("**Login Failed.** No user found with those credentials.")
                
            except sqlite3.Error as e:
                st.error(f"An error occurred: {e}")
                st.info("This error itself can leak information about the database structure!")

    st.write("---")
    st.subheader("Try the Attack")
    st.markdown("""
    To see the vulnerability, try entering the following in the **Username** field and *anything* in the Password field:
    
    `' OR '1'='1' --`
    
    **What this does:**
    * `'` closes the opening quote for the username.
    * `OR '1'='1'` changes the logic: "find a user where username is... OR where 1 equals 1". Since 1 always equals 1, this is *always true*.
    * `--` is a SQL comment. It tells the database to ignore the rest of the query (including the part that checks the password).
    
    The database will execute the query, find the *first user in the table* (since `'1'='1'` is true for every row), and log you in as them.
    """)

# --- Tab 3: The Secure Fix (Prevention) ---
with tab3:
    st.header("Secure Login (The Fix)")
    st.success("This login form is **SECURE** and uses Parameterized Queries.")
    
    with st.form("secure_form"):
        username_s = st.text_input("Username")
        password_s = st.text_input("Password", type="password")
        submitted_s = st.form_submit_button("Login")
        
    if submitted_s:
        if not username_s or not password_s:
            st.error("Please enter both username and password.")
        else:
            st.write("---")
            st.subheader("Secure Result")
            
            # This is the SECURE part: using parameters (?)
            query = "SELECT * FROM users WHERE username = ? AND password = ?"
            
            st.markdown("**Query Template Sent to Database:**")
            st.code(query, language="sql")
            st.markdown(f"**Data Sent Separately:** `({username_s}, {password_s})`")
            
            try:
                conn = get_db_conn()
                if conn:
                    cursor = conn.cursor()
                    # The database engine safely inserts the data into the query
                    cursor.execute(query, (username_s, password_s))
                    user = cursor.fetchone()
                    conn.close()
                    
                    if user:
                        st.success(f"**Login Successful!** Welcome, {user[1]} (Role: {user[4]})")
                    else:
                        st.error("**Login Failed.** No user found with those credentials.")
                
            except sqlite3.Error as e:
                st.error(f"An error occurred: {e}")

    st.write("---")
    st.subheader("Try the *Same* Attack")
    st.markdown(f"""
    Now, try the same attack string in the **Username** field:
    
    `' OR '1'='1' --`
    
    **What happens now:**
    The login will **fail**. 
    
    **Why?**
    With parameterized queries, the database doesn't mix commands and data. It receives the command (`SELECT ... WHERE username = ?`) and the data (`' OR '1'='1' --`) separately.
    
    It then *safely* searches for a user whose literal username is `' OR '1'='1' --`. Since no such user exists, the login fails. The attack string is never executed as a command.
    """)

# --- Tab 4: Attack Detection Scanner ---
with tab4:
    st.header("Simple SQLi Pattern Scanner")
    st.info("This tool scans text for common SQLi patterns. This is a simplified example of what a Web Application Firewall (WAF) might do.")
    
    input_text = st.text_area("Enter text to scan:", height=150)
    
    if st.button("Scan Text"):
        if not input_text:
            st.warning("Please enter some text to scan.")
        else:
            detections = detect_sqli(input_text)
            
            if detections:
                st.error("**Potential SQLi Detected!**")
                st.write("The following suspicious patterns were found:")
                for d in detections:
                    st.code(d, language="regex")
            else:
                st.success("**No SQLi Patterns Detected.**")

# --- Tab 5: About ---
with tab5:
    st.header("About This Project")
    st.markdown("""
    This application is an educational tool designed to provide a hands-on demonstration of:
    
    1.  **SQL Injection (SQLi) Vulnerabilities:** How they occur when user input is insecurely added to a database query.
    2.  **SQLi Detection:** A basic look at how security tools can scan for malicious patterns.
    3.  **SQLi Prevention:** The correct, secure method of handling user data using **Parameterized Queries** (also known as Prepared Statements).
    
    ### Key Takeaway
    
    **NEVER** build queries by formatting strings with user input. **ALWAYS** use parameterized queries provided by your database library (like the `?` placeholder in Python's `sqlite3`).
    
    This simple practice is the single most effective way to prevent SQL injection attacks.
    """)
