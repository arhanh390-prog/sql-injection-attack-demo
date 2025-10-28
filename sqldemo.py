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
tab1, tab_simple_attack, tab2, tab3, tab4, tab5 = st.tabs([
    "1. Database Viewer",
    "2. The Simplest Attack (1 Field)", # <-- NEW SIMPLIFIED TAB
    "3. Vulnerable Login Attack (2 Fields)",
    "4. The Secure Fix (Prevention)", 
    "5. Attack Detection Scanner",
    "About This Project"
])

# --- Tab 1: Database Viewer ---
with tab1:
    st.header("Mock User Database")
    st.write("This is the data stored in our `users` table. The attacker wants to see all of this.")
    
    try:
        conn = get_db_conn()
        if conn:
            df = pd.read_sql_query("SELECT id, username, password, email, role FROM users", conn)
            st.dataframe(df, use_container_width=True)
            conn.close()
    except Exception as e:
        st.error(f"Could not load database: {e}")

# --- NEW TAB: The Simplest Attack (1 Field) ---
with tab_simple_attack:
    st.header("The Simplest Attack (The 'Mad Libs' Demo)")
    st.warning("This search box is **INTENTIONALLY VULNERABLE**.")
    
    st.markdown("""
    Think of this as a "fill-in-the-blank" game. The app has a template:
    
    `SELECT * FROM users WHERE username = '` **...USER INPUT GOES HERE...** `'`
    
    A normal user just fills the blank. An attacker breaks the sentence.
    """)

    username_search = st.text_input("Search for a username:")
    
    if username_search:
        st.write("---")
        st.subheader("Attack Result")
        
        # This is the VULNERABLE part: directly formatting a string
        query = f"SELECT * FROM users WHERE username = '{username_search}'"
        
        st.markdown("**Final Query Sent to Database:**")
        st.code(query, language="sql")
        
        try:
            conn = get_db_conn()
            if conn:
                df = pd.read_sql_query(query, conn)
                conn.close()
                
                if not df.empty:
                    st.success(f"Found {len(df)} user(s):")
                    st.dataframe(df, use_container_width=True)
                else:
                    st.error("No user found with that exact name.")
            
        except sqlite3.Error as e:
            st.error(f"An error occurred: {e}")

    st.write("---")
    st.subheader("Try the Attack")
    st.markdown("""
    **1. Normal Search:** Type `user3` in the box and see what happens. The query becomes `...WHERE username = 'user3'` and finds 1 user.
    
    **2. The Attack:** Now, copy and paste this into the box:
    
    `' OR 1=1 --`
    
    **What this does:**
    * `'` : This first quote **closes the blank** (the username text).
    * `OR 1=1` : This **adds a new command** that is *always true*.
    * `--` : This **comments out** the rest of the app's original command, preventing errors.
    
    The final query becomes: `SELECT * FROM users WHERE username = '' OR 1=1 --'`
    
    The database runs this and thinks you're asking: "Show me users where the username is empty... **OR where 1 equals 1**." Since 1 always equals 1, it returns **all 20 users**. You've dumped the entire table!
    """)

# --- Tab 2: The Vulnerable Login Attack ---
with tab2:
    st.header("Vulnerable Login (The 2-Field Attack)")
    st.warning("This login form is also **INTENTIONALLY VULNERABLE**.")
    
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
    st.subheader("Try the Login Attack")
    st.markdown("""
    This is the same concept, but it bypasses the password check. Enter this in the **Username** field and *anything* in the Password field:
    
    `' OR '1'='1' --`
    
    The query becomes:
    `SELECT * FROM users WHERE username = '' OR '1'='1' --' AND password = '...password...'`
    
    The `--` comments out the *entire password check*, so the database just runs `...WHERE username = '' OR '1'='1'`. This is true for `user1`, so it logs you in as an admin.
    """)

# --- Tab 3: The Secure Fix (Prevention) ---
with tab3:
    st.header("Secure Login (The Fix)")
    st.success("This login form is **SECURE** and uses Parameterized Queries.")
    
    st.markdown("""
    This is the **correct** way. We again use a "fill-in-the-blanks" template, but this time, we send the template and the user's answers to the database **separately**.
    
    **Template:** `SELECT * FROM users WHERE username = ? AND password = ?`
    **Data:** `('user_input', 'pass_input')`
    
    The database *knows* the data is just data, not a command. It *never* lets the user's input change the sentence structure.
    """)

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
    
    **It will fail.**
    
    The database *knows* this is not a command. It *literally* searches for a user whose name is the 14-character string `' OR '1'='1' --`.
    
    Since no user has that name, the login correctly fails. This is called **input sanitization** and **parameterized queries**, and it's the #1 defense.
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

