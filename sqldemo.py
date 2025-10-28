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
        conn = sqlite3.connect(DB_NAME, check_same_thread=False) # Allow access from different threads
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
        # check_same_thread=False is needed for Streamlit's threading
        return sqlite3.connect(DB_NAME, check_same_thread=False)
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

# --- Helper for Visuals ---
def show_query_visual(template, user_input, is_vulnerable=True):
    """Visually shows how the query is constructed."""
    
    # Sanitize user_input for HTML display to prevent XSS in the demo
    import html
    safe_input = html.escape(user_input)
    
    if is_vulnerable:
        # Red for malicious input
        final_query = template.replace("...USER_INPUT...", f"<span style='color:#FF4B4B; font-weight:bold;'>{safe_input}</span>")
    else:
        # Blue for sanitized, safe data
        final_query = template.replace("?", f"<span style='color:#3D7BFF; font-weight:bold;'>'{safe_input}'</span>")

    st.markdown(f"**Query Template:**\n```sql\n{template}\n```")
    st.markdown(f"**User Input:**\n```\n{user_input}\n```")
    st.markdown(f"**Final Query Sent to Database:**")
    st.markdown(f"<pre style='background-color:#f0f2f6; padding:10px; border-radius:5px;'><code>{final_query}</code></pre>", unsafe_allow_html=True)


# --- Streamlit App UI ---
st.set_page_config(page_title="SQLi Demo", page_icon="🛡️", layout="wide")
st.title("🛡️ The Visual SQL Injection Demo")
st.markdown("An educational app to visually demonstrate SQL injection attacks and how to stop them.")

# Use tabs to organize the application
tab_db, tab_attack1, tab_attack2, tab_attack3, tab_fix, tab_detect, tab_summary = st.tabs([
    "1. The Database (Our Target) 🗃️",
    "2. Attack #1: The 'Bypass' 🔓",
    "3. Attack #2: The 'Data Theft' 📈",
    "4. Attack #3: The 'Login Bypass' 🔑",
    "5. The Secure Fix (The Shield) 🛡️", 
    "6. Detection (The Watchdog) 🐶",
    "7. Key Takeaways 🧠"
])

# --- Tab 1: Database Viewer ---
with tab_db:
    st.header("Mock User Database 🗃️")
    st.write("This is the data stored in our `users` table. In a real app, this would be secret. The attacker wants to steal this.")
    
    try:
        conn = get_db_conn()
        if conn:
            df = pd.read_sql_query("SELECT id, username, password, email, role FROM users", conn)
            st.dataframe(df, use_container_width=True)
            conn.close()
    except Exception as e:
        st.error(f"Could not load database: {e}")

# --- Tab 2: Attack #1: The 'Bypass' ---
with tab_attack1:
    st.header("Attack #1: The 'Mad Libs' Bypass 🔓")
    st.warning("This search box is **INTENTIONALLY VULNERABLE**.")
    
    st.markdown("""
    This is the simplest attack. The app insecurely builds a query by just "filling in the blank" with whatever you type.
    An attacker doesn't fill in the blank—they *change the sentence*.
    """)

    username_search_1 = st.text_input("Search for a username:", key="attack1_input")
    
    if username_search_1:
        st.write("---")
        st.subheader("Attack Result")
        
        template = "SELECT * FROM users WHERE username = '...USER_INPUT...'"
        query = f"SELECT * FROM users WHERE username = '{username_search_1}'"
        
        # Show the visual
        show_query_visual(template, username_search_1, is_vulnerable=True)
        
        try:
            conn = get_db_conn()
            if conn:
                df = pd.read_sql_query(query, conn)
                conn.close()
                
                if not df.empty:
                    st.success(f"**Attack Succeeded!** Found {len(df)} user(s):")
                    st.dataframe(df, use_container_width=True)
                else:
                    st.error("**Search Failed.** No user found with that exact name.")
            
        except sqlite3.Error as e:
            st.error(f"A database error occurred: {e}")

    st.write("---")
    st.subheader("Try the Attack")
    st.markdown("""
    **1. Normal Search:** Type `user3` and click Enter. The app finds 1 user.
    
    **2. The Attack:** Now, copy and paste this into the box:
    
    `' OR 1=1 --`
    
    **Why it works:**
    * `'` : This first quote **closes the blank** (the `username` field).
    * `OR 1=1` : This **adds a new rule** that is *always true*.
    * `--` : This **comments out** the rest of the query, ignoring the last `'` and preventing an error.
    
    The database runs `...WHERE username = '' OR 1=1 --` and returns **all 20 users** because `1=1` is always true.
    """)

# --- Tab 3: Attack #2: The 'Data Theft' (UNION) ---
with tab_attack2:
    st.header("Attack #2: The 'Data Theft' UNION Attack 📈")
    st.warning("This search box is also **INTENTIONALLY VULNERABLE**.")
    
    st.markdown("""
    This attack is more advanced. Instead of just bypassing a rule, the attacker uses `UNION` to **stitch their own fake data** onto the results.
    """)

    username_search_2 = st.text_input("Search for a username:", key="attack2_input")
    
    if username_search_2:
        st.write("---")
        st.subheader("Attack Result")
        
        template = "SELECT * FROM users WHERE username = '...USER_INPUT...'"
        query = f"SELECT * FROM users WHERE username = '{username_search_2}'"
        
        # Show the visual
        show_query_visual(template, username_search_2, is_vulnerable=True)
        
        try:
            conn = get_db_conn()
            if conn:
                df = pd.read_sql_query(query, conn)
                conn.close()
                
                if not df.empty:
                    st.success(f"**Attack Succeeded!** The query returned {len(df)} row(s):")
                    st.dataframe(df, use_container_width=True)
                else:
                    st.error("**Search Failed.** No user found with that exact name.")
            
        except sqlite3.Error as e:
            st.error(f"A database error occurred: {e}")

    st.write("---")
    st.subheader("Try the Attack")
    st.markdown("""
    **The Attack:** Copy and paste this into the box. It will *fail* to find a user but then *add its own user* to the results.
    
    `' UNION SELECT 100, 'hacked_user', 'pwned_pass', 'hacker@evil.com', 'admin' --`
    
    **Why it works:**
    * `'` : Closes the `username` field (which will fail to find a user).
    * `UNION SELECT ...` : This is the key. It tells the database to "also include the results from this *second* query."
    * `100, 'hacked_user', ...` : The attacker provides fake data for all 5 columns (`id`, `username`, `password`, `email`, `role`).
    
    You will see a table with **one user in it**—the fake one the attacker just created out of thin air! In a real attack, they could use this to steal data from other tables.
    """)

# --- Tab 4: Attack #3: The 'Login Bypass' ---
with tab_attack3:
    st.header("Attack #3: The Login Bypass 🔑")
    st.warning("This login form is also **INTENTIONALLY VULNERABLE**.")
    
    with st.form("vulnerable_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        
    if submitted:
        st.write("---")
        st.subheader("Attack Result")
        
        # This is the VULNERABLE part
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        st.markdown("**Query Sent to Database:**")
        st.code(query, language="sql")
        
        try:
            conn = get_db_conn()
            if conn:
                cursor = conn.cursor()
                cursor.execute(query)
                user = cursor.fetchone()
                conn.close()
                
                if user:
                    st.success(f"**Login Successful!** Welcome, **{user[1]} (Role: {user[4]})**")
                    if user[4] == 'admin':
                        st.balloons()
                        st.error("You've been logged in as an ADMIN!")
                else:
                    st.error("**Login Failed.** No user found.")
            
        except sqlite3.Error as e:
            st.error(f"An error occurred: {e}")

    st.write("---")
    st.subheader("Try the Login Attack")
    st.markdown("""
    This is the classic login bypass. Enter this in the **Username** field and *anything* in the Password field:
    
    `admin' --`
    
    **Why it works:**
    * `admin'` : It provides a real username (`admin`) and a quote to close the `username` field.
    * `--` : It comments out the *entire rest of the query*, including the part that checks the password!
    
    The final query becomes: `SELECT * FROM users WHERE username = 'admin' --' AND password = '...'`
    
    The database only runs `SELECT * FROM users WHERE username = 'admin'`, finds the admin user, and logs you in.
    """)

# --- Tab 5: The Secure Fix (Prevention) ---
with tab_fix:
    st.header("The Secure Fix: Parameterized Queries 🛡️")
    st.success("This search box is **SECURE** and defeats all the attacks.")
    
    st.markdown("""
    This is the **correct** way. We use a template with placeholders (`?`). We send the template and the user's input to the database **separately**.
    
    The database *knows* the user input is just data, not a command. It *never* lets the input change the query's structure.
    """)

    username_search_3 = st.text_input("Search for a username:", key="secure_input")
    
    if username_search_3:
        st.write("---")
        st.subheader("Secure Result")
        
        template = "SELECT * FROM users WHERE username = ?"
        
        # Show the "secure" visual
        show_query_visual(template, username_search_3, is_vulnerable=False)
        
        try:
            conn = get_db_conn()
            if conn:
                # This is the SECURE part: using parameters (?, (data,))
                df = pd.read_sql_query(template, conn, params=(username_search_3,))
                conn.close()
                
                if not df.empty:
                    st.success(f"Found {len(df)} user(s):")
                    st.dataframe(df, use_container_width=True)
                else:
                    st.error("**Search Failed.** No user found with that exact name.")
            
        except sqlite3.Error as e:
            st.error(f"An error occurred: {e}")

    st.write("---")
    st.subheader("Try the *Same* Attacks")
    st.markdown(f"""
    Now, try *any* of the previous attack strings in this **secure** box:
    
    1.  `' OR 1=1 --`
    2.  `' UNION SELECT ...`
    3.  `admin' --`
    
    **They will all fail.**
    
    The database doesn't run the malicious code. It *literally* searches for a user whose name is the weird string `' OR 1=1 --`.
    
    Since no user has that name, the search fails, and the application is safe. This is called **parameterization** and it's the #1 defense against SQLi.
    """)

# --- Tab 6: Attack Detection Scanner ---
with tab_detect:
    st.header("Simple SQLi Pattern Scanner 🐶")
    st.info("This tool scans text for common SQLi patterns. This is a simplified example of what a Web Application Firewall (WAF) might do.")
    
    input_text = st.text_area("Enter any text to scan:", height=150)
    
    if st.button("Scan Text"):
        if not input_text:
            st.warning("Please enter some text to scan.")
        else:
            detections = detect_sqli(input_text)
            
            if detections:
                st.error("**Potential SQLi Detected!**")
                st.write("The following suspicious patterns were found (using regular expressions):")
                for d in detections:
                    st.code(d, language="regex")
            else:
                st.success("**No SQLi Patterns Detected.**")

# --- Tab 7: Key Takeaways ---
with tab_summary:
    st.header("Key Takeaways 🧠")
    st.markdown("""
    This application demonstrated three key concepts:
    
    ### 1. The Vulnerability
    SQL Injection happens when an application **trusts user input** and mixes it directly with database commands.
    This is like a "Mad Libs" game where the user can write new rules instead of just filling in the blank.
    
    ### 2. The Attacks
    * **Bypass:** `OR 1=1` tricks the database into returning `TRUE` for every row.
    * **Data Theft:** `UNION SELECT` stitches malicious, fake data onto the real results.
    * **Logic Break:** `--` comments out the rest of the query, making the app skip important steps (like checking a password).
    
    ### 3. The Defense (The Most Important Part)
    **NEVER build queries by formatting strings.**
    
    **ALWAYS use Parameterized Queries (Prepared Statements).**
    
    Send your query template (e.g., `SELECT * FROM users WHERE username = ?`) and your data (e.g., `('admin' --)`) to the database **separately**. The database engine will handle the rest, ensuring your user's input is *never* treated as a command.
    """)

