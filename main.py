
import streamlit as st
import json
import os
import time
import hashlib
from cryptography.fernet import Fernet
from datetime import datetime
from base64 import urlsafe_b64encode
import secrets

# Some constants 
DATA_FILE = "data_store.json"
USER_FILE = "users.json"
LOCKOUT_TIME = 60


### Helper functions 

# 1. For Hashing Password
def hash_passkey(passkey, salt=None):
    if not salt:
        salt = secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt, 100000)
    return urlsafe_b64encode(hashed).decode(), salt.hex()

# 2. Encrypted Passkey
def generate_key(passkey):
    key = hashlib.sha256(passkey.encode()).digest()
    return Fernet(urlsafe_b64encode(key))

# 3. Load json if exist other wise create
def load_json(filename):
    if not os.path.exists(filename):
        with open(filename, "w") as f:
            json.dump({}, f)
    with open(filename, "r") as f:
        return json.load(f)

# 4. Function to save Python data (dict) into a JSON file with indentation for readability.
def save_json(data, filename):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)


#  Auth Functions 
def login_user(username, password):
    if username in users:
        stored = users[username]
        hashed, _ = hash_passkey(password, bytes.fromhex(stored['salt']))
        if hashed == stored['password']:
            return True
    return False

def register_user(username, password):
    if username in users:
        return False
    hashed, salt = hash_passkey(password)
    users[username] = {"password": hashed, "salt": salt}
    save_json(users, USER_FILE)
    return True


###  Sessions

if 'user' not in st.session_state:
    st.session_state.user = None
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'lockout_until' not in st.session_state:
    st.session_state.lockout_until = None
if 'page' not in st.session_state:
    st.session_state.page = "Login"


###  Load Data
data_store = load_json(DATA_FILE)
users = load_json(USER_FILE)


### UI

# Header
st.title("🔐 Advanced Secure Data System")

menu = ["Login", "Sign Up", "Store Data", "Retrieve Data"]

# Sidebar
with st.sidebar:
    st.header("📋 Navigation")
    if st.session_state.user:
        st.markdown(f"👤 Logged in as: `{st.session_state.user}`")
        if st.button("🚪 Logout"):
            st.session_state.user = None
            st.session_state.page = "Login"
            st.rerun()

    choice = st.radio("Go to", menu, index=menu.index(st.session_state.page))
    if choice != st.session_state.page:
        st.session_state.page = choice
        st.rerun()
    st.markdown("---")
    st.markdown("---")
    st.header("🙌 About Developer")
    st.markdown("""
        #### 👨‍💻 **Syed Shoaib Sherazi**
        - 🔗 [LinkedIn](https://www.linkedin.com/in/syed-shoaib-sberazi/)
        - 💻 [GitHub](https://github.com/sherazi-412002)
        """)


### Logics for sessions

# --- Sign Up ---
if st.session_state.page == "Sign Up":
    st.subheader("🧾 Create a New Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Register"):
        if register_user(username, password):
            st.success("✅ Registered! Redirecting to Login...")
            time.sleep(1)
            st.session_state.page = "Login"
            st.rerun()
        else:
            st.error("🚫 Username already exists!")

    if st.button("🔐 Already have an account? Login"):
        st.session_state.page = "Login"
        st.rerun()


# --- Login ---
elif st.session_state.page == "Login":
    st.subheader("🔑 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if login_user(username, password):
            st.session_state.user = username
            st.session_state.failed_attempts = 0
            st.session_state.lockout_until = None
            st.success(f"✅ Welcome, {username}!")
            st.session_state.page = "Store Data"
            st.rerun()
        else:
            st.session_state.failed_attempts += 1
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_until = time.time() + LOCKOUT_TIME
            st.error("❌ Incorrect credentials!")

    with st.expander("🔁 Forgot Password?"):
        reset_username = st.text_input("Reset Username")
        new_pass = st.text_input("New Password", type="password")
        if st.button("Reset Password"):
            if reset_username in users:
                hashed, salt = hash_passkey(new_pass)
                users[reset_username] = {"password": hashed, "salt": salt}
                save_json(users, USER_FILE)
                st.success("✅ Password reset successfully!")
            else:
                st.error("❌ Username not found!")

    if st.button("🧾 Don't have an account? Sign Up"):
        st.session_state.page = "Sign Up"
        st.rerun()


# --- Store Data ---
elif st.session_state.page == "Store Data":
    if not st.session_state.user:
        st.warning("⚠️ Please login first.")
    else:
        st.subheader("📦 Store Encrypted Data")
        data = st.text_area("Enter Data")
        passkey = st.text_input("Encryption Key", type="password")
        if st.button("Encrypt & Save"):
            if data and passkey:
                hashed, salt = hash_passkey(passkey)
                cipher = generate_key(passkey + salt)
                encrypted = cipher.encrypt(data.encode()).decode()
                user_data = data_store.get(st.session_state.user, [])
                user_data.append({
                    "ciphertext": encrypted,
                    "salt": salt,
                    "timestamp": time.time()
                })
                data_store[st.session_state.user] = user_data
                save_json(data_store, DATA_FILE)
                st.success("✅ Data encrypted and saved!")
            else:
                st.error("⚠️ Fill in all fields!")


# --- Retrieve Data ---
elif st.session_state.page == "Retrieve Data":
    if not st.session_state.user:
        st.warning("⚠️ Please login to continue.")
    elif st.session_state.lockout_until and time.time() < st.session_state.lockout_until:
        wait = int(st.session_state.lockout_until - time.time())
        st.error(f"🔒 Locked! Try again in {wait} seconds.")
    else:
        st.subheader("🔍 Retrieve Encrypted Data")
        entries = data_store.get(st.session_state.user, [])
        if not entries:
            st.info("ℹ️ No encrypted entries found.")
        else:
            labels = [
                f"{i+1}. Stored at {datetime.fromtimestamp(item['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}"
                for i, item in enumerate(entries)
            ]
            idx = st.selectbox("Choose Entry", range(len(entries)), format_func=lambda i: labels[i])
            selected = entries[idx]

            passkey = st.text_input("Decryption Key", type="password")
            if st.button("Decrypt"):
                try:
                    salt = selected['salt']
                    full_key = generate_key(passkey + salt)
                    decrypted = full_key.decrypt(selected['ciphertext'].encode()).decode()
                    st.success(f"✅ Decrypted:\n\n{decrypted}")
                    st.session_state.failed_attempts = 0
                except Exception:
                    st.session_state.failed_attempts += 1
                    remaining = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect key! {remaining} attempts left.")
                    if st.session_state.failed_attempts >= 3:
                        st.session_state.lockout_until = time.time() + LOCKOUT_TIME
                        st.warning("🔒 Too many failed attempts! Locked.")




