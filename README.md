# 🔐 Advanced Secure Data Storage App

Welcome to the **Secure Data Storage App**, built with **Streamlit** and **Python Cryptography**, allowing users to:

✅ Register and log in securely  
🔐 Encrypt sensitive data with a custom key  
📦 Store encrypted data per user  
🔍 Decrypt previously stored data  
🔁 Reset passwords  
🔒 Lockout users after failed attempts for added security  

---

## 🧠 Features

- **Secure User Authentication**
  - PBKDF2-HMAC-SHA256 password hashing
  - Custom salting
  - Lockout after 3 failed login/decryption attempts

- **Data Encryption & Decryption**
  - Symmetric encryption using `cryptography.fernet`
  - Each user's data is encrypted using a unique key they provide

- **Persistent Storage**
  - Uses `JSON` files for user and data storage
  - Supports multiple encrypted entries per user

- **Streamlit UI**
  - Clean and interactive frontend
  - Sidebar navigation
  - Conditional rendering based on session

---

## 🧰 Tech Stack

- 🐍 Python 3.x  
- 📦 Streamlit  
- 🔐 Cryptography  
- 🧠 Hashlib  
- 📁 JSON  
- ⏱ Time, OS, Datetime  

---

## 🌐 Live App

🔗 **Deployed on Streamlit Cloud**:  
[https://secure-data-app.streamlit.app](https://pythonproject05.streamlit.app/)  

---

## 🧑‍💻 Developer Info

### 👨‍💻 Syed Shoaib Sherazi  
💼 Tech Explorer  

- 🔗 [LinkedIn](https://www.linkedin.com/in/syed-shoaib-sberazi/)  
- 💻 [GitHub](https://github.com/sherazi-412002)  

---

## ⭐ Like this Project?

If you found it useful or interesting, give it a ⭐ on GitHub and follow for more exciting projects!

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/secure-data-app.git
cd secure-data-app

