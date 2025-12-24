CryptiVault-Python

A command-line based security tool developed in Python. This application allows users to store, generate, and manage credentials using industry-standard cryptographic hashing and encryption techniques.

## 📌 Features

* **Secure Authentication:** Main password protection using `bcrypt` (salting & hashing).
* **AES Encryption:** End-to-end encryption/decryption of account passwords using `Fernet` symmetric keys.
* **Strength Validation:** Heuristic analysis to ensure passwords meet complexity standards.
* **Entropy Generator:** Built-in tool to generate high-entropy, random passwords.
* **Persistent Storage:** Data is stored in local JSON for portability.
* **Master Reset:** Built-in disaster recovery to wipe data and rotate keys.

## 🛠 Technologies Used

* **Language:** Python 3.x
* **Security:** `bcrypt`, `cryptography` (Fernet)
* **Data Handling:** `json`, `shlex`, `codecs`
* **Logic:** `random`, `string`



## 🚀 Getting Started

### 📦 Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/DeViKaanil62/CryptiVault-Python.git](https://github.com/DeViKaanil62/CryptiVault-Python.git)
   cd CryptiVault-Python

2. **Install dependencies:**
   ```bash
    pip install bcrypt cryptography

3. **Run the application:**
   ```bash
   python main.py
