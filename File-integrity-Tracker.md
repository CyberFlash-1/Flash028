## **File Integrity Tracker** 🔒

### **Overview**
The **File Integrity Tracker** is a Python-based tool designed to monitor files for unauthorized changes by comparing their cryptographic hashes over time. It ensures the integrity of critical files, making it an essential tool for cybersecurity professionals, system administrators, and developers.

---

### **Key Features**
- **Hash Calculation**:
  - Uses the **SHA-256** hashing algorithm to generate a unique fingerprint of the file.
  - Encodes the file in **Base64** before hashing to ensure compatibility with binary files.

- **Periodic Checks**:
  - Continuously monitors the file at a specified interval (default: 24 hours).
  - Alerts the user if the file has been modified.

- **Tamper Detection**:
  - Compares the current hash of the file with the original hash.
  - Prints a message if the file has been tampered with.

- **Customizable Interval**:
  - Allows users to specify the check interval (in seconds).

---

### **How It Works**
1. The program takes the file name as input.
2. It calculates the **SHA-256 hash** of the file after encoding it in **Base64**.
3. The program periodically re-calculates the hash and compares it to the original hash.
4. If the hashes differ, it prints a message indicating that the file has been modified.

---

### **Code**
Here’s the Python code for the **File Integrity Tracker**:

```python
import hashlib  # Importing hashlib module
import base64   # File must be encoded before hashing
import time     # For sleeping

file = input("Enter the file name: ")  # Taking file name as input

def hash_function(file):
    """Calculate the SHA-256 hash of a file."""
    filename = open(file, 'rb')  # Open the file in binary mode
    data = filename.read()       # Read the file
    base64_data = base64.b64encode(data)  # Encode the file in Base64
    SHA_256 = hashlib.sha256(base64_data).hexdigest()  # Hash the file
    return SHA_256

print("Initial hash:", hash_function(file))

# Check if the file has been tampered with
def file_check(file, interval=86400):  # Default interval: 24 hours (86400 seconds)
    original_hash = hash_function(file)  # Store the original hash
    while True:
        current_hash = hash_function(file)  # Calculate the current hash
        if original_hash != current_hash:
            print("File is modified!")
        else:
            print("File is not modified.")
        time.sleep(interval)  # Wait for the specified interval before checking again

file_check(file)
