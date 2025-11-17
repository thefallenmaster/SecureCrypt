# 🔐 SecureCrypt
### **Advanced Text Encryption & Decryption Tool (Java Swing)**

SecureCrypt is a lightweight yet powerful desktop application that provides fast and reliable text encryption and decryption using both classical and modern cryptographic algorithms. Designed with a clean UI and secure AES-based password protection, it is ideal for students, developers, and anyone who works with sensitive text data.



## 🚀 Features
- **Multiple Algorithms Supported**
  - Caesar Cipher  
  - Base64  
  - AES (GCM)  
  - Reverse Text  
  - ROT13  
  - XOR Cipher  
  - Atbash Cipher  
  - Vigenere Cipher  
  - Hex Encode / Decode  
  - Substitution Cipher  

- **Master Password Protection**
  - Optional AES-256 encryption layer  
  - Password-derived key using SHA-256  
  - Secure IV generation  

- **Modern UI**
  - Gradient background  
  - Clean, simple interface  
  - Titled input/output panels  
  - Dark/Light friendly design  

- **File Tools**
  - Save input/output to file  
  - Load text from file  
  - Integrated About window  



## 📦 Installation & Usage
1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/SecureCrypt.git
   ```
2. **Compile**
   ```bash
   javac EncryptionApp.java
   ```
3. **Run**
   ```bash
   java EncryptionApp
   ```



## 🧩 How It Works
1. Enter text into **Input Text**  
2. Select an **Encryption Algorithm**  
3. (Optional) Enter a **Master Password**  
4. Click **Encrypt** or **Decrypt**  
5. Output appears instantly in the **Output Text** panel  

## Screenshot
 
 

## 🛠 Built With
- Java 8+  
- Java Swing  
- AES/GCM Encryption  
- SecureRandom + SHA-256  
- Base64 Encoding  



## 🔒 Security Notes
- AES encryption uses **GCM mode** for authenticated encryption.  
- Password protection uses **SHA-256–derived keys**.  
- IVs are securely generated each time.  



## 📄 License
**MIT License** – Free to modify and use.
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)



## 👤 Author
**Gauthambala**  
Passionate about secure, user-friendly applications.
