<div align="center">

# 🔐 RSA Encryption Tool

**A premium desktop application for RSA key management, encryption & decryption — built with Python and Tkinter.**

![Python](https://img.shields.io/badge/Python-3.10%2B-4F6EF7?style=for-the-badge&logo=python&logoColor=white)
![Cryptography](https://img.shields.io/badge/Cryptography-46.0.5-7C3AED?style=for-the-badge&logo=letsencrypt&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-F59E0B?style=for-the-badge)

</div>

---

## ✨ Features

| Category | Details |
|---|---|
| 🔑 **Key Generation** | 1024-bit, 2048-bit, and 4096-bit RSA key pairs |
| 🔒 **Encryption** | OAEP-SHA256 padding — secure against chosen-ciphertext attacks |
| 🔓 **Decryption** | Multi-chunk decryption for messages of any length |
| 💾 **Key Export** | Export public & private keys as standard `.pem` files |
| 📂 **Key Import** | Import `.pem` files or paste raw PEM content directly |
| 📋 **Clipboard** | One-click copy for keys and ciphertext |
| 🔏 **Password Protection** | Optional AES-encrypted private key storage |
| 🛡️ **Key Fingerprint** | SHA-256 fingerprint and modulus preview for key verification |
| 🌑 **Dark Mode UI** | Premium dark theme with smooth hover animations |

---

## 📸 Interface Overview

The app is organized into **4 tabs**:

```
┌──────────────────────────────────────────────────────────────┐
│  🔐 RSA Encryption Tool    OAEP-SHA256 · PEM · Multi-chunk  │
├──────────────────┬──────────────┬──────────────┬────────────┤
│  🔑 Key Manager  │  🔒 Encrypt  │  🔓 Decrypt  │  ℹ️ Info   │
├──────────────────┴──────────────┴──────────────┴────────────┤
│                                                              │
│   [ Generate New RSA Key Pair ]                              │
│   Key Size: ○ 1024-bit  ● 2048-bit  ○ 4096-bit              │
│   Private Key Password (optional): ••••••••                  │
│   [ ⚙ Generate Key Pair ]                                   │
│                                                              │
│   [ Export & Import buttons ]                                │
│   [ Key Preview area ]                                       │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/TheRaven815/rsa_encryption.git
cd rsa_encryption
```

### 2. Create a Virtual Environment (Recommended)

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Application

```bash
python rsa_app.py
```

---

## 📦 Dependencies

| Package | Version | Purpose |
|---|---|---|
| `cryptography` | 46.0.5 | RSA key generation, OAEP encryption/decryption, PEM serialization |
| `cffi` | 2.0.0 | C Foreign Function Interface (required by cryptography) |
| `pycparser` | 3.0 | C code parser (required by cffi) |
| `pillow` | 12.1.1 | Image processing support |

> **Note:** `tkinter` is included with Python's standard library — no separate install needed.

---

## 🛡️ Security Details

### Encryption Scheme
This tool uses **RSA-OAEP** (Optimal Asymmetric Encryption Padding) with **SHA-256** as both the hash and MGF1 algorithm. This is the modern, recommended standard for RSA encryption and provides:

- ✅ Semantic security (same plaintext → different ciphertext each time)
- ✅ Protection against chosen-ciphertext attacks
- ✅ Compliance with PKCS#1 v2.2 / RFC 8017

### Multi-chunk Encryption
RSA has a hard limit on how much data can be encrypted at once (determined by key size and padding overhead). This tool automatically **splits long messages into chunks** and encrypts each one independently, allowing messages of **arbitrary length** to be encrypted.

| Key Size | Max Chunk Size |
|---|---|
| 1024-bit | ~62 bytes |
| 2048-bit | ~190 bytes |
| 4096-bit | ~446 bytes |

The chunks are then serialized with a custom binary format (4-byte count header + length-prefixed blocks) and encoded as **Base64** for safe text transport.

### Key Storage
- Private keys can optionally be **AES-encrypted with a user-provided password** (`BestAvailableEncryption`)
- Keys are exported in the standard **PEM / TraditionalOpenSSL** format, compatible with OpenSSL, SSH tools, and most libraries
- SHA-256 **fingerprinting** lets you verify key identity without exposing the full key

---

## 🗂️ Project Structure

```
rsa_encryption/
│
├── rsa_app.py          # Main application (single-file, ~700 lines)
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

---

## 🖥️ Usage Guide

### Generating a Key Pair
1. Open the **🔑 Key Management** tab
2. Select a key size (2048-bit recommended for general use, 4096-bit for maximum security)
3. Optionally enter a password to encrypt the private key
4. Click **⚙ Generate Key Pair** — generation runs in a background thread so the UI stays responsive
5. Keys appear in the **Key Preview** panel below

### Encrypting a Message
1. Make sure a key pair (or at least a public key) is loaded — check the badge in the top-right corner
2. Go to the **🔒 Encrypt** tab
3. Type or paste your plaintext message
4. Click **🔒 Encrypt Message**
5. The Base64-encoded ciphertext appears below — copy it with the **📋 Copy Ciphertext** button

### Decrypting a Message
1. Make sure the **private key** is loaded (badge shows **🔐 Key Pair Loaded**)
2. Go to the **🔓 Decrypt** tab
3. Paste the Base64 ciphertext
4. Click **🔓 Decrypt Message**
5. The original plaintext is recovered in the output panel

### Importing External Keys
You can import keys generated by other tools (e.g., OpenSSL):
```bash
# Generate a key with OpenSSL
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem
```
Then use **📂 Import Public Key** / **📂 Import Private Key** in the app.

---

## 🎨 Design & UI

The interface is built with pure **Tkinter** — no external UI frameworks required. The design features:

- 🌑 Deep dark color palette (`#0D0F14` background)
- 💜 Indigo/violet accent colors (`#4F6EF7`, `#7C3AED`)
- 🟢 Color-coded status indicators (green = success, red = error, amber = warning)
- ✨ Hover animations on all interactive buttons
- 📟 Monospace font (`Consolas`) for all cryptographic content
- 📊 Animated status bar with live feedback

---

## ⚠️ Disclaimer

This tool is intended for **educational and personal use**. While the underlying cryptographic primitives (`cryptography` library, OAEP-SHA256) are production-grade, the application itself has **not been audited for production security use cases**.

- Do **not** use this tool to protect classified or highly sensitive data in professional environments
- Always keep your **private key and its password** in a safe place — there is no recovery mechanism
- The ciphertext format is **custom / non-standard** and is only compatible with this tool

---

## 📄 License

This project is licensed under the **MIT License** — feel free to use, modify, and distribute.

---

<div align="center">

Made with 🔐 and Python

</div>
