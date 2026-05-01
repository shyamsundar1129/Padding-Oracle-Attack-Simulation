# Padding Oracle Attack on AES-CBC

## Project Overview
This project is a Python-based cryptographic simulation demonstrating a **Padding Oracle Side-Channel Attack**. It proves how deterministic cryptographic algorithms specifically the Advanced Encryption Standard (AES) operating in Cipher Block Chaining (CBC) mode can be entirely bypassed by exploiting boolean error-handling routines related to PKCS#7 padding.

## How It Works
The project consists of two core components:
1. **`server.py` (The Target):** A vulnerable server that encrypts data using a strict 128-bit AES key. It exposes a side-channel by returning `True` for valid PKCS#7 padding and `False` for invalid padding.
2. **`attacker.py` (The Exploit):** An automated algorithmic attacker that intercepts the ciphertext and systematically deduces the plaintext at an optimal $\mathcal{O}(N \times 256)$ time complexity, completely bypassing the need for the AES key.

## How to Run the Simulation
1. Clone this repository to your local machine.
2. Ensure you have the cryptography library installed: `pip install cryptography`
3. Execute the attacker script: `python attacker.py`
4. Enter a secret message when prompted and watch the algorithm decrypt the blocks via Oracle queries.

## Analytics & Efficiency
A brute-force attack on a 128-bit AES key requires $\mathcal{O}(2^{128})$ operations. By exploiting the mathematical properties of the XOR bit-flipping operation against the CBC intermediate state, this script cracks the ciphertext in a maximum of `4096` network requests per block.
