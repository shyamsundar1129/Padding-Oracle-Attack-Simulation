import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class VulnerableServer:
    def __init__(self):
        # 1. The Secret Key
        # The server generates a random 16-byte (128-bit) AES key. 
        # In a real scenario, this is locked on the server. The attacker NEVER sees it.
        self.key = os.urandom(16)
        
    def encrypt_message(self, plaintext_bytes):
        """Encrypts a message using AES-CBC and PKCS#7 Padding."""
        
        # 2. The Padding (PKCS#7)
        # AES needs blocks of exactly 16 bytes (128 bits). 
        # This padder fills any empty space according to the PKCS#7 rules.
        padder = padding.PKCS7(128).padder() 
        padded_data = padder.update(plaintext_bytes) + padder.finalize()
        
        # 3. The Initialization Vector (IV)
        # CBC mode needs a random 16-byte block to start the chaining process.
        iv = os.urandom(16)
        
        # 4. The Encryption (AES-CBC)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # We return the IV attached to the front of the ciphertext. 
        # An attacker intercepting network traffic would be able to see this.
        return iv + ciphertext
        
    def padding_oracle(self, iv_and_ciphertext):
        """The Vulnerable Function: Returns True if padding is valid, False if invalid."""
        
        # Separate the IV (first 16 bytes) from the actual ciphertext
        iv = iv_and_ciphertext[:16]
        ciphertext = iv_and_ciphertext[16:]
        
        # Decrypt the ciphertext back into padded plaintext
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # 5. THE FATAL FLAW (The Side-Channel Leak)
        unpadder = padding.PKCS7(128).unpadder()
        try:
            # The server tries to remove the padding.
            unpadded_data = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            # If no error occurs, the padding was perfectly valid!
            return True 
            
        except ValueError:
            # If the padding was mangled, the cryptography library throws a 'ValueError'.
            # By returning 'False' here, the server accidentally leaks crucial mathematical 
            # information to the attacker.
            return False

if __name__ == "__main__":
    # Start the server
    server = VulnerableServer()
    
    # Define a secret message
    secret_message = b"This is a top secret message for the professor!"
    
    # The server encrypts the message
    intercepted_data = server.encrypt_message(secret_message)
    print(f"Intercepted Encrypted Data: {intercepted_data.hex()}")
    
    # Test the Oracle with the perfectly valid, untouched intercepted data
    valid_test = server.padding_oracle(intercepted_data)
    print(f"Oracle Response to untouched data: {valid_test} (Should be True)")
    
    # Test the Oracle by corrupting just ONE byte of the intercepted data
    # We change the last byte by XORing it with 1
    corrupted_data = bytearray(intercepted_data)
    corrupted_data[-1] ^= 1 
    
    invalid_test = server.padding_oracle(bytes(corrupted_data))
    print(f"Oracle Response to corrupted data: {invalid_test} (Should be False)")