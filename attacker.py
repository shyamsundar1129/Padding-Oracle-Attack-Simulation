from server import VulnerableServer
import time

class PaddingOracleAttacker:
    def __init__(self, oracle_function):
        # We pass the server's vulnerable function into our attacker
        self.oracle = oracle_function

    def split_into_blocks(self, data, block_size=16):
        """Helper function to chop data into 16-byte blocks."""
        return [data[i:i+block_size] for i in range(0, len(data), block_size)]

    def crack_single_block(self, prev_block, target_block):
        """Cracks a single 16-byte block by manipulating the previous block."""
        block_size = 16
        # This will store the hidden intermediate state of the decryption
        intermediate_state = bytearray(block_size)
        # This will store our successfully cracked plaintext characters
        cracked_plaintext = bytearray(block_size)

        # We must crack backwards! Start at byte 15, down to 0.
        for padding_length in range(1, block_size + 1):
            target_byte_index = block_size - padding_length
            
            # Step 1: Guess the byte from 0 to 255
            for guess in range(256):
                # Create a malicious version of the previous block
                malicious_prev_block = bytearray(16)
                
                # Setup the padding for the bytes we ALREADY cracked in this block
                # (e.g., if we are looking for padding 03 03 03, we must set the last two bytes to 03)
                for i in range(block_size - 1, target_byte_index, -1):
                    malicious_prev_block[i] = intermediate_state[i] ^ padding_length
                
                # Inject our current guess into the target byte
                malicious_prev_block[target_byte_index] = guess
                
                # Send the malicious previous block + the untouched target block to the Oracle
                payload = bytes(malicious_prev_block) + target_block
                
                # Did the Oracle accept the padding?
                if self.oracle(payload):
                    # WE GOT A HIT! 
                    # Calculate the intermediate state for this byte
                    intermediate_state[target_byte_index] = guess ^ padding_length
                    
                    # Crack the actual plaintext byte using the original previous block
                    cracked_plaintext[target_byte_index] = intermediate_state[target_byte_index] ^ prev_block[target_byte_index]
                    
                    # We cracked this byte, break the 0-255 loop and move to the next byte
                    break
                    
        return bytes(cracked_plaintext)

    def execute_full_attack(self, intercepted_data):
        """Splits the intercepted message and cracks it block by block."""
        blocks = self.split_into_blocks(intercepted_data)
        full_plaintext = b""

        print(f"Intercepted {len(blocks)} blocks (including IV). Starting decryption...")
        
        # We start at index 1 because blocks[0] is the IV, which acts as the 'prev_block' for block[1]
        for i in range(1, len(blocks)):
            print(f"[*] Cracking Block {i}...")
            prev_block = blocks[i-1]
            target_block = blocks[i]
            
            cracked_block = self.crack_single_block(prev_block, target_block)
            full_plaintext += cracked_block
            print(f"    -> Block {i} decrypted: {cracked_block}")
            
        return full_plaintext


if __name__ == "__main__":
    print("\n" + "="*40)
    print("   PADDING ORACLE ATTACK SIMULATOR")
    print("="*40)
    
    # 1. Boot up the vulnerable server
    print("\n[*] Initializing Vulnerable Server...")
    time.sleep(1)
    server = VulnerableServer()
    
    # Feature 1: Live Interactive Input
    print("\n--- Encryption Mode ---")
    user_input = input("Enter a secret message for the server to encrypt: ")
    secret_message = user_input.encode('utf-8')
    
    print("\n[*] Server is encrypting via AES-CBC with PKCS#7 Padding...")
    time.sleep(1)
    intercepted_ciphertext = server.encrypt_message(secret_message)
    
    print(f"\n[!] NETWORK INTERCEPTION SUCCESSFUL")
    print(f"Target Ciphertext (Hex): {intercepted_ciphertext.hex()}")
    
    # Feature 4: Presentation Control Pause
    input("\nPress ENTER to launch the Padding Oracle Attack...")
    
    # Feature 2: The Analytics Tracker
    oracle_call_count = 0
    def tracked_oracle(payload):
        global oracle_call_count
        oracle_call_count += 1
        # Feature 3: Optional micro-delay for realistic network feel
        time.sleep(0.005) 
        return server.padding_oracle(payload)
    
    # Initialize attacker with our tracked oracle
    attacker = PaddingOracleAttacker(tracked_oracle)
    
    # Start the timer and execute!
    start_time = time.time()
    decrypted_result = attacker.execute_full_attack(intercepted_ciphertext)
    end_time = time.time()
    
    print("\n" + "="*40)
    print("   ATTACK COMPLETE")
    print("="*40)
    
    # Strip the PKCS#7 padding off the final result to make it readable
    pad_len = decrypted_result[-1]
    clean_plaintext = decrypted_result[:-pad_len]
    
    print(f"\n>> RECOVERED SECRET: {clean_plaintext.decode('utf-8')} <<")
    
    # Print the Data Analytics
    print(f"\n[Attack Analytics]")
    print(f"- Total Oracle Queries Sent: {oracle_call_count}")
    print(f"- Time Elapsed: {round(end_time - start_time, 2)} seconds")
    print("- Keys Cracked: 0 (Bypassed entirely via Side-Channel)")
    print("="*40 + "\n")