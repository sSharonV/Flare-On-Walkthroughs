# Function to convert the hex key into a list of byte values
def convert_key_to_bytes(key):
    """Convert hexadecimal string key to a list of byte values."""
    return [int(key[i:i+2], 16) for i in range(0, len(key), 2)]

# Function to initialize CPU registers (AX, BX, CX, DX)
def initialize_registers():
    """Initialize CPU-like registers for decryption."""
    AX = [0x01, 0xC7]  # AX = 0x01C7 (AH, AL)
    BX = [0, 0]        # BX = 0x0000
    CX = [0, 0x25]     # CX = 0x0025 (CL initialized to 0x25)
    DX = [0, 0]        # DX = 0x0000
    CF = 1             # Carry Flag
    KEY_XOR = 0xC7     # XOR key constant
    
    return AX, BX, CX, DX, CF, KEY_XOR

# Function to perform the decryption logic for each character
def decrypt_character(encrypted_char, AX, BX, CX, DX, CF, KEY_XOR):
    """Decrypt a single character using bitwise operations and CPU-like registers."""
    
    # Save BX into DX
    DX[0] = BX[0]
    DX[1] = BX[1]

    # Perform bitwise AND operation on DX[1] with 0x03
    DX[1] &= 0x03  # Only keep the lower 2 bits of DX[1]

    # Swap values of CX[1] and DX[1] (XCHG operation)
    TEMP_CL = CX[1]
    CX[1] = DX[1]
    DX[1] = TEMP_CL

    # Perform a left shift on AH (AX[0]) by the value in CL (CX[1])
    AX[0] <<= CX[1]

    # Subtract (CF + AH) from the encrypted character to get the AL value
    AX[1] = encrypted_char - (CF + AX[0])

    # Apply the XOR operation with the KEY_XOR value to AL (AX[1])
    AX[1] ^= KEY_XOR

    # Swap values of CX[1] and DX[1] again
    TEMP_CL = CX[1]
    CX[1] = DX[1]
    DX[1] = TEMP_CL

    # Reset DX to 0
    DX = [0, 0]

    # Combine BX[0] and BX[1] to form a 16-bit value
    BX_value = (BX[0] << 8) | BX[1]

    # Add the current encrypted character to BX_value
    BX_value += encrypted_char

    # Split BX_value back into two bytes and store them in BX
    BX[0] = (BX_value >> 8) & 0xFF  # Extract the high byte
    BX[1] = BX_value & 0xFF         # Extract the low byte

    # Decrease the value of CL (CX[1]) by 1
    CX[1] -= 1

    # Reset AX[0] to 0x01 after each iteration
    AX[0] = 0x01

    # Return the decrypted character
    return chr(AX[1]), AX, BX, CX, DX, CF

# Function to perform the decryption for the entire key
def decrypt_key(key):
    """Decrypt the entire key using the decryption logic and return the result as a string."""
    # Convert key to bytes
    key_bytes = convert_key_to_bytes(key)
    
    # Initialize registers
    AX, BX, CX, DX, CF, KEY_XOR = initialize_registers()

    # List to accumulate decrypted characters
    decrypted_chars = []

    # Decrypt each character in the key
    for encrypted_char in key_bytes:
        decrypted_char, AX, BX, CX, DX, CF = decrypt_character(encrypted_char, AX, BX, CX, DX, CF, KEY_XOR)
        decrypted_chars.append(decrypted_char)

    # Return the decrypted string
    return ''.join(decrypted_chars)

# Main function to run the decryption process
def main():
    # Define the hex key for decryption
    key = "A89A90B3B6BCB4AB9DAEF9B89DB8AFBAA5A5BA9ABCB0A7C08AAAAEAFBAA4ECAAAEEBADAAAFFF"
    
    # Perform decryption
    decrypted_string = decrypt_key(key)
    
    # Print the decrypted string
    print("Decrypted string:", decrypted_string)

# Run the main function
if __name__ == "__main__":
    main()
