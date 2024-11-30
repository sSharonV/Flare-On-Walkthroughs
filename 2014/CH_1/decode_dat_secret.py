import os

def transform_bytes(dat_secret):
    """
    Transform the byte data as per the original C# code logic.
    This function performs bit-shifting and XOR operations on each byte.
    
    :param dat_secret: List of bytes (binary data) to be transformed
    :return: Transformed string after the bitwise operations
    """
    transformed_text = ''
    for byte in dat_secret:
        # Perform bitwise operations: shift and XOR with 41
        transformed_char = chr((byte >> 4 | (byte << 4 & 0xF0)) ^ 41)
        transformed_text += transformed_char
    
    print("After transforming bytes:", repr(transformed_text))  # Debug: print intermediate result
    return transformed_text


def reverse_pairs(text):
    """
    Reverse every adjacent pair of characters in the text.
    
    :param text: The string whose characters' pairs need to be reversed
    :return: New string with reversed adjacent character pairs
    """
    reversed_text = ""
    for i in range(0, len(text) - 1, 2):
        reversed_text += text[i + 1] + text[i]
    
    print("After reversing character pairs:", repr(reversed_text))  # Debug: print intermediate result
    return reversed_text


def xor_with_102(text):
    """
    XOR each character in the string with 102 (0x66) to further decode the data.
    
    :param text: The string to apply XOR with 102
    :return: New string after XOR operation
    """
    xor_text = ""
    for char in text:
        xor_text += chr(ord(char) ^ 102)
    
    print("After XORing with 102:", repr(xor_text))  # Debug: print intermediate result
    return xor_text


def to_ascii_string(decoded_text):
    """
    Convert the decoded text to a human-readable ASCII string,
    replacing non-printable characters with a dot ('.').
    
    :param decoded_text: The string to be converted to ASCII
    :return: ASCII string with non-printable characters replaced by dots
    """
    ascii_string = ''.join([char if 32 <= ord(char) <= 126 else '.' for char in decoded_text])
    return ascii_string


def decode_secret_from_file(file_path):
    """
    Decode the secret message from a given file.
    This function reads the binary data, applies the decoding logic, and returns the final decoded message.
    
    :param file_path: Path to the file containing the encoded binary data
    :return: Decoded ASCII message as a string
    """
    # Ensure the file exists before attempting to open it
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The file '{file_path}' does not exist.")
    
    try:
        with open(file_path, 'rb') as file:
            dat_secret = file.read()
    except Exception as e:
        raise IOError(f"Error reading the file '{file_path}': {e}")
    
    # Apply the transformation steps
    transformed_text = transform_bytes(dat_secret)
    
    # Null-terminate the string (like '\0' in C#)
    transformed_text += "\0"
    
    reversed_text = reverse_pairs(transformed_text)
    xor_text = xor_with_102(reversed_text)
    
    # Convert the final decoded text to ASCII
    decoded_message = to_ascii_string(xor_text)
    
    return decoded_message


# Main script execution
if __name__ == "__main__":
    # Specify the path to your file (replace with actual file path)
    file_path = "rev_challenge_1.dat_secret.encode"
    
    try:
        # Decode the secret from the file and print the ASCII string
        decoded_message = decode_secret_from_file(file_path)
        
        # Output the final decoded message in ASCII
        print("Final Decoded ASCII Message:", decoded_message)
    
    except (FileNotFoundError, IOError) as e:
        # Handle errors gracefully and print a user-friendly message
        print(f"Error: {e}")
