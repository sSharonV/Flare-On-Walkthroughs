def xor_hex_strings(hex1, hex2):
    """
    XOR two hex strings and return the result as a hex string.
    
    Args:
        hex1 (str): The first hex string.
        hex2 (str): The second hex string.
    
    Returns:
        str: The result of the XOR operation as a hex string.
    """
    # Convert hex strings to byte arrays
    bytes1 = bytes.fromhex(hex1)
    bytes2 = bytes.fromhex(hex2)
    
    # Perform XOR operation on each byte
    xored_bytes = bytearray(a ^ b for a, b in zip(bytes1, bytes2))
    
    # Return the result as a hex string
    return xored_bytes.hex()


def hex_to_ascii(hex_string):
    """
    Convert a hex string to its ASCII representation.
    
    Args:
        hex_string (str): The hex string to convert.
    
    Returns:
        str: The corresponding ASCII string.
    """
    return ''.join(chr(int(hex_string[i:i+2], 16)) for i in range(0, len(hex_string), 2))


def hex_pairs(hex_string):
    """
    Reverse the order of each pair of characters in a hex string.
    
    Args:
        hex_string (str): The hex string to reverse.
    
    Returns:
        str: The hex string with reversed byte pairs.
    """
    pairs = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
    return ''.join(pairs)


def process_hex_dumps(xor_keys, hex_dumps):
    """
    Process the XOR operation on hex dumps with corresponding XOR keys and convert results to ASCII.
    
    Args:
        xor_keys (list): A list of XOR keys.
        hex_dumps (dict): A dictionary of hex dumps with addresses as keys.
    
    Returns:
        dict: A dictionary of results with XORed ASCII values.
    """
    reversed_hex_dumps = [hex_pairs(val) for val in hex_dumps.values()]
    results = {}

    for key, hex_value in zip(xor_keys, reversed_hex_dumps):
        # XOR the hex values
        xored_hex = xor_hex_strings(key, hex_value)
        
        # Convert the XOR result to ASCII
        ascii_result = hex_to_ascii(xored_hex)
        
        # Print the XOR operation details
        print(f"XORing {key} with {hex_value} = {xored_hex} -> ASCII: {ascii_result}")
        
        # Store the result
        results[key] = ascii_result

    return results


def combine_results(results):
    """
    Combine the results into a single string by concatenating the ASCII results and reversing the final string.
    
    Args:
        results (dict): A dictionary of ASCII results from XOR operations.
    
    Returns:
        str: The final combined result, reversed.
    """
    res_str = ""
    for ascii_value in results.values():
        res_str += ascii_value  # Concatenate ASCII values
    
    # Reverse the final combined string
    return res_str[::-1]


# Example usage
if __name__ == "__main__":
    # Define the XOR keys and hex dumps
    xor_keys = [
        "32FBA316", "48CF45AE", "D29F3610", "0CA9A9F7", 
        "43A993BE", "3B628A82", "CCC047D6", "3154CAA3"
    ]
    
    hex_dumps = {
        "0Bh": "32BECE79",
        "17h": "2BE12BC1",
        "23h": "FFFA4471",
        "2Fh": "60CFE984",
        "3Bh": "3798A3D2",
        "47h": "4B11A4EF",
        "53h": "FFA469BE",
        "5Fh": "5265ABD4"
    }

    # Process the hex dumps with the XOR keys
    results = process_hex_dumps(xor_keys, hex_dumps)

    # Combine the results into a final string and reverse it
    final_result = combine_results(results)

    # Print the final reversed combined result
    print("\nFinal Reversed Combined Result:")
    print(final_result)
