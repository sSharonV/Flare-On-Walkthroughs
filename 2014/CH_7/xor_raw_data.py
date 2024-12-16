import os
from itertools import product

# Define the byte array (random data to XOR)
RANDOM_DATA = b"\x5D\x16\x90\x47\x04\x56\x5E\x49\x24\x19\x5B\x6C\xD7\xC1\x67\x69\xA7\x45\x32\x19\x2F\x4E\x69\x77\x09\x52\x01\x73\x64\x4C\x16\x7F\x5C\x0F\x00\x0A\x19\x21\x11\x3A\x32\x51\x7A\x2A\x14\x5C\x6D\x3D\x48\x45\x66\x6E\x79\x36\x13\x51\x72\x5D\x47\x03\xC0\x16\x73\x6A"

# Define XOR keys for each function
XOR_KEYS = {
    "ChkDebugged": ["the final countdown", "oh happy dayz"],
    "CheckPEB_BeingDebugged": ["UNACCEPTABLE!", "omglob"],
    "ChkSIDT_Vmware": ["you're so good", "you're so bad"],
    "ChkVMX_IO_Port": [b"\x66", b"\x01"],
    "ChkOutput_Debug_Str": ["I'm gonna sandbox your face", "Sandboxes are fun to play in"],
    "ChkSoftware_Breakpoints": ["Such fire. Much burn. Wow.", "I can haz decode?"],
    "ChkNtGlobalFlags_Debugged": [b"\x09\x00\x00\x01", "Feel the sting of the Monarch!"],
    "ChkTime_Friday": ["1337", "! 50 1337"],
    "ChkName_backdoge": ["LETS GO SHOPPING", "MATH IS HARD"],
    "ChkDebugged_DNS": ["LETS GO MATH", "SHOPPING IS HARD"],
    "ChkTime_5PM": [b"\x01\x02\x03\x05\x00\x78\x30\x38\x0d", b"\x07\x77"],
    "XorFullPath": [b"\x00", "backdoge.exe"],
    "ChkERoot_Servers": ["192.203.230.10", b"\x00"],
    "ChkTwitter_JackRAT": [b"\x00", "jackRAT"]
}

def xor_bytes(data, key):
    """XOR the given data with the key."""
    key = key.encode('latin-1') if isinstance(key, str) else key
    return bytes([byte ^ key[i % len(key)] for i, byte in enumerate(data)])

def brute_force_xor_combinations(data, keys):
    """Brute-force all key combinations and return valid ones that produce data starting with 'MZ'."""
    valid_combinations = []

    # Generate all possible key combinations using itertools.product
    key_combinations = product(*[keys[function] for function in keys])

    for combination in key_combinations:
        xored_data = data
        # Apply each key in the combination to the data
        for key in combination:
            xored_data = xor_bytes(xored_data, key)

        # Check if the result starts with the "MZ" header (Windows executable)
        if xored_data[:2] == b"MZ":
            valid_combinations.append((combination, xored_data))
            print(f"Valid combination found: {combination}")

    return valid_combinations

def xor_and_save_dumped_data(dumped_data_path, key_combination, output_index):
    """Read dumped data, XOR it with the key combination, and save the result."""
    with open(dumped_data_path, 'rb') as f:
        dumped_data = f.read()

    # XOR the dumped data with the key combination
    xored_data = dumped_data
    for key in key_combination:
        xored_data = xor_bytes(xored_data, key)

    # Save the XORed data to a file
    output_filename = f'xored_dumped_data_{output_index}.bin'
    with open(output_filename, 'wb') as f:
        f.write(xored_data)

    print(f"Saved XORed data as '{output_filename}'")

def main():
    """Main function to find valid key combinations and save the XORed dumped data."""
    # Step 1: Brute-force the XOR combinations with the random data
    valid_combinations = brute_force_xor_combinations(RANDOM_DATA, XOR_KEYS)

    # Step 2: For each valid key combination, XOR the dumped data and save it
    if valid_combinations:
        dumped_data_path = 'dumped_data_latest.bin'  # Path to your dumped data file
        for idx, (key_combination, _) in enumerate(valid_combinations, start=1):
            xor_and_save_dumped_data(dumped_data_path, key_combination, idx)
    else:
        print("No valid XOR key combinations found.")

if __name__ == "__main__":
    main()


