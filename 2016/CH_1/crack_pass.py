# The byte_1E3000 array as provided
byte_1E3000 = [
    0x5A, 0x59, 0x58, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x7A, 0x79, 0x78, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 
    0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x30, 0x31, 0x32, 0x33, 0x34, 
    0x35, 0x36, 0x37, 0x38, 0x39, 0x2B, 0x2F
]

# Decryption function using the given register names EAX, ECX, EDX
def decrypt(Str2):
    input_str = []
    output_cnt = 0
    
    # Start processing the encrypted string in chunks of 4 characters
    while output_cnt < len(Str2):
        # Init: Extract 4 characters (corresponding to tmp_2, tmp_4, tmp_6, tmp_8 in the original pseudocode)
        tmp_2 = Str2[output_cnt]
        tmp_4 = Str2[output_cnt + 1]
        tmp_6 = Str2[output_cnt + 2]
        tmp_8 = Str2[output_cnt + 3]

        # Process: Find the index of each character in byte_1E3000 (equivalent to using `EAX`, `EDX`, `ECX` in your pseudocode)
        EAX = byte_1E3000.index(ord(tmp_2))  # tmp_2 -> EAX
        ECX = byte_1E3000.index(ord(tmp_4))  # tmp_4 -> ECX
        EDX = byte_1E3000.index(ord(tmp_6))  # tmp_6 -> EDX
        tmp_8_index = byte_1E3000.index(ord(tmp_8))  # tmp_8 -> tmp_8_index

        # Rebuild the 24-bit value tmp_246 (equivalent to combining EAX, ECX, EDX as in the pseudocode)
        tmp_246 = (EAX << 18) + (ECX << 12) + (EDX << 6) + tmp_8_index
        
        # Extract the original bytes (equivalent to tmp_2, tmp_4, tmp_6 in the pseudocode)
        tmp_2 = (tmp_246 >> 16) & 0xFF  # Extract the first byte
        tmp_4 = (tmp_246 >> 8) & 0xFF   # Extract the second byte
        tmp_6 = tmp_246 & 0xFF          # Extract the third byte

        # Append the decoded bytes to the input string
        input_str.append(chr(tmp_2))
        input_str.append(chr(tmp_4))
        input_str.append(chr(tmp_6))

        # Move to the next set of 4 characters in the encrypted string
        output_cnt += 4

    return ''.join(input_str)

# Example usage:
Str2 = "x2dtJEOmyjacxDemx2eczT5cVS9fVUGvWTuZWjuexjRqy24rV29q"
input_str = decrypt(Str2)
print("Decrypted Input String:", input_str)
