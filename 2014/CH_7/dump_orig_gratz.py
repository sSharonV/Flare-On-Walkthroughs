import idaapi

# Specify the address and the size to dump
start_address = 0x1131F8
size_to_dump = 0x106240  # 106240 in hexadecimal

# Open a file to dump the data
output_filename = "dumped_data.bin"
with open(output_filename, "wb") as output_file:
    # Read the specified memory range and write it to the output file
    for offset in range(size_to_dump):
        byte = idaapi.get_byte(start_address + offset)
        output_file.write(bytes([byte]))

print(f"Data dumped to {output_filename}")
