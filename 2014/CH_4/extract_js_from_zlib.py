import zlib

# Function to decompress and convert a hex-encoded JavaScript file to ASCII
def decompress_and_convert(input_file_path, output_file_path):
    """
    This function reads a zlib-compressed file, decompresses it, decodes the result from hex to ASCII,
    and saves the output to a new file.

    Args:
    input_file_path (str): Path to the compressed input file.
    output_file_path (str): Path to save the decompressed and converted file.
    """
    try:
        # Step 1: Read the compressed data from the input file
        with open(input_file_path, 'rb') as file:
            compressed_data = file.read()

        # Step 2: Decompress the data using zlib
        decompressed_data = zlib.decompress(compressed_data)
        print(f"After decompressing data: {decompressed_data[:30]}")


        # Step 3: Decode decompressed data from UTF-8 and strip the last character
        hex_string = decompressed_data.decode('utf-8', errors='ignore')[:-1]
        print(f"After decoding decompressed data: {hex_string[:30]}")

        # Step 4: Convert the hex string to bytes (ASCII data)
        ascii_data = bytes.fromhex(hex_string)
        print(f"After hex convertion: {ascii_data[:30]}")

        # Step 5: Save the resulting ASCII data to the output file
        with open(output_file_path, 'wb') as output_file:
            output_file.write(ascii_data)

        print(f"Successfully decompressed and converted data saved to '{output_file_path}'")

    except zlib.error as e:
        print(f"Error during decompression: {e}")
    except ValueError as e:
        print(f"Error during hex conversion: {e}")
    except UnicodeDecodeError as e:
        print(f"Error during UTF-8 decoding: {e}")

# Define input and output file paths
input_file = 'obfu_js.mal'
output_file = 'deobfu_ascii_js.js'

# Run the function
decompress_and_convert(input_file, output_file)
