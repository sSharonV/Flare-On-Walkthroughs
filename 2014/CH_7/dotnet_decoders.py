def xor_decrypt(encoded_str, key):
    """
    XOR-decrypt the given string using the specified key.
    The key is repeated if it's shorter than the encoded string.
    """
    decoded_str = ''
    for i in range(len(encoded_str)):
        decoded_str += chr(ord(encoded_str[i]) ^ ord(key[i % len(key)]))
    return decoded_str

# Decoder functions based on the C# code
def decoder1(encoded):
    key = "lulz"  # Key for decoder1
    return xor_decrypt(encoded, key)

def decoder2(encoded):
    key = "this"  # Key for decoder2
    return xor_decrypt(encoded, key)


def decoder3(encoded):
    key = "silly"  # Key for decoder3
    return xor_decrypt(encoded, key)


def decoder4(encoded):
    # For decoder4, we first decode using decoder2 with a specific encoded string
    key_string = "\u001b\u0005\u000eS\u001d\u001bI\a\u001c\u0001\u001aS\0\0\fS\u0006\r\b\u001fT\a\a\u0016K"
    decoded_key = decoder2(key_string)  # Get the dynamic key for decoder4
    return xor_decrypt(encoded, decoded_key)


def decode_datwork():
    # Example usage with the updated input string
    encoded_string = "\v\fP\u000e\u000fBA\u0006\rG\u0015I\u001a\u0001\u0016H\\\t\b\u0002\u0013/\b\t^\u001d\bJO\a]C\u001b\u0005"
    decoded_string = decoder4(encoded_string)
    print(f"The wanted FLAG: {decoded_string}")


    # Decoding each of the strings in the `datwork` method
    decoded_string1 = decoder1("(\u0014\u0018Z.\u0010\r\u0019\u0003\u001bVpAXAWAXAWAXAWAXAWAXAWAXAWAXAWAXAWAXAp")
    decoded_string2 = decoder2("9\t\n\u001b\u001d\u0006\fIT")
    decoded_string3 = decoder3("&\u001a\t\u001e=\u001c\u0004\r\u0005\u0017II")
    decoded_string4 = decoder1("9\u0006\t\bVU")
    decoded_string5 = decoder2(";;I%\u0011\u001a\u001a\u001a\u001b\u0006SS")
    decoded_string6 = decoder3("7\u001b\u0005\u001a\u001cII")
    decoded_string7 = decoder3("=\u0006\u0001\u001fCS")
    decoded_email = decoder2("\u0015\u0004X]\u0010\t\u001d]\u0010\t\u001d\u00124\u000e\u0005\u0012\u0006\rD\u001c\u001aF\n\u001c\u0019")
    decoded_subject = decoder3(":N\u0001L\u0018S\n\u0003\u0001\t\u0006\u001d\t\u001e")
    decoded_sender = decoder1("\0\0\0\0,\u0013\0\u001b\u001e\u0010A\u0015\u0002[\u000f\u0015\u0001")
    decoded_smtp_server = decoder2("\a\u0005\u001d\u0003Z\u001b\f\u0010\u0001\u001a\f\0\u0011\u001a\u001f\u0016\u0006F\a\u0016\0")
    
    # Combine all the decoded results to simulate the datwork output
    print("Decoded String 1 (decoder1):", decoded_string1)
    print("Decoded String 2 (decoder2):", decoded_string2)
    print("Decoded String 3 (decoder3):", decoded_string3)
    print("Decoded String 4 (decoder1):", decoded_string4)
    print("Decoded String 5 (decoder2):", decoded_string5)
    print("Decoded String 6 (decoder3):", decoded_string6)
    print("Decoded String 7 (decoder3):", decoded_string7)
    print("Decoded Email Address:", decoded_email)
    print("Decoded Subject:", decoded_subject)
    print("Decoded Sender:", decoded_sender)
    print("Decoded SMTP Server:", decoded_smtp_server)


# Call the function to decode all strings
decode_datwork()

