def rol_byte(value, shift):
    """
    Rotate Left (ROL) on a byte (8 bits). Rotate the bits of the value to the left by 'shift' positions.
    
    Args:
    - value: The byte (8 bits) to rotate, expressed as an integer (0-255).
    - shift: Number of positions to shift left (0-7).
    
    Returns:
    - The rotated byte (0-255), in integer.
    """
    value = value & 0xFF  # Ensure it's within 8 bits
    shift = shift & 0x07   # Ensure shift is within 0-7
    return ((value << shift) | (value >> (8 - shift))) & 0xFF

def ror_byte(value, shift):
    """
    Rotate Right (ROR) on a byte (8 bits). Rotate the bits of the value to the right by 'shift' positions.
    
    Args:
    - value: The byte (8 bits) to rotate, expressed as an integer (0-255).
    - shift: Number of positions to shift right (0-7).
    
    Returns:
    - The rotated byte (0-255), in integer.
    """
    value = value & 0xFF  # Ensure it's within 8 bits
    shift = shift & 0x07   # Ensure shift is within 0-7
    return ((value >> shift) | (value << (8 - shift))) & 0xFF

wanted_flag = []

# Stage 1
wanted_flag.insert(0, chr(rol_byte(0x1b, 0xf2)))
# Stage 2
wanted_flag.insert(1, chr(0x30 ^ 0xB3 ^ 0xF2 ^ 0x40))
# Stage 3
wanted_flag.insert(2, chr(0x1F ^ 0x71))
# Stage 4
wanted_flag.insert(3, chr((rol_byte(0xB0, 0xBC) - 0xA3) & 0xFF))
# Stage 5
wanted_flag.insert(4, chr((0xE8 + 0x79) & 0xFF))
# Stage 6
wanted_flag.insert(5, chr(rol_byte((0xF6 + 0x28) & 0xFF, 0x82)))
# Stage 7
wanted_flag.insert(8, chr((rol_byte((0x1F - 0x2C) & 0xFF, 0x4D) + 0xB0) & 0xFF))
# Stage 8
wanted_flag.insert(9, chr(((ror_byte((rol_byte(((0xAF - 0x3F) & 0xFF), 0x2A) ^ 0xB8), 0x99)) - 0x54) & 0xFF))
# Stage 9
wanted_flag.insert(10, chr(rol_byte(0x5D, 0xBA)))
# Stage 10
wanted_flag.insert(11, chr(rol_byte((0x29 - 0x30) & 0xFF, 0x6C) ^ 0xED))
# Stage 11
wanted_flag.insert(12, chr((0xB5 + 0xBF) & 0xFF))
# Stage 12
wanted_flag.insert(13, chr(ror_byte(((ror_byte((0xA5 - 0x63 + 0x31) & 0xFF, 0x7B)) - 0x8C) & 0xFF, 0xBC)))
# Stage 13
wanted_flag.insert(14, chr(ror_byte(ror_byte(ror_byte(0xF3, 0x98) ^ 0xAE, 0x16), 0x20)))
# Stage 14
wanted_flag.insert(15, chr(rol_byte((0xA6 - 0xD2) & 0xFF, 0x6E)))
# Stage 15
wanted_flag.insert(16, chr((0x62 - 0x34) & 0xFF))
# Stage 16
wanted_flag.insert(17, chr(((0x32 ^ 0xB2) - 0x62 + 0x10 - 0xCD) & 0xFF))
# Stage 17
wanted_flag.insert(18, chr((rol_byte(0xEB, 0x7)) ^ 0x73 ^ 0xB7))
# Stage 18
wanted_flag.insert(19, chr((rol_byte((0xB + 0x4C - 0x5B) & 0xFF, 0x36) + 0x61 - 0x34) & 0xFF))
# Stage 19
wanted_flag.insert(20, chr((0x9A - 0x5A) & 0xFF))
# Stage 20
wanted_flag.insert(21, chr(ror_byte(0x99, 0xA2)))
# Stage 21
wanted_flag.insert(22, chr(((0x2B + 0xE7) ^ 0x7E) & 0xFF))
# Stage 22
wanted_flag.insert(23, chr(((((rol_byte(ror_byte(0xAF, 0x57), 0x4A) - 0x4E) & 0xFF) ^ 0x86) + 0xB8) & 0xFF))
# Stage 23
wanted_flag.insert(24, chr(rol_byte(ror_byte(0xC3 ^ 0xAD ^ 0x4A, 0x95) ^ 0xE8, 0x86)))
# Stage 24
wanted_flag.insert(25, chr(rol_byte(((0x3 - 0x1C) & 0xFF) ^ 0xCC, 0x45)))
# Stage 25
wanted_flag.insert(26, chr((0xE3 + 0x4A) & 0xFF))
# Stage 26
wanted_flag.insert(27, chr(rol_byte(0xCA, 0x90) ^ 0xA5))
# Stage 27
wanted_flag.insert(28, chr(rol_byte(ror_byte(((0x3E + 0xD8) & 0xFF) ^ 0x78, 0x36), 0xDE)))
# Stage 28
wanted_flag.insert(29, chr((rol_byte(ror_byte(ror_byte(0xD8, 0x11), 0xA2), 0x89) + 0xAD - 0xB5) & 0xFF))
# Stage 29
wanted_flag.insert(30, chr((rol_byte(0x82, 0xC0) + 0x21 - 0x40) & 0xFF))
# Stage 30
wanted_flag.insert(31, chr(ror_byte(0x7B, 0xE3)))
# Stage 31
wanted_flag.insert(32, chr((rol_byte(0xD7, 0xF6) + 0x78) & 0xFF))

print(''.join(wanted_flag))