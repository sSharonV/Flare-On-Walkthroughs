import idaapi
import idautils
import idc
import ida_ua
import ida_name

def has_call_to_cfltcvt_init(function_ea: int) -> bool:
    """Check if the called function (at 'function_ea') has a call to __cfltcvt_init."""
    for block in idautils.Chunks(function_ea):
        for instruction_ea in idautils.Heads(block[0], block[1]):
            if idaapi.is_call_insn(instruction_ea):
                called_function_ea = idc.get_operand_value(instruction_ea, 0)
                if idc.get_func_name(called_function_ea) == "__cfltcvt_init":
                    print(f"Found call to __cfltcvt_init in function at {hex(function_ea)}")
                    return True
    return False

def has_conditional_blocks(function_ea: int) -> bool:
    """Check if the called function (at 'function_ea') contains any conditional blocks (conditional jumps)."""
    for block in idautils.Chunks(function_ea):
        for instruction_ea in idautils.Heads(block[0], block[1]):
            if is_conditional_jump(instruction_ea):
                print(f"Found conditional block in function at {hex(function_ea)}")
                return True
    return False

def is_conditional_jump(instruction_ea: int) -> bool:
    """Check if the instruction at 'instruction_ea' is a conditional jump."""
    instruction = idaapi.insn_t()
    if idaapi.decode_insn(instruction, instruction_ea):
        mnemonic = instruction.get_canon_mnem()
        return mnemonic in ["je", "jne", "jl", "jle", "jg", "jge", "jb", "jbe", "ja", "jae"]
    return False

def is_mov_eax_with_immediate(instruction_ea: int) -> bool:
    """
    Check if the instruction at the given address is a MOV EAX, <immediate value>.
    
    :param instruction_ea: The effective address of the instruction to check.
    :return: True if the instruction is 'MOV EAX, immediate', False otherwise.
    """
    # Retrieve the bytes of the instruction
    instruction_bytes = idaapi.get_bytes(instruction_ea, 5)  # Get up to 5 bytes (enough for the MOV instruction)
    
    if instruction_bytes:
        # Reference: Anti-Disassembly DigitalWhisper article
        # Check if the first byte is 0xB8
        return instruction_bytes[0] == 0xB8
    return False

def retrieve_value_from_offset(function_ea: int) -> str:
    """Retrieve the value stored at an offset within the function."""
    for block in idautils.Chunks(function_ea):
        for instruction_ea in idautils.Heads(block[0], block[1]):
            if is_mov_eax_with_immediate(instruction_ea):
                return get_offset_value(instruction_ea)
    return None

def get_offset_value(instruction_ea: int) -> str:
    """Get the ASCII character from the offset value in the instruction."""
    instruction = idaapi.insn_t()
    if idaapi.decode_insn(instruction, instruction_ea) and instruction.ops[1].type in {idaapi.o_mem, idaapi.o_imm}:
        offset_address = instruction.ops[1].value
        value = idc.get_wide_dword(offset_address)
        if value in range(255) and chr(value).isalnum():  # Simple check for non-bad chars
            print(f"Retrieved ASCII character '{chr(value)}' from offset {hex(offset_address)}")
            return chr(value)
    print(f"No valid ASCII character found at offset {hex(instruction_ea)}")
    return None

def print_cross_references_to_dwords_in_function(function_name: str) -> str:
    """
    Print all cross-references to dwords within a specified function.

    :param function_name: The name of the function to check for dwords.
    :return: A string representing the flag found.
    """
    # Get the function address from the function name
    function_ea = idc.get_name_ea(0, function_name)
    
    if function_ea == idc.BADADDR:
        print(f"Function '{function_name}' not found.")
        return ""
    
    print(f"Checking for cross-references to dwords in function: {function_name} at {hex(function_ea)}")
    
    flag = ""
    # Iterate over all instructions in the function
    for instruction_ea in idautils.Heads(function_ea + 13, idc.get_func_attr(function_ea, idc.FUNCATTR_END)):
        if is_dword_operation(instruction_ea):
            dword_address = idc.get_operand_value(instruction_ea, 0)
            print(f"Found dword operation at {hex(instruction_ea)}, dword address: {hex(dword_address)}")
            flag += collect_xrefs_to_dwords(dword_address)
    print(f"Final flag collected from function {function_name}: {flag + 'm'}")
    return flag + 'm'

def is_dword_operation(instruction_ea: int) -> bool:
    """Check if the instruction modifies a dword."""
    return idc.get_operand_type(instruction_ea, 0) == idc.o_mem and idc.get_operand_value(instruction_ea, 0) is not None

def collect_xrefs_to_dwords(dword_address: int) -> str:
    """Collect cross-references to a dword and construct the flag string."""
    # Get xrefs to this dword
    xrefs = list(idautils.XrefsTo(dword_address))
    if not xrefs:
        print(f"  No xrefs found for dword at {hex(dword_address)}.")
        return ""

    flag = ""
    for xref in xrefs:
        xref_function_name = idc.get_func_name(xref.frm)
        if xref_function_name.startswith("char_") and idc.get_operand_value(xref.frm, 1) == 1:
            flag += xref_function_name[5]
            print(f"  Found character '{xref_function_name[5]}' from xref at {hex(xref.frm)}")
    return flag

def convert_special_characters(flag: str) -> str:
    """Convert specific substrings in the flag to their corresponding characters."""
    replacements = {
        "dot": ".",
        "at": "@",
        "dash": "-"
    }
    # Replace each term in the string
    for key, value in replacements.items():
        flag = flag.replace(key, value)
    print(f"Converted flag: {flag}")
    return flag

def find_flag_in_range(start_ea: int, end_ea: int) -> str:
    """Find the flag within the specified address range by analyzing functions."""
    # Iterate through all functions presented in the range of start-end EA
    for function_ea in idautils.Functions(start_ea, end_ea):  # Returns the start address of the function
        function_name = idc.get_func_name(function_ea)
        print(f"Analyzing function: {function_name} at {hex(function_ea)}")
        process_function_calls(function_ea)

    return print_cross_references_to_dwords_in_function("__cfltcvt_init")

def process_function_calls(function_ea: int) -> None:
    """Process the calls within the function to identify relevant characters."""
    # Iterate through each function of 'function_ea'
    for block in idautils.Chunks(function_ea):  # Returns a tuple with start-end EA
        for instruction_ea in idautils.Heads(block[0], block[1]):  # Head - Address of instructions
            if idaapi.is_call_insn(instruction_ea):  # If the instruction is "call"
                handle_called_function(instruction_ea)

def handle_called_function(instruction_ea: int) -> None:
    """Handle a called function and determine its significance."""
    called_function_ea = idc.get_operand_value(instruction_ea, 0)  # Get the first parameter (only one)
    called_function_name = idc.get_func_name(called_function_ea) or ida_name.get_visible_name(called_function_ea)

    # Check if the called function has a call to __cfltcvt_init and isn't checking for FLAG sequence
    if has_call_to_cfltcvt_init(called_function_ea) and not has_conditional_blocks(called_function_ea):
        print(f"Detected reset function: {called_function_name} at {hex(called_function_ea)}")
        return  # This is a reset function; no need to process further

    # Checks if the called function is part of the functions that checks for specific chars
    if called_function_name.startswith("sub_"): 
        ascii_value = retrieve_value_from_offset(called_function_ea)
        if ascii_value is not None:
            print(f"Setting name for function {called_function_name} to 'char_{ascii_value}'")
            ida_name.set_name(called_function_ea, f"char_{ascii_value}")

# Define the address range
start_address = 0x10009F0A
end_address = 0x10009F0B  # Adjust this if you want to include more addresses

print(convert_special_characters(find_flag_in_range(start_address, end_address)))
