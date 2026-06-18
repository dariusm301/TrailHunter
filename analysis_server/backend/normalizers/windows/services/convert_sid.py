import struct

def convert_raw_sid_to_string(numbers: list[int]) -> str:
    revision = numbers[0]
    
    authority = 0
    for i in range(2, 8):
        authority = (authority << 8) + numbers[i]
    
    sub_authorities = []
    num_sub_auths = numbers[1] 
    
    for i in range(num_sub_auths):
        start = 8 + (i * 4)
        chunk = numbers[start : start + 4]
        val = struct.unpack("<I", bytes(chunk))[0]
        sub_authorities.append(str(val))
    
    return f"S-{revision}-{authority}-" + "-".join(sub_authorities)