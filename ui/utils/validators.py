def validate_text_key(text: str):
    if not text:
        raise ValueError("Key is empty.")

def parse_des_key(text: str) -> int:
    if not text:
        raise ValueError("Key is empty.")
    try:
        key = int(text, 16) if text.startswith(("0x", "0X")) else int(text)
    except ValueError:
        raise ValueError("Invalid key format.")
    if key < 0 or key > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Key must be a 64-bit value.")
    return key

def parse_positive_int(text: str, name: str = "Value") -> int:
    if not text:
        raise ValueError(f"{name} is empty.")
    try:
        value = int(text)
    except ValueError:
        raise ValueError(f"{name} must be an integer.")
    if value <= 0:
        raise ValueError(f"{name} must be positive.")
    return value
