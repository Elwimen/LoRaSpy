"""
xxd-style hex/ASCII dump — same layout and colour scheme as meshprobe's hex_dump.py.
"""

GRAY = "\033[90m"
BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

_CONTROL = set(range(0x20)) | {0x7F}


def _color(b: int) -> str:
    if 32 <= b < 127:
        return BOLD + (GREEN if chr(b).isalnum() else YELLOW)
    if b in _CONTROL:
        return BOLD + CYAN
    return ""


def hex_dump(data: bytes, width: int = 16, use_color: bool = True) -> str:
    lines = []
    full_hex_len = width * 2 + (width // 2 - 1)  # 39 for 16-byte lines
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        pairs, visible = [], 0
        for j in range(0, len(chunk), 2):
            part = ""
            for b in chunk[j:j + 2]:
                c = _color(b) if use_color else ""
                part += f"{c}{b:02x}{RESET if c else ''}"
                visible += 2
            pairs.append(part)
        visible += max(len(pairs) - 1, 0)
        ascii_part = ""
        for b in chunk:
            if 32 <= b < 127:
                c = _color(b) if use_color else ""
                ascii_part += f"{c}{chr(b)}{RESET if c else ''}"
            else:
                ascii_part += f"{GRAY}.{RESET}" if use_color else "."
        lines.append(f"{off:08x}: {' '.join(pairs)}{' ' * (full_hex_len - visible)}  {ascii_part}")
    return "\n".join(lines)
