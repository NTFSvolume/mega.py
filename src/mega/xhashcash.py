import base64
import hashlib
import struct


def d64(data_str: str) -> bytes:
    return base64.urlsafe_b64decode(data_str + "=" * (-len(data_str) % 4))


def e64(data_bytes: bytes) -> str:
    return base64.urlsafe_b64encode(data_bytes).decode("utf-8").rstrip("=")


def generate_hashcash_token(challenge: str) -> str:
    parts = challenge.split(":")
    version_str, easiness_str, _, token_str = parts
    version = int(version_str)
    if version != 1:
        raise ValueError("hashcash challenge is not version 1")

    easiness = int(easiness_str)
    base = ((easiness & 63) << 1) + 1
    shifts = (easiness >> 6) * 7 + 3
    threshold = base << shifts
    token = d64(token_str)
    buffer = bytearray(4 + 262144 * 48)
    for i in range(262144):
        buffer[4 + i * 48 : 4 + (i + 1) * 48] = token

    while True:
        digest = hashlib.sha256(buffer).digest()
        view = struct.unpack(">I", digest[:4])[0]  # big-endian uint32
        if view <= threshold:
            return f"1:{token_str}:{e64(buffer[:4])}"

        # Increment the first 4 bytes as a little-endian integer
        for j in range(4):
            buffer[j] = (buffer[j] + 1) & 0xFF
            if buffer[j] != 0:
                break
