import numpy as np
from timeit import timeit


def byte_to_bin_string(byte: int) -> str:
    bit_str = bin(byte)[2:]
    length = len(bit_str)
    return bit_str if length == 8 else (8 - length) * '0' + bit_str


def bytes_to_bits(byte_string: bytes, size=None) -> np.array:
    bits_len = len(byte_string) * 8 if not size else size

    arr = np.zeros((bits_len,), dtype=np.bool_)

    current = 0
    for byte in byte_string:
        bits = byte_to_bin_string(byte)
        bits_list = [int(ch) for ch in bits]
        arr[current:current+8] = bits_list
        current += 8
    return arr


def bytes_to_bits_opt(byte_string: bytes, size=None) -> np.array:
    initial_size = len(byte_string) * 8
    size = initial_size if not size else size

    result_array = np.zeros((size, ), dtype=np.bool_)

    bits_array = np.unpackbits(
        np.frombuffer(byte_string, dtype=np.uint8)
    ).astype(np.bool_)

    result_array[:initial_size] = bits_array
    return result_array


# 32 bits
x1 = b"\x61\x62\x63\x64\x67\x45\x23\x01\x67\x45\x23\x01\xff\xaa\xb1"
x2 = b"\x67\x45\x23\x01"

t1 = bytes_to_bits(x1)
t2 = bytes_to_bits_opt(x1)
assert np.array_equal(t1, t2)

t1 = timeit(stmt="bytes_to_bits(x1)", globals=globals(), number=10000)
t2 = timeit(stmt="bytes_to_bits_opt(x1)", globals=globals(), number=10000)
print(t1, t2, sep='\n')
