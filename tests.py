import numpy as np

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


def bitarray_to_bytes(arr: np.array) -> bytes:
    bit_list = ''.join([str(int(x)) for x in arr])
    bytes_length = len(bit_list) // 8
    result = b''.join([
        int(bit_list[i*8:i*8+8], 2).to_bytes(1) for i in range(bytes_length)
    ])
    return result


def bitstring_to_bytes(s: str) -> bytes:
    bytes_length = len(s) // 8
    result = b''.join([
        int(s[i*8:i*8+8], 2).to_bytes(1) for i in range(bytes_length)
    ])
    return result


def circ_left_shift_arr(arr, n):
    length = arr.shape[0]
    temp_arr = np.zeros((2, length), dtype=np.bool_)

    temp_arr[0, :length - n] = arr[n:]  # shift left
    temp_arr[1, 32 - n:] = arr[:length - (32 - n)]  # shift right

    arr[:] = np.logical_or(temp_arr[0,], temp_arr[1,])


def func(arr):
    arr[2] = 1
    arr[4] = 1


def bin_sum(*arrays):
    size = arrays[0].shape[0]
    res_arr = np.zeros((size, ), dtype=np.bool_)
    to_next = '0'
    for i in range(size - 1, -1, -1):
        num = sum([a[i] for a in arrays]) + int(to_next, 2)
        bin_num = bin(num)[2:]

        res_arr[i] = int(bin_num[-1])
        to_next = '0' if len(bin_num) < 2 else bin_num[:-1]
    print()
    return res_arr


arr = np.zeros((10, ), dtype=np.bool_)
print(arr)

func(arr)
print(arr)

circ_left_shift_arr(arr, 1)
print(arr)


# 32 bits
x1 = b"\x61\x62\x63\x64"
x2 = b"\x67\x45\x23\x01"
x3 = b"\xEF\xCD\xAB\x89"
x4 = b"\xEF\xCD\xAB\x89"

x1_num, x2_num, x3_num, x4_num = (
    int.from_bytes(x1),
    int.from_bytes(x2),
    int.from_bytes(x3),
    int.from_bytes(x4)
)
sm = sum([x1_num, x2_num, x3_num, x4_num])
print(sm & 0xffffffff)

x1_bits, x2_bits, x3_bits, x4_bits = (
    bytes_to_bits(x1),
    bytes_to_bits(x2),
    bytes_to_bits(x3),
    bytes_to_bits(x4),
)

arr_lst = [
    x1_bits.astype(int), x2_bits.astype(int),
    x3_bits.astype(int), x4_bits.astype(int)
]

pprint_str = '\n'.join([''.join(str(arr)) for arr in arr_lst])
print(pprint_str, '\n')

sum_arr = bin_sum(*arr_lst)
sum_bytes = bitarray_to_bytes(sum_arr)
sum_number = int.from_bytes(sum_bytes)
print(sum_number)