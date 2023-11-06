import numpy as np


def byte_to_bin_string(byte: int) -> str:
    bit_str = bin(byte)[2:]
    length = len(bit_str)
    return bit_str if length == 8 else (8 - length) * '0' + bit_str


def bytes_to_bits(byte_string: bytes) -> np.array:
    bits_len = len(byte_string) * 8
    arr = np.zeros((bits_len,), dtype=np.bool_)
    current = 0
    for byte in byte_string:
        bits = byte_to_bin_string(byte)
        bits_list = [int(ch) for ch in bits]
        arr[current:current+8] = bits_list
        current += 8
    return arr


s1 = b"\xff\x00" * 2
s2 = b"\x0f\x0f" * 2


bin_seq1 = ' '.join([byte_to_bin_string(byte) for byte in s1])
bin_seq2 = ' '.join([byte_to_bin_string(byte) for byte in s2])

print(s1.hex(), s2.hex(), sep='\n')
print(bin_seq1, bin_seq2, sep='\n')

s1_num = int.from_bytes(s1)
s2_num = int.from_bytes(s2)

res = s1_num
print(res.to_bytes(4))
bits1 = bytes_to_bits(s1)
bits2 = bytes_to_bits(s2)

res = np.logical_and(bits1, bits2)
print(''.join([str(int(el)) for el in res]))

print()
'''
res_list = []
for i in range(len(res) // 8):
    res_list.append(res[i*8:i*8+8])
print(' '.join(res_list))
'''

