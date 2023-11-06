def byte_to_bin_string(byte: int) -> str:
    bit_str = bin(byte)[2:]
    length = len(bit_str)
    return bit_str if length == 8 else (8 - length) * '0' + bit_str


s1 = b"\xff\x00" * 2
s2 = b"\x0f\x0f" * 2

bin_seq1 = ' '.join([byte_to_bin_string(byte) for byte in s1])
bin_seq2 = ' '.join([byte_to_bin_string(byte) for byte in s2])

print(s1.hex(), s2.hex(), sep='\n')
print(bin_seq1, bin_seq2, sep='\n')

s1_num = int.from_bytes(s1)
s2_num = int.from_bytes(s2)

res = not s1_num
print(res.to_bytes(4))
'''
res_list = []
for i in range(len(res) // 8):
    res_list.append(res[i*8:i*8+8])
print(' '.join(res_list))
'''

