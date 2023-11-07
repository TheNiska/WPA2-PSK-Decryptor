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

    return np.logical_or(temp_arr[0,], temp_arr[1,])


def bin_sum(*arrays):
    size = arrays[0].shape[0]
    res_arr = np.zeros((size, ), dtype=np.bool_)
    to_next = '0'
    for i in range(size - 1, -1, -1):
        num = sum([a[i] for a in arrays]) + int(to_next, 2)
        bin_num = bin(num)[2:]

        res_arr[i] = int(bin_num[-1])
        to_next = '0' if len(bin_num) < 2 else bin_num[:-1]
    return res_arr


K_0_19 = bytes_to_bits(b"\x5A\x82\x79\x99")
K_20_39 = bytes_to_bits(b"\x6E\xD9\xEB\xA1")
K_40_59 = bytes_to_bits(b"\x8F\x1B\xBC\xDC")
K_60_79 = bytes_to_bits(b"\xCA\x62\xC1\xD6")

H0 = bytes_to_bits(b"\x67\x45\x23\x01")
H1 = bytes_to_bits(b"\xEF\xCD\xAB\x89")
H2 = bytes_to_bits(b"\x98\xBA\xDC\xFE")
H3 = bytes_to_bits(b"\x10\x32\x54\x76")
H4 = bytes_to_bits(b"\xC3\xD2\xE1\xF0")

K_map = dict()
func_map = dict()


for t in range(80):
    if t <= 19:
        def func1(B, C, D):
            return np.logical_or(
                np.logical_and(B, C),
                np.logical_and(np.logical_not(B), D)
            )

        func_map[t] = func1
        K_map[t] = K_0_19

    elif 20 <= t <= 39:
        def func2(B, C, D):
            return np.logical_xor(
                np.logical_xor(B, C),
                D
            )

        func_map[t] = func2
        K_map[t] = K_20_39

    elif 40 <= t <= 59:
        def func3(B, C, D):
            return np.logical_or(
                np.logical_or(
                    np.logical_and(B, C),
                    np.logical_and(B, D)
                ),
                np.logical_and(C, D)
            )

        func_map[t] = func3
        K_map[t] = K_40_59

    else:
        def func4(B, C, D):
            return np.logical_xor(
                np.logical_xor(B, C),
                D
            )

        func_map[t] = func4
        K_map[t] = K_60_79


def sha1(msg: bytes):
    bits_ln = len(msg) * 8
    bin_bits_ln = bin(bits_ln)[2:]

    msg = bytes_to_bits(msg, 512)
    msg[bits_ln] = 1

    bit_string = '0' * (64 - len(bin_bits_ln)) + bin_bits_ln
    # hx = bitstring_to_bytes(bit_string).hex()
    # print(hx)

    msg[448:] = [int(bit) for bit in bit_string]
    # print(bitarray_to_bytes(msg).hex())

    h0, h1, h2, h3, h4 = H0, H1, H2, H3, H4

    w = np.zeros((80, 32), dtype=np.bool_)
    for i in range(16):
        w[i] = msg[i*32:i*32+32]

    for t in range(16, 80):
        xored = np.logical_xor(
            np.logical_xor(w[t-3], w[t-8]),
            np.logical_xor(w[t-14], w[t-16])
        )
        circ_left_shift_arr(xored, 1)
        w[t,] = xored

    A, B, C, D, E = h0, h1, h2, h3, h4

    for t in range(80):
        temp = bin_sum(
            circ_left_shift_arr(A, 5),
            func_map[t](B, C, D),
            E,
            w[t,],
            K_map[t]
        )

        E = D
        D = C
        C = circ_left_shift_arr(B, 30)
        B = A
        A = temp

        with open("words_in_np_sha1.txt", 'a') as f:
            f.write(bitarray_to_bytes(temp).hex() + '\n')
            f.write(bitarray_to_bytes(E).hex() + '\n')
            f.write(bitarray_to_bytes(D).hex() + '\n')
            f.write(bitarray_to_bytes(C).hex() + '\n')
            f.write(bitarray_to_bytes(B).hex() + '\n')
            f.write(bitarray_to_bytes(A).hex() + '\n')
            f.write('\n')

    h0 = bin_sum(h0, A)
    h1 = bin_sum(h1, B)
    h2 = bin_sum(h2, C)
    h3 = bin_sum(h3, D)
    h4 = bin_sum(h4, E)

    res = (
        bitarray_to_bytes(h0) +
        bitarray_to_bytes(h1) +
        bitarray_to_bytes(h2) +
        bitarray_to_bytes(h3) +
        bitarray_to_bytes(h4)
    )

    return res




if __name__ == '__main__':
    res = sha1(b"denis")
    print(res.hex())
