from hashlib import sha1
import numpy as np

'''
Cryptographic hash func. In the future must we be written from scratch
'''
hash_func = sha1
# Should be replaces with custom: hash_func = lambda bytes -> hash


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


def bytes_xor(string: bytes, pad: int) -> bytes:
    return b''.join(
        [(byte ^ pad).to_bytes(1) for byte in string]
    )



def words_sum(X, Y):
    '''
    x and y are numbers between 0 and 2^32. Then main computing is:
        z = (x + y) mod 2^32
    '''
    x, y = int.from_bytes(X), int.from_bytes(Y)
    return ((x + y) % (2**32)).to_bytes(4)


def circ_left_shit(X: bytes, n: int):
    '''
    If X is a word and n is integer 0 <= n < 32, then func is
        shift = (X << n) or (X >> 32 - n)

    X << n: discarding left-most n bits and padding the result with
    n zeros on the right.

    X >> n: discarding the right-most n bits and padding the result with
    n zeros on the left.
    '''
    x = int.from_bytes(X)
    shifted = (x << n) or (x >> (32 - n))
    return shifted.to_bytes(4)


def circ_left_shift_arr(arr, n):
    length = arr.shape[0]
    temp_arr = np.zeros((2, length), dtype=np.bool_)

    temp_arr[0, :length - n] = arr[n:]  # shift left
    temp_arr[1, 32 - n:] = arr[:length - (32 - n)]  # shift right

    return np.logical_or(temp_arr[0,], temp_arr[1,])


def sha1_pad(msg: bytes) -> bytes:
    byte_len = len(msg)  # len in bytes (two hex digits)
    bit_len = byte_len * 8

    # last 64 bits are reserved (8 bytes)
    remainder = bit_len % 512 if bit_len >= 512 else 512 - bit_len
    if remainder == 0:
        return msg

    zeroes_num = remainder - 64 - 1
    bin_num = '1' + '0' * zeroes_num
    bin_num_len = len(bin_num)
    if bin_num_len % 8 != 0:
        print("Error. Bin num len is not modulo of 8")

    for i in range(bin_num_len // 8):
        byte_num = int(bin_num[i*8:i*8+8], 2).to_bytes(1)
        msg += byte_num

    # now calculating 2 words (4 bytes x 2)
    two_words_length = bit_len.to_bytes(8)

    msg += two_words_length
    print("After padding: ", msg.hex())
    return msg


def main_sha1(msg: bytes):
    '''
    SHA1. RFC 3174. Max input size: < 2^64 bites. Output - 160 bit (digest).
    A word is 32-bit (4 bytes) string or 8 hex digits. Any int between 0 and
    2^32 - 1 may be represented as a word (291 = 00000123).

    If z is int, and 0 <= z < 2^64, then z = (2^32)x + y, where 0 <= x <= 2^32
    and 0 <= y < 2^32. So z can be represented as two words X and Y.

    Block is 512 bit string. A block may be represented as a sequence of 16
    words.

    Sum of two words A + B definned in words_sum() function.
    Circular left shift in circ_left_shift() function.

    Before computing digest we need to pad the message. The length of the
    message is the number of bits in the message. The purpuse of message
    padding is to make the total length of a padded message a multiple of
    512.

    '''
    msg = sha1_pad(msg)
    length = len(msg) // 64
    blocks = np.zeros((length, 512), dtype=np.bool_)
    for i in range(length):
        blocks[i, :] = bytes_to_bits(msg[i*64:i*64+64])[:]

    print(blocks)
    print(blocks.shape)

    '''
    f_0_19 = (B and C) or ((not B) and D)
    f_20_39 = B ^ C ^ D
    f_40_59 = (B and C) or (B and D) or (C and D)
    f_60_79 = B ^ C ^ D
    '''


    return

    for i in range(blocks.shape[0]):
        # now we have 512 len block
        words = np.zeros((80, 32), dtype=np.bool_)

        for j in range(16):
            words[j,] = blocks[i, j*32:j*32+32]

        for t in range(16, 80):
            xored = np.logical_xor(
                np.logical_xor(words[t-3,], words[t-8,]),
                np.logical_xor(words[t-14,], words[t-16,])
            )
            words[t, ] = circ_left_shift_arr(xored, 1)

        A, B, C, D, E = H0, H1, H2, H3, H4

        for t in range(80):
            temp = (circ_left_shift_arr(A, 5)
                    + func_map[t](B, C, D)
                    + E
                    + words[t,]
                    + K_map[t])

            E = D
            D = C
            C = circ_left_shift_arr(B, 30)
            B = A
            A = temp

        H0 = H0 + A
        H1 = H1 + B
        H2 = H2 + C
        H3 = H3 + D
        H4 = H4


    return None


def main_hmac(key: bytes = None, data: bytes = None) -> bytes:
    B = 64  # byte length of hash input
    L = 20  # byte lenght of hash output

    IPAD = b'\x36'
    OPAD = b'\x5c'

    K = 'password_key'.encode() if key is None else key
    text = 'example_text'.encode() if data is None else data

    key_len = len(K)

    # 1
    if key_len < B:
        K += b'\x00' * (B - key_len)

    # 2
    k_padded_ipad = bytes_xor(K, IPAD[0])

    # 3 - 4
    first_sha1 = hash_func(k_padded_ipad + text)

    # 5
    k_padded_opad = bytes_xor(K, OPAD[0])

    # 6
    final_string = k_padded_opad + first_sha1.digest()

    # 7
    return hash_func(final_string).digest()


if __name__ == '__main__':
    test_hex = b"denisdflasdfjasdl;f"
    res = main_sha1(test_hex)
    print(type(res))
