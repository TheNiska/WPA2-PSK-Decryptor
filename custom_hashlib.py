from hashlib import sha1


'''
Cryptographic hash func. In the future must we be written from scratch
'''
hash_func = sha1
# Should be replaces with custom: hash_func = lambda bytes -> hash


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
    blocks = []
    for i in range(len(msg) // 64):
        blocks.append(msg[i:i+64])

    '''
    f_0_19 = (B and C) or ((not B) and D)
    f_20_39 = B ^ C ^ D
    f_40_59 = (B and C) or (B and D) or (C and D)
    f_60_79 = B ^ C ^ D
    '''

    K_0_19 = b"\x5A\x82\x79\x99"
    K_20_39 = b"\x6E\xD9\xEB\xA1"
    K_40_59 = b"\x8F\x1B\xBC\xDC"
    K_60_79 = b"\xCA\x62\xC1\xD6"

    H0 = b"\x67\x45\x23\x01"
    H1 = b"\xEF\xCD\xAB\x89"
    H2 = b"\x98\xBA\xDC\xFE"
    H3 = b"\x10\x32\x54\x76"
    H4 = b"\xC3\xD2\xE1\xF0"

    for block in blocks:
        words = [block[i*4:i*4+4] for i in range(16)]
        words.extend([b''] * 64)
        print(words)
        print(len(words))

        for t in range(16, 80):
            words[t] = circ_left_shit(
                words[t-3] ^ words[t-8] ^ words[t-14] ^ words[t-16],
                1
            )
        
        A, B, C, D, E = H0, H1, H2, H3, H4

        for t in range(80):
            match t:
                case if 0 <= t <= 19:
                    func = (B and C) or ((not B) and D)
                    K = b"\x5A\x82\x79\x99"
                case if 20 <= t <= 39:
                    func = B ^ C ^ D
                    K = b"\x6E\xD9\xEB\xA1"
                case if 40 <= t <= 59:
                    func = (B and C) or (B and D) or (C and D)
                    K = b"\x8F\x1B\xBC\xDC"
                case if 60 <= t <= 79:
                    func = B ^ C ^ D
                    K = b"\xCA\x62\xC1\xD6"

            temp = circ_left_shit(A, 5) + func + E + words[t] + K[t]

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
    test_hex = b"\x61\x62\x63\x64\x65"
    msg = main_sha1(test_hex)
    print(msg)
