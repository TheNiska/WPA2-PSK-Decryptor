from hashlib import sha1
import numpy as np

'''
Cryptographic hash func. In the future must we be written from scratch
'''
hash_func = sha1
# Should be replaces with custom: hash_func = lambda bytes -> hash


def bytes_xor(string: bytes, pad: int) -> bytes:
    return b''.join(
        [(byte ^ pad).to_bytes(1) for byte in string]
    )


def circ_left_shit(X: bytes, n: int):
    '''
    If X is a word and n is integer 0 <= n < 32, then func is
        shift = (X << n) or (X >> 32 - n)

    X << n: discarding left-most n bits and padding the result with
    n zeros on the right.

    X >> n: discarding the right-most n bits and padding the result with
    n zeros on the left.
    '''



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
