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











main_hmac()

'''
res = bytes_xor(K, ipad[0])
res_old = bytes_xor_old(K, ipad * 64)
print(res.hex())
print(res_old.hex())

time_old = timeit(stmt="bytes_xor_old(K, ipad * 64)", globals=globals(), number=50000)
time = timeit(stmt="bytes_xor(K, ipad[0])", globals=globals(), number=50000)
print(time, time_old)
'''

















