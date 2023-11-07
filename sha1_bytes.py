K_0_19 = int.from_bytes(b"\x5A\x82\x79\x99")
K_20_39 = int.from_bytes(b"\x6E\xD9\xEB\xA1")
K_40_59 = int.from_bytes(b"\x8F\x1B\xBC\xDC")
K_60_79 = int.from_bytes(b"\xCA\x62\xC1\xD6")

H0 = int.from_bytes(b"\x67\x45\x23\x01")
H1 = int.from_bytes(b"\xEF\xCD\xAB\x89")
H2 = int.from_bytes(b"\x98\xBA\xDC\xFE")
H3 = int.from_bytes(b"\x10\x32\x54\x76")
H4 = int.from_bytes(b"\xC3\xD2\xE1\xF0")

K_map = dict()
func_map = dict()


for t in range(80):
    if t <= 19:
        def func1(B, C, D):
            return D ^ (B & (C ^ D))

        func_map[t] = func1
        K_map[t] = K_0_19

    elif 20 <= t <= 39:
        def func2(B, C, D):
            return B ^ C ^ D

        func_map[t] = func2
        K_map[t] = K_20_39

    elif 40 <= t <= 59:
        def func3(B, C, D):
            return (B & C) | (B & D) | (C & D)

        func_map[t] = func3
        K_map[t] = K_40_59

    else:
        def func4(B, C, D):
            return B ^ C ^ D

        func_map[t] = func4
        K_map[t] = K_60_79


def left_rotate(n, b):
    """Left rotate a 32-bit integer n by b bits."""
    return ((n << b) | (n >> (32 - b))) & 0xffffffff


def sha1_pad(msg: bytes):
    length = len(msg)
    bit_length = length * 8
    return (
        msg
        + b'\x80'
        + b'\x00' * ((56 - (length + 1) % 64) % 64)
        + bit_length.to_bytes(8)
    )


def sha1(msg: bytes):
    msg = sha1_pad(msg)

    H0 = int.from_bytes(b"\x67\x45\x23\x01")
    H1 = int.from_bytes(b"\xEF\xCD\xAB\x89")
    H2 = int.from_bytes(b"\x98\xBA\xDC\xFE")
    H3 = int.from_bytes(b"\x10\x32\x54\x76")
    H4 = int.from_bytes(b"\xC3\xD2\xE1\xF0")

    words = [int.from_bytes(msg[i*4:i*4+4]) for i in range(16)] + [b''] * 64

    for t in range(16, 80):
        words[t] = left_rotate(
            words[t-3] ^ words[t-8] ^
            words[t-14] ^ words[t-16],
            1
        )

    A, B, C, D, E = H0, H1, H2, H3, H4

    for t in range(80):
        A, B, C, D, E = (
            (left_rotate(A, 5) + func_map[t](B, C, D) + E + words[t] + K_map[t])
            & 0xffffffff,
            A,
            left_rotate(B, 30),
            C,
            D
        )

    H0 = (H0 + A) & 0xffffffff
    H1 = (H1 + B) & 0xffffffff
    H2 = (H2 + C) & 0xffffffff
    H3 = (H3 + D) & 0xffffffff
    H4 = (H4 + E) & 0xffffffff

    res = (
        H0.to_bytes(4)
        + H1.to_bytes(4)
        + H2.to_bytes(4)
        + H3.to_bytes(4)
        + H4.to_bytes(4)
    )
    return res


if __name__ == '__main__':
    from timeit import timeit
    import hashlib
    msg = b"alsdfasdflasdjf;lal;j;lj;;ljsdfja;lj;ljll;jlk;jl"
    res = sha1(msg)
    print(res.hex())
    print(hashlib.sha1(msg).hexdigest())

    my_time = timeit(stmt="sha1(msg)", globals=globals(), number=1000)
    std_time = timeit(stmt="hashlib.sha1(msg)", globals=globals(), number=1000)
    print(my_time, std_time)
