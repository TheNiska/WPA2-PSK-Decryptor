from timeit import timeit
import random
from custom_hashlib import bytes_xor


def get_random_string():
    return ''.join([chr(random.randint(0, 100)) for _ in range(64)])


byte_strings = [get_random_string().encode() for _ in range(20)]


def f1(strings):
    # 0.25
    for i in range(len(strings)):
        strings[i] = bytes_xor(strings[i], b'\x36'[0])
    return b''.join(strings)


def f2(strings):
    pad = b'\x36'[0]
    return b''.join([bytes_xor(s, pad) for s in strings])


f1(byte_strings)
t1 = timeit(stmt="f2(byte_strings)", globals=globals(), number=1000)
print(t1)
