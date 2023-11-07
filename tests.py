import numpy as np


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
    return res_arr


arr = np.zeros((10, ), dtype=np.bool_)
print(arr)

func(arr)
print(arr)

circ_left_shift_arr(arr, 1)
print(arr)

arr1 = np.array([1, 1, 1, 1], dtype=np.bool_)
arr2 = np.array([1, 1, 1, 1], dtype=np.bool_)

print(bin_sum(arr1, arr2))
