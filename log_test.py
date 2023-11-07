with open("words_in_byte_sha1.txt", 'r') as f:
    lines1 = f.read()

with open("words_in_np_sha1.txt", 'r') as f:
    lines2 = f.read()


block1 = lines1.split('\n\n')
block2 = lines2.split('\n\n')

for n, el in enumerate(zip(block1, block2)):
    print(f"{n} {el[0] == el[1]}")
    print(el)
