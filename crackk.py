from scapy.all import rdpcap, EAPOL, Dot11, Raw
from binascii import hexlify, a2b_hex
from pbkdf2 import PBKDF2
from hashlib import sha1
from hmac import new
from itertools import product


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


def main():
    # Открываем файл .cap и читаем его содержимое
    packets = rdpcap('shake.pcap')
    handshakes = [0, 0, 0, 0]
    essid = 'essid'
    bssid = ''
    cl = ''
    characters = 'abeghiw'
    rep = 4
    length = 4**len(characters)

    passwords = product(characters, repeat=rep)

    for pkt in packets:
        bssid, cl = check(pkt, handshakes, bssid, cl)

    if all(handshakes):
        print("Пакеты успешно прошли проверку!\n")

    key_data, mic, payload = organize(bssid, cl, handshakes)

    for i, passwrd in enumerate(passwords):
        password = ''.join(passwrd) + 'ending_of_pass'
        if i % 30 == 0:
            print(int(i / length * 100), '%')
            print(password)
            print("-----")
        pmk = PBKDF2(password, essid, 4096).read(32)
        ptk = customPRF512(pmk, b"Pairwise key expansion", key_data)
        # _mic = hmac.new(_ptk[0:16], payload, md5).hexdigest()
        _mic_ = new(ptk[0:16], payload, sha1).hexdigest()[:32]

        _mic_ = _mic_.encode()
        # if mic == mic or mic == _mic_
        if mic == _mic_:
            print('Пароль найден: ', password)
            print(i)
            break


if __name__ == "__main__":
    main()
