# -*- coding: utf-8 -*-

from decryptor_multiprocess import main_app


def main():
    print("Enter ESSID: ", end="")
    bssid = input()
    print("Enter filename with handshakes: ")
    filename = input()
    main_app(bssid, filename)


if __name__ == "__main__":
    main()
