# -*- coding: utf-8 -*-

from decryptor_multiprocess import main_app
import sys


def main():
    print(sys.argv)
    req_1 = "--essid or -e"
    req_1_descr = "BSSID or the target AP"
    req_2 = "--file or -f"
    req_2_descr = "File that contains captured packets"
    opt_1 = "--str or -s"
    opt_1_descr = "Two argumens separated by space: string containing symbols to generate the password and the length of the password"
    
    if len(sys.argv) == 2:
        if sys.argv[1] == '--help' or sys.argv[1] == '-h':
            print('-'*50)
            print("Required arguments:")
            print(f"{req_1.ljust(15)} {req_1_descr}")
            print(f"{req_2.ljust(15)} {req_2_descr}")
            print("Optional arguments:")
            print(f"{opt_1.ljust(15)} {opt_1_descr}")
            return 
            
            

    for i in range(len(sys.argv) - 1):
        if sys.argv[i] == '--essid' or sys.argv[i] == '-e':
            essid = sys.argv[i+1]
        elif sys.argv[i] == '--file' or sys.argv[i] == '-f':
            filename = sys.argv[i+1]
        elif sys.argv[i] == '--str' or sys.argv[i] == '-s':
            chars = sys.argv[i+1]
            length = int(sys.argv[i+2])

    main_app(essid, filename, chars, length)


if __name__ == "__main__":
    main()
