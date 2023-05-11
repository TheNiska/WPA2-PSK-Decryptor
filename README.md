## WPA2-PSK Decryptor
*Simple python script to decrypt captured EAPOL packets.
EAPOL have 4 packets, and in order for this script to work properly each of them must occur in .cap or .pcap file only once. Otherwise the script will grab the first encountered packet.*

Script was written in Python 3.10.6 but probably will work in any Python 3.x version.

### Usage
Just run run.py
If you want to copy-past code and run it (or to use Python Notebook), copy the content of 'decryptor_multiprocess.py'
