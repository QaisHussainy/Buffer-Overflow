import socket

# Create an array of buffers, from 10 to 200, with increments of 10.
counter = 10
fuzz_strings = ["A"]

while len(fuzz_strings) <= 30:
    fuzz_strings.append("A" * counter)
    counter = counter + 10

for fuzz in fuzz_strings:
    print "Fuzzing with %s bytes" % len(fuzz)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connect = s.connect(('192.168.45.153', 31337))
    s.send(fuzz + '\r\n\r\n' )
    
    print s.recv(1024)
    s.close()