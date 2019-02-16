import base64
import struct

key = [0x188314A7, 0x0E68A17CB, 0x0A6159DC9, 0x134AC73, 0x34969AA5, 0x0A6A7491B, 0x0C87A1170, 0x0AB039A48, 0x86A14196, 0x99AEBA53]


def rev_sub_40137C(a1):
	v4 = []
	for index in range(len(a1) / 2):
		v6 = (ord(a1[index * 2]), ord(a1[index * 2 + 1]))
		v4.append(rev_sub_4013AB(v6))

	return v4


def rev_sub_4013AB(a1):
	return ((a1[0] % 16) << 0x4) + (a1[1] % 16)

	
with open('exfiltrated', 'r') as file:
	cipher = file.read()

contents = bytearray(rev_sub_40137C(cipher))

j = 0
for i in range(0, len(contents)-(len(contents) % 8), 8):
	a, b = struct.unpack('II', contents[i:i+8])

	contents[i: i+4] = struct.pack('I', a ^ key[j % len(key)])
	contents[i+4: i+8] = struct.pack('I', (b - key[(j+1) % len(key)]) & 0xffffffff)

	j += 2

with open('exfiltrated_decrypted', 'wb') as file:
	file.write(bytearray(contents))
