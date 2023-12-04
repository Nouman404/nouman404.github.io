import base64 as b64

def xor(bytes1, bytes2):
    return bytes(a ^ b for a, b in zip(bytes1, bytes2))

file1_path = 'cipher.txt'
file2_path = 'cipher2.txt'
out_p1 = "p1.txt"

with open(file1_path, 'rb') as file1, open(file2_path, 'rb') as file2:
    ciphertext1 = file1.read()
    ciphertext2 = file2.read()

# Extract the known parts
P2 = "Build with love, kitties and flowers"
C2 = "C19FW3jqqqxd6G/z0fcpnOSIBsUSvD+jZ7E9/VkscwDMrdk9i9efIvJw1Fj6Fs0R"
P2 += "\x0c" * (len(b64.b64decode(C2))-len(P2))
P2_byte = P2.encode('utf-8')

# XOR plaintext and base64-decoded ciphertext to get the key
key = xor(P2_byte, b64.b64decode(C2))

print(key.hex())
# XOR the bytes to recover the plaintext P2
P2_byte = xor(b64.b64decode(C2), key)
P2 = P2_byte.decode('utf-8')

# Corrected XOR to recover P1
P1 = xor(b64.b64decode(ciphertext1[32:]), key)

with open(out_p1, 'wb') as out_p1_f:
    out_p1_f.write(P1)
