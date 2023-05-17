from Crypto.Cipher import AES
import base64

# Set the key and encrypted message
key = b'c45c60232c9847e2'
encrypted_message = 'kSDIsBFTYa3+aLqEpVLXtspdLse8WclEhbqGLiqvM6k='

# Decode the message from base64
decoded_message = base64.b64decode(encrypted_message)

# Create an AES cipher object with the key and mode
cipher = AES.new(key, AES.MODE_ECB)

# Decrypt the message
decrypted_message = cipher.decrypt(decoded_message)

# Print the decrypted message
print(decrypted_message)
