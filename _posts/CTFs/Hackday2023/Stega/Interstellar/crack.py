#https://codepen.io/abdhass/full/jdRNdj
import pyshark
cap = pyshark.FileCapture('dump.pcap', display_filter="icmp")
img = ""
for pkt in cap:
  if "8" in str(pkt.icmp.Type):
  	img += pkt.icmp.data[16:]

#print(img)

import binascii
import numpy as np
from PIL import Image

# define image dimensions
width = 250
height = 166

# load hex data
with open('image', 'r') as f:
    hex_data = f.read().replace('\n', '')

# convert hex data to binary string
binary_data = binascii.unhexlify(hex_data)

# create numpy array from binary string
img_array = np.frombuffer(binary_data, dtype=np.uint8).reshape((height, width, 4))

# create image from numpy array
img = Image.fromarray(img_array, 'RGBA')

# save image
img.save('output.png')
