---
title: CTFs | HeroCTF_2024 | Steganographie | Subliminal2
author: BatBato
date: 2024-10-26
categories:
  - CTFs
  - HeroCTF_2024
  - Steganographie
tags:
  - Stega
permalink: /CTFs/HeroCTF_2024/Steganographie/Subliminal2
---
# Subliminal#2


![[https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_Stega_subliminal_enonce.png]]

Here we are given a video with a square that appears on each frame. We need to recover every square, reassemble them into one image and save it to get the flag. I used the following code:

```python
import cv2
import numpy as np

# Path to the video file
video_path = 'subliminal_hide.mp4'

# Open the video capture
cap = cv2.VideoCapture(video_path)

# Check if video opened successfully
if not cap.isOpened():
    print("Error: Could not open video.")
    exit()

# Get the width, height, and frame count of the video
frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))

# Set the size of the squares to 20x20
square_size = 20

# Calculate the size of the output image to fit the squares in grid form
output_width = (frame_width // square_size) * square_size
output_height = (frame_height // square_size) * square_size

# Initialize an empty array to store the reconstructed image
output_image = np.zeros((output_height, output_width, 3), dtype=np.uint8)

# Starting position for placing each square
current_x, current_y = 0, 0

# Loop through each frame in the video
frame_number = 0
while cap.isOpened():
    ret, frame = cap.read()
    if not ret:
        break  # End of video

    # Resize frame to ensure it fits the output grid exactly
    frame = cv2.resize(frame, (output_width, output_height))

    # Extract a 20x20 square from the current position
    square = frame[current_y:current_y+square_size, current_x:current_x+square_size]

    # Place the extracted square in the output image at the current position
    output_image[current_y:current_y+square_size, current_x:current_x+square_size] = square

    # Update y-position to move down by square size
    current_y += square_size

    # If we reach the bottom of the column, move to the next column and reset y
    if current_y >= output_height:
        current_y = 0
        current_x += square_size

    # If we've filled all columns, stop the process
    if current_x >= output_width:
        break

    frame_number += 1

# Rotate the output image by 180° to the left
output_image = cv2.rotate(output_image, cv2.ROTATE_180)

# Save the final reconstructed image
output_filename = "reconstructed_image.png"
cv2.imwrite(output_filename, output_image)
print(f"Processing complete. The final reconstructed image is saved as {output_filename}.")

# Release the video capture
cap.release()
```

> This also rotate the image because it is upside down when we save it at first.
{: .prompt-info}


We get the following image:

![[https://raw.githubusercontent.com/Nouman404/nouman404.github.io/refs/heads/main/_posts/CTFs/HeroCTF_2024/photos/HeroCTF_2024_Stega_subliminal_flag.png]]

Because the last part is a bit dark, we have to guess the last part. We have `Hero{The_demon..._eated!!!!}` and we guess that the flag is `Hero{The_demon_is_defeated!!!!}`.