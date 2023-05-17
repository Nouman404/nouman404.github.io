import cv2
import numpy as np
import os

# Load all square images from the "squares" folder
square_filenames = os.listdir("squares")
square_filenames.sort(key=lambda x: int(x.split('.')[0]))
squares = [cv2.imread(f"squares/{filename}") for filename in square_filenames]

# Create an empty final image with the same size as the video frames
final_image = np.zeros((720, 1280, 3), dtype=np.uint8)

# Calculate the number of squares per row and column
squares_per_row = 1280 // 20
squares_per_col = 720 // 20

# Iterate over all squares and place them in the final image
for i, square in enumerate(squares):
    row = i // squares_per_row
    col = i % squares_per_row
    x_offset = col * 20
    y_offset = row * 20
    final_image[y_offset:y_offset+20, x_offset:x_offset+20] = square

# Display the final image
#cv2.imshow("Final Image", final_image)
cv2.waitKey(0)
cv2.destroyAllWindows()

# Save the final image to a file
cv2.imwrite("final_image.png", final_image)
