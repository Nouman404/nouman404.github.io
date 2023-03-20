# Chunk_of_surprises

In this challenge, we are given a png image. But when we try to open it, we get an error. So we look at the hexadecimal inside the image and we see that the headers and the tailer are not correct.

As we can see on [this website](https://www.garykessler.net/library/file_sigs.html), the png header should be ```89 50 4E 47 0D 0A 1A 0A``` but is ```01 50 4E 47 0D 0A 1A 0A``` so the first bit is not good. The second header should be IHDR but there is no IHDR so we add it by replacing the wrong hex value. We also modify the tailor as for the PNG header and we got the flag.