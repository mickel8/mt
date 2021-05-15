#!/bin/fish

ffmpeg -f lavfi -i testsrc=d=10:s=1920x1080:r=24,format=yuv420p -f lavfi -i sine=f=440:b=4 -shortest sample.mp4

