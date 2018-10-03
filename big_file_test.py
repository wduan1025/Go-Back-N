import os
import sys
os.system("rm -rf src.txt dst.txt")
os.system("touch src.txt dst.txt")
num = 100000000
'''
step_size = num/1000
if step_size == 0:
    step_size = 1
'''
if len(sys.argv) > 1:
    num = int(sys.argv[1])
with open("src.txt", "w") as f:
    for i in range(num):
        f.write("a")
        if i % 100 == 0:
            f.write(str(i))
