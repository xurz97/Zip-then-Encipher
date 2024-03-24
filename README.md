# Zip-then-Encipher

compile:
'''
gcc lz4.c hctr.c timing.c -march=native -O2
'''
run:
'''
rm ./part/*
./split (input a file, for example "./files/mr")
./a.out
'''