CC=gcc

default: builds

builds: injecto.c colors.h
	gcc injecto.c -o build/injecto

clean:
	rm -f build/injecto

