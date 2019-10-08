CC=gcc

default: builds

builds: injecto.c
	gcc injecto.c -o build/injecto

clean:
	rm -f build/injecto

