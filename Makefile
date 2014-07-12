crypt.so : lua-crypt.c
	gcc -g -Wall -fPIC --shared -I/usr/local/include -o $@ $^
