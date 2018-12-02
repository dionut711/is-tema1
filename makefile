INC = /usr/local/ssl/include/
LIB = /user/local/ssl/lib/

all:
	gcc -I$(INC) -L$(LIB) -o out source.cpp -lcrypto -ldl
	./out
