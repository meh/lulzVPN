LIB=-lpthread -lssl -lreadline -lcrypt
OPT=-Wall -Wextra -pedantic -g
CC=gcc

all: 
	@echo Building lulzNet suite - lulz p2p vpn 
	@echo Version 0.0.1
	@indent -l 512 src/lulznet/*.c
	@indent -l 512 src/lulznet/headers/*.h
	@rm src/lulznet/*~ src/lulznet/headers/*~
	@echo Compiling lulzNet 
	@$(CC) src/lulznet/*.c $(LIB) $(OPT) -o bin/lulzNet
	@echo Compiling tools
	@$(CC) src/tools/ug.c $(OPT) -lssl -o bin/lulzNet_ug
