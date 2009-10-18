VERSION	= 0.0.1
NAME	= lulzNet

CC	= g++
CFLAGS	= -Wall -Wextra -pedantic -g -I ./include
LDFLAGS	= -lpthread -lssl -lreadline -lcrypt

LULZNET_FILES = src/auth.c src/config.c src/main.c src/peer.c\
		src/shell.c src/xfunc.c src/log.c src/networking.c\
		src/protocol.c src/tap.c src/packet.c

UG_FILES = var/lulznet_ug.c

all:lulznet ug
	${CC} ${LDFLAGS} -o ${NAME} $(LULZNET_FILES:.c=.o)
	${CC} ${LDFLAGS} -o ug $(UG_FILES:.c=.o) 


lulznet: $(LULZNET_FILES:.c=.o)

$(LULZNET_FILES:.c=.o): $(LULZNET_FILES)
	${CC} ${CFLAGS} ${INCLUDE} -o $*.o -c $*.c

ug: $(UG_FILES:.c=.o)

$(UG_FILES:.c=.o): $(UG_FILES)
	${CC} ${CFLAGS} ${INCLUDE} -o $*.o -c $*.c

indent:
	@indent -l 512 src/*.c
	@rm -f src/*~

clean:
	rm -f src/*.o
	rm -f var/*.o
	rm ${NAME}
	rm ug
