VERSION	= 0.0.1
NAME	= lulzNet

CC	= gcc
CFLAGS	= -Wall -Wextra -pedantic -g -I ./include
LDFLAGS	= -lpthread -lssl -lreadline -lcrypt

LULZNET_FILES = src/lulznet/auth.c src/lulznet/config.c src/lulznet/main.c src/lulznet/peer.c\
		src/lulznet/shell.c src/lulznet/xfunc.c src/lulznet/log.c src/lulznet/networking.c\
		src/lulznet/protocol.c src/lulznet/tap.c

UG_FILES = src/tools/lulznet_ug.c

all: lulznet ug
	gcc ${LDFLAGS} -o ${NAME} $(LULZNET_FILES:.c=.o)
	gcc ${LDFLAGS} -o ug $(UG_FILES:.c=.o) 


lulznet: $(LULZNET_FILES:.c=.o)

$(LULZNET_FILES:.c=.o): $(LULZNET_FILES)
	${CC} ${CFLAGS} ${INCLUDE} -o $*.o -c $*.c

ug: $(UG_FILES:.c=.o)

$(UG_FILES:.c=.o): $(UG_FILES)
	${CC} ${CFLAGS} ${INCLUDE} -o $*.o -c $*.c

indent:
	@indent src/lulznet/*.c
	@rm src/lulznet/*~

clean:
	rm src/lulznet/*.o
	rm ${NAME}
	rm ug
