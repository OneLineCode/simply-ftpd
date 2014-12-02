.PHONY:clean
CC=g++
CXXFLAGS=-Wall -g -D_LOGSCR
BIN=ftpd
OBJS=main.o util.o session.o config.o socket.o \
inner.o
LIBS=-lcrypt

$(BIN):$(OBJS)
	$(CC) $(CXXFLAGS) $^ -o $@ $(LIBS)
%.o:%.c
	$(CC) $(CXXFLAGS) -c $< -o $@
clean:
	rm -f *.o $(BIN)
