# This Makefile will work only with GNU make.
OSNAME=$(shell uname -s)
CFLAGS += -O2 -g -Wall -Wstrict-prototypes -I../include -D$(OSNAME)
PROGRAMS=fcoeadm

default: all

all: $(PROGRAMS)

fcoeadm: fcoeadm.o

clean:
	rm -f *.o $(PROGRAMS)
