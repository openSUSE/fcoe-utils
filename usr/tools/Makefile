# File: open-fcoe/usr/tools/Makefile

#
# List of legal build component names
#
LEGAL_ARCH = i386 i486 i586 i686 x86_64
LEGAL_OS = linux Linux

#
#
# Validating OS and the machine architecture.
#
ifneq "$(filter-out $(LEGAL_ARCH), $(shell uname -i))" ""
    $(error bad build architecture $(shell uname -i))
else
ifneq "$(filter-out $(LEGAL_OS), $(shell uname -s))" ""
    $(error bad build OS $(shell uname -s))
else

CC = gcc
LD = gcc
INSTALL = install
RM = rm

DATE=`date "+%D-%T"`
OSNAME = $(shell uname -s)

# If HBALINUX is not defined, set it to default
ifeq ($(HBALINUX),)
	HBALINUX=/usr/local/src/hbalinux
endif

CFLAGS += -fPIC -O0 -g -Wall -Werror
CFLAGS += -D$(OSNAME) -DBUILD_DATE="\"${DATE}\""
CFLAGS += -I.
CFLAGS += -I$(HBALINUX)/include
CFLAGS += -I$(HBALINUX)/hbaapi_src_2.2

LIBRARIES = -ldl -lHBAAPI

ifeq ($(shell uname -i),x86_64)
	CFLAGS += -m64
	LDFLAGS += $(LIBRARIES)
else
	CFLAGS += -m32
	LDFLAGS += -melf_i386 $(LIBRARIES)
endif

PROGRAMS = fcoeadm

default: all

all: $(PROGRAMS)

clean:
	@$(RM) -f *.o .depend $(PROGRAMS) > /dev/null 2>&1

.c.o:
	@echo '       CC PIC' $<
	@$(CC) $(CFLAGS) -c -o $@ $<

fcoeadm: fcoeadm_display.o fcoeadm.o
	@echo '       LINK' $@
	@$(LD) -o $@ $(LDFLAGS) $^

install: all
	@echo '       INSTALL' $(PROGRAMS)
	@$(INSTALL) fcoeadm /usr/local/bin

uninstall:
	@$(RM) -f /usr/local/bin/fcoeadm > /dev/null 2>&1

endif
endif
