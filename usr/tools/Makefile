# File: open-fcoe/usr/tools/Makefile

#
# Installation directory of the tools
#
INSTALL_DIR=/sbin

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

CFLAGS += -fPIC -O0 -g -Wall -Werror
CFLAGS += -D$(OSNAME) -DBUILD_DATE="\"${DATE}\""
CFLAGS += -I.
CFLAGS += -I$(LIBHBALINUX)/include
CFLAGS += -I$(LIBHBALINUX)/hbaapi_src_2.2

ifeq ($(shell uname -i),x86_64)
	CFLAGS += -m64
else
	CFLAGS += -m32
	LDFLAGS += -melf_i386
endif

PROGRAMS = fcoeadm

default: all

all: $(PROGRAMS)

clean:
	@$(RM) -f *.o version.* $(PROGRAMS) > /dev/null 2>&1

.c.o:
	@echo '       CC PIC' $<
	@$(CC) $(CFLAGS) -c -o $@ $<

fcoeadm: version.o fcoeadm_display.o fcoeadm.o
	@echo '       LINK' $@
	@$(LD) -o $@ $(LDFLAGS) -ldl -lHBAAPI $^

install: all
	@$(if $(PROGRAMS), $(foreach i, $(PROGRAMS), \
		$(INSTALL) -v -m 775 $(i) $(INSTALL_DIR); ))

uninstall:
	@$(if $(PROGRAMS), $(foreach i, $(PROGRAMS), \
		$(RM) -v -f $(INSTALL_DIR)/$(i); ))

version.c: FORCE
	@echo '       BUILD $(@F)'
	@$(RM) -f $@
	@echo char tools_version[] = '"'$(BUILD_VERSION) $(shell date)'";' > $@

.PHONY: FORCE

endif
endif
