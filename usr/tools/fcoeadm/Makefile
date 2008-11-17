# File: open-fcoe/usr/tools/fcoeadm/Makefile

# set the following corresepondingly to your preferred locations
DESTDIR ?=

#
# Installation directory of the tools
#
EXEC_PREFIX = /
SBINDIR = $(EXEC_PREFIX)sbin
PREFIX = /usr/
MANDIR = $(PREFIX)share/man

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
GZIP = gzip

OSNAME = $(shell uname -s)
MANPAGES = fcoeadm.8

CFLAGS += -fPIC -O0 -g -Wall -Werror
CFLAGS += -D$(OSNAME) -D_GNU_SOURCE
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

install: all install_doc
	@$(if $(PROGRAMS), $(foreach i, $(PROGRAMS), \
		$(INSTALL) -v -m 775 $(i) $(DESTDIR)$(SBINDIR) ; ))

install_doc:
	@$(INSTALL) -d $(DESTDIR)$(MANDIR)/man8
	@$(if $(MANPAGES), $(foreach i, $(MANPAGES), \
		$(INSTALL) -v -m 644 ../../doc/$(i) $(DESTDIR)$(MANDIR)/man8 ; \
		$(RM) -f $(DESTDIR)$(MANDIR)/man8/$(i).gz ; \
		$(GZIP) -9 $(DESTDIR)$(MANDIR)/man8/$(i) ; ))

uninstall:
	@$(if $(PROGRAMS), $(foreach i, $(PROGRAMS), \
		$(RM) -vf $(DESTDIR)$(SBINDIR)/$(i) ; ))
	@$(if $(MANPAGES), $(foreach i, $(MANPAGES), \
		$(RM) -vf $(DESTDIR)$(MANDIR)/man8/$(i).gz ; ))

version.c: FORCE
	@$(if $(LIBHBALINUX),, $(error Error! LIBHBALINUX is not defined,\
		Please read the INSTALL file.))
	@echo '       BUILD $(@F)'
	@$(RM) -f $@
	@echo char tools_version[] = '"'$(BUILD_VERSION) $(shell date)'";' > $@

.PHONY: FORCE

endif
endif
