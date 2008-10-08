# File: /open-fcoe/usr/Makefile

# set the following corresepondingly to your preferred locations
DESTDIR ?=

prefix = /usr
exec_prefix = /
sbindir = $(exec_prefix)/sbin
bindir = $(exec_prefix)/bin
mandir = $(prefix)/share/man
etcdir = /etc
initddir = $(etcdir)/init.d

MANPAGES = fcoeadm.8

INSTALL = install
MAKE = make
GZIP = gzip
RM = rm

default: all

all:
	$(MAKE) LIBHBALINUX="$(LIBHBALINUX)" -C tools

clean:
	$(MAKE) -C tools clean

install: install_tools
	@echo
	@echo -------------------------------------------------
	@echo Please check README file for detailed information.
	@echo Remember to setup the FCoE config file located at:
	@echo -e "\t$(DESTDIR)$(etcdir)/fcoe/open-fcoe.conf"
	@echo

uninstall: uninstall_tools

install_tools: install_doc install_initd
	$(MAKE) LIBHBALINUX=$(LIBHBALINUX) -C tools install

uninstall_tools:
	$(MAKE) -C tools uninstall

install_initd:
	@$(INSTALL) -d $(DESTDIR)$(initddir)
	@$(INSTALL) -m 755 etc/initd/initd.fcoe $(DESTDIR)$(initddir)/open-fcoe
	@$(INSTALL) -d $(DESTDIR)$(etcdir)/fcoe
	@$(INSTALL) -m 644 etc/fcoe.conf $(DESTDIR)$(etcdir)/fcoe/open-fcoe.conf

install_doc:
	@$(INSTALL) -d $(DESTDIR)$(mandir)/man8
	@$(if $(MANPAGES), $(foreach i, $(MANPAGES), \
		$(INSTALL) -m 644 doc/$(i) $(DESTDIR)$(mandir)/man8 ; \
		$(RM) -f $(DESTDIR)$(mandir)/man8/$(i).gz ; \
		$(GZIP) -9 $(DESTDIR)$(mandir)/man8/$(i) ; \
	))

