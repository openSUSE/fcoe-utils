#
# Makefile for the Open-FCoE Initiator
#

# set the following corresepondingly to your preferred locations
DESTDIR ?= 

prefix = /usr
exec_prefix = /
sbindir = $(exec_prefix)/sbin
bindir = $(exec_prefix)/bin
mandir = $(prefix)/share/man
etcdir = /etc
initddir = $(etcdir)/init.d

MANPAGES = doc/fcoeadm.8
PROGRAMS = usr/fcoeadm
INSTALL = install

default: all

all:
	$(MAKE) -C usr
	
clean:
	$(MAKE) -C usr clean

install: all install_usr
	@echo 
	@echo -------------------------------------------------
	@echo Please check README file for detailed information.
	@echo Remember to setup the FCoE config file located at: 
	@echo -e "\t$(DESTDIR)$(etcdir)/fcoe/open-fcoe.conf"
	@echo

install_usr: install_programs install_doc install_initd

install_programs:  $(PROGRAMS)
	$(INSTALL) -d $(DESTDIR)$(sbindir)
	$(INSTALL) -m 755 $^ $(DESTDIR)$(sbindir)

install_initd:
	$(INSTALL) -d $(DESTDIR)$(initddir)
	$(INSTALL) -m 755 etc/initd/initd.fcoe \
		$(DESTDIR)$(initddir)/open-fcoe
	$(INSTALL) -d $(DESTDIR)$(etcdir)/fcoe
	$(INSTALL) -m 644 etc/fcoe.conf \
		$(DESTDIR)$(etcdir)/fcoe/open-fcoe.conf

install_doc: $(MANPAGES)
	$(INSTALL) -d $(DESTDIR)$(mandir)/man8
	$(INSTALL) -m 644 $^ $(DESTDIR)$(mandir)/man8
