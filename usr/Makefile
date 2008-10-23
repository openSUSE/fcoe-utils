# File: /open-fcoe/usr/Makefile

#
# List of legal build component names
#
LEGAL_ARCH = i386 i486 i586 i686 x86_64
LEGAL_OS = linux Linux

#
# Validating OS and the machine architecture.
#
ifneq "$(filter-out $(LEGAL_ARCH), $(shell uname -i))" ""
    $(error bad build architecture $(shell uname -i))
else
ifneq "$(filter-out $(LEGAL_OS), $(shell uname -s))" ""
    $(error bad build OS $(shell uname -s))
else

# set the following corresepondingly to your preferred locations
DESTDIR ?=

ETCDIR = /etc
INITDDIR = $(ETCDIR)/init.d

INSTALL = install
MAKE = make
GZIP = gzip
RM = rm

default: all

all:
	@$(foreach i, $(wildcard tools/*), $(MAKE) -C $(i) ; )

clean:
	@$(foreach i, $(wildcard tools/*), $(MAKE) -C $(i) clean ; )

install: install_initd
	@$(foreach i, $(wildcard tools/*), $(MAKE) -C $(i) install ; )

uninstall: uninstall_initd
	@$(foreach i, $(wildcard tools/*), $(MAKE) -C $(i) uninstall ; )

install_initd:
	@$(INSTALL) -d $(DESTDIR)$(ETCDIR)/fcoe
	@$(INSTALL) -v -m 644 etc/fcoe.conf $(DESTDIR)$(ETCDIR)/fcoe/open-fcoe.conf
	@$(INSTALL) -d $(DESTDIR)$(INITDDIR)
	@$(INSTALL) -v -m 755 etc/initd/initd.fcoe $(DESTDIR)$(INITDDIR)/open-fcoe
	@echo
	@echo -------------------------------------------------
	@echo Please check INSTALL file for detailed information.
	@echo Remember to setup the FCoE config file located at:
	@echo -e "\t$(DESTDIR)$(ETCDIR)/fcoe/open-fcoe.conf"
	@echo

uninstall_initd:
	@$(RM) -vf $(DESTDIR)$(ETCDIR)/fcoe/open-fcoe.conf
	@$(RM) -vf $(DESTDIR)$(INITDDIR)/open-fcoe

endif
endif
