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

MAKE = make

default: all

all:
	@$(foreach i, $(wildcard tools/*), $(MAKE) -C $(i) ; )

clean:
	@$(foreach i, $(wildcard tools/*), $(MAKE) -C $(i) clean ; )

install:
	@$(foreach i, $(wildcard tools/*), $(MAKE) -C $(i) install ; )

uninstall:
	@$(foreach i, $(wildcard tools/*), $(MAKE) -C $(i) uninstall ; )

endif
endif
