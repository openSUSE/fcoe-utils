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

TOOLS = fcoeadm fcoemon
default: all

all:
	@$(foreach i, $(TOOLS), $(MAKE) -f Makefile.$(i) ; )

clean:
	@$(foreach i, $(TOOLS), $(MAKE) -f Makefile.$(i) clean ; )

install:
	@$(foreach i, $(TOOLS), $(MAKE) -f Makefile.$(i) install ; )

uninstall:
	@$(foreach i, $(TOOLS), $(MAKE) -f Makefile.$(i) uninstall ; )

endif
endif
