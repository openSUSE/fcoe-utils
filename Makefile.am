## target programs, to be built and installed in $(prefix)/sbin
sbin_PROGRAMS = fcoeadm fcoemon

## all targets should look for headers in the include directory
AM_CPPFLAGS = -Iinclude

## pass the sysconfdir into the C proprocessor
AM_CFLAGS = -DSYSCONFDIR="\"${sysconfdir}\""

## rules for building fcoeadm
## only listed sources get packaged, so must list all headers too
fcoeadm_SOURCES = fcoeadm_display.c fcoeadm.c fcoeadm.h \
include/fc_scsi.h include/fc_types.h include/net_types.h

## fcoeadm uses HBAAPI, so get the right flags for compiling and linking
fcoeadm_CFLAGS = $(HBAAPI_CFLAGS)
fcoeadm_LDFLAGS = $(HBAAPI_LIBS)

## rules for building fcoemon
## only listed sources get packaged, so must list all headers too
fcoemon_SOURCES = fcoemon_utils.c fcoemon.c fcoemon.h fcoemon_utils.h \
include/fc_scsi.h include/fc_types.h include/net_types.h

## fcoemon needs headers from dcbd, get the right include path for them
fcoemon_CFLAGS = $(DCBD_CFLAGS)
fcoemon_LDFLAGS = -lrt

## install configuration file in $(prefix)/etc/fcoe
fcoe_configdir = ${sysconfdir}/fcoe
dist_fcoe_config_DATA = etc/config etc/cfg-ethx

## install fcoeplumb script in $(prefix)/etc/fcoe/scripts
fcoe_scriptsdir = ${sysconfdir}/fcoe/scripts
fcoe_scripts_SCRIPTS = fcoeplumb.sh

## man pages for fcoeadm and fcoemon
dist_man_MANS = doc/fcoeadm.8 doc/fcoemon.8

## init script for fcoemon
dist_noinst_SCRIPTS = etc/initd/initd.fcoe etc/initd/initd.suse etc/initd/initd.fedora

CLEANFILES = etc/initd/fcoe
etc/initd/fcoe:
	if [ -f /etc/fedora-release ]; then \
		ln -s initd.fedora $@; \
	elif [ -f /etc/SuSE-release ]; then \
		ln -s initd.suse $@; \
	else \
		ln -s initd.fcoe $@; \
	fi

init_ddir = ${sysconfdir}/init.d
init_d_SCRIPTS = etc/initd/fcoe

dist_noinst_DATA = README COPYING INSTALL

