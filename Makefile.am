## target programs, to be built and installed in $(prefix)/sbin
sbin_PROGRAMS = fcoeadm fcping fipvlan fcnsq fcrls
if WITH_DCB
sbin_PROGRAMS += fcoemon
endif

## all targets should look for headers in the include directory
AM_CPPFLAGS = -Wall -I${srcdir}/include

## pass the sysconfdir into the C proprocessor
AM_CFLAGS = -DSYSCONFDIR="\"${sysconfdir}\""

## rules for building fcoeadm
## only listed sources get packaged, so must list all headers too
fcoeadm_SOURCES = fcoeadm_display.c fcoeadm.c fcoeadm.h fcoe_utils.h \
include/fc_scsi.h include/fc_types.h include/net_types.h fcoe_clif.c fcoe_clif.h

## fcoeadm uses HBAAPI, so get the right flags for compiling and linking
fcoeadm_CFLAGS = $(HBAAPI_CFLAGS)
fcoeadm_LDFLAGS = $(HBAAPI_LIBS)

## rules for building fcping
## only listed sources get packaged, so must list all headers too
fcping_SOURCES = fcping.c

## fcping uses HBAAPI, so get the right flags for compiling and linking
fcping_CFLAGS = $(HBAAPI_CFLAGS)
fcping_LDFLAGS = $(HBAAPI_LIBS) -lrt

## rules for building fcoemon
## only listed sources get packaged, so must list all headers too
fcoemon_SOURCES = fcoemon_utils.c fcoemon.c fcoemon.h fcoemon_utils.h \
fcoe_utils.h include/fc_scsi.h include/fc_types.h include/net_types.h \
fcoe_clif.c fcoe_clif.h

## fcoemon needs headers from dcbd, get the right include path for them
fcoemon_CFLAGS = $(DCBD_CFLAGS)
fcoemon_LDFLAGS = -lrt

## rules for building fipvlan
## only listed sources get packaged, so must list all headers too
fipvlan_SOURCES = fipvlan.c fcoe_utils.h include/fip.h \
log.c include/log.h include/list.h

## install configuration file in $(prefix)/etc/fcoe
fcoe_configdir = ${sysconfdir}/fcoe
dist_fcoe_config_DATA = etc/config etc/cfg-ethx

## man pages for fcoeadm and fcoemon
dist_man_MANS = doc/fcoeadm.8
if WITH_DCB
dist_man_MANS += doc/fcoemon.8
endif

## init script for fcoemon
dist_noinst_SCRIPTS = etc/initd/initd.suse etc/initd/initd.fedora

CLEANFILES = etc/initd/fcoe
etc/initd/fcoe:
	mkdir -p etc/initd
	if [ -f /etc/fedora-release ] || [ -f /etc/redhat-release ]; then \
		ln -s ${abs_srcdir}/etc/initd/initd.fedora $@; \
	else \
		ln -s ${abs_srcdir}/etc/initd/initd.suse $@; \
	fi

init_ddir = ${sysconfdir}/init.d
init_d_SCRIPTS = etc/initd/fcoe

dist_noinst_DATA = README COPYING INSTALL fcoe-utils.spec

