## target programs, to be built and installed in $(prefix)/sbin
sbin_PROGRAMS = fcoeadm fcoemon fcping fipvlan fcnsq fcrls

## all targets should look for headers in the include directory
AM_CPPFLAGS = -Wall -I${srcdir}/include

## pass the sysconfdir into the C proprocessor
AM_CFLAGS = -DSYSCONFDIR="\"${sysconfdir}\""

## rules for building fcoeadm
## only listed sources get packaged, so must list all headers too
fcoeadm_SOURCES = fcoeadm_display.c fcoeadm.c fcoeadm.h \
include/fc_scsi.h include/fc_types.h \
include/net_types.h fcoe_clif.h
fcoeadm_LDADD = lib/libutil.a

## fcoeadm uses HBAAPI, so get the right flags for compiling and linking
fcoeadm_CFLAGS = $(HBAAPI_CFLAGS)
fcoeadm_LDFLAGS = $(HBAAPI_LIBS)

## rules for building fcping
## only listed sources get packaged, so must list all headers too
fcping_SOURCES = fcping.c
fcping_LDADD = lib/libutil.a

## fcping uses HBAAPI, so get the right flags for compiling and linking
fcping_CFLAGS = $(HBAAPI_CFLAGS)
fcping_LDFLAGS = $(HBAAPI_LIBS) -lrt

## rules for building fcoemon
## only listed sources get packaged, so must list all headers too
fcoemon_SOURCES = fcoemon.c fcoemon.h \
include/fc_scsi.h \
include/fc_types.h include/net_types.h fcoe_clif.h
fcoemon_LDADD = lib/libutil.a

## fcoemon needs headers from dcbd, get the right include path for them
fcoemon_CFLAGS = $(DCBD_CFLAGS)
fcoemon_LDFLAGS = -lrt

## rules for building fipvlan
## only listed sources get packaged, so must list all headers too
fipvlan_SOURCES = fipvlan.c include/fip.h
fipvlan_LDADD = lib/libutil.a

AUTOMAKE_OPTIONS=subdir-objects
noinst_LIBRARIES = lib/libutil.a
lib_libutil_a_SOURCES = lib/fcoe_utils.c lib/sa_log.c lib/sa_select.c \
	lib/sa_timer.c lib/sa_other.c lib/fip.c lib/rtnetlink.c

## install configuration file in $(prefix)/etc/fcoe
fcoe_configdir = ${sysconfdir}/fcoe
dist_fcoe_config_DATA = etc/cfg-ethx

## man pages for fcoeadm and fcoemon
dist_man_MANS = doc/fcoeadm.8 doc/fcoemon.8

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

install-data-hook:
	if [ ! -f ${DESTDIR}${fcoe_configdir}/config ] ; then \
		cp etc/config ${DESTDIR}${fcoe_configdir}/config; \
	fi
