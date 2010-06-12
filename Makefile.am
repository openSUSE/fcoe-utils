## target programs, to be built and installed in $(prefix)/sbin
sbin_PROGRAMS = fcoeadm fcoemon fcping fipvlan fcnsq fcrls

## all targets should look for headers in the include directory
AM_CPPFLAGS = -I${srcdir}/include -I${builddir}/include
## pass the sysconfdir into the C proprocessor
AM_CPPFLAGS += -DSYSCONFDIR="\"${sysconfdir}\""
AM_CFLAGS = -Wall

## rules for building fcoeadm
fcoeadm_SOURCES = fcoeadm.c fcoeadm_display.c
fcoeadm_LDADD = lib/libutil.a
fcoeadm_CFLAGS = $(AM_CFLAGS) $(HBAAPI_CFLAGS)
fcoeadm_LDFLAGS = $(AM_LDFLAGS) $(HBAAPI_LIBS)

## rules for building fcoemon
fcoemon_SOURCES = fcoemon.c
fcoemon_LDADD = lib/libutil.a
fcoemon_CFLAGS = $(AM_CFLAGS) $(DCBD_CFLAGS)
fcoemon_LDFLAGS = $(AM_LDFLAGS) -lrt

## rules for building fcping
fcping_SOURCES = fcping.c
fcping_LDADD = lib/libutil.a
fcping_CFLAGS = $(AM_CFLAGS) $(HBAAPI_CFLAGS)
fcping_LDFLAGS = $(AM_LDFLAGS) $(HBAAPI_LIBS) -lrt

## rules for building fipvlan
fipvlan_SOURCES = fipvlan.c
fipvlan_LDADD = lib/libutil.a

AUTOMAKE_OPTIONS=subdir-objects
noinst_LIBRARIES = lib/libutil.a
lib_libutil_a_SOURCES = lib/fcoe_utils.c lib/sa_log.c lib/sa_select.c \
	lib/sa_timer.c lib/sa_other.c lib/fip.c lib/rtnetlink.c

## header files that need to be distributed
noinst_HEADERS = fcoeadm_display.h fcoe_clif.h fcoemon.h \
	include/fcoemon_utils.h include/fcoe_utils.h include/fc_scsi.h \
	include/fc_types.h include/fip.h include/net_types.h include/rtnetlink.h

## install configuration file in $(prefix)/etc/fcoe
fcoe_configdir = ${sysconfdir}/fcoe
dist_fcoe_config_DATA = etc/cfg-ethx

## man pages for fcoeadm and fcoemon
dist_man_MANS = doc/fcoeadm.8 doc/fcoemon.8 doc/fipvlan.8 doc/fcrls.8 \
	doc/fcnsq.8 doc/fcping.8

## init script for fcoemon
dist_noinst_SCRIPTS = etc/initd/initd.suse etc/initd/initd.fedora \
	contrib/fcc.sh contrib/fcoe-setup.sh contrib/fcoe_edd.sh \
	debug/dcbcheck.sh debug/fcoedump.sh

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

dist_noinst_DATA = README COPYING INSTALL fcoe-utils.spec etc/config

install-data-hook:
	if [ ! -f ${DESTDIR}${fcoe_configdir}/config ] ; then \
		cp ${srcdir}/etc/config ${DESTDIR}${fcoe_configdir}/config; \
	fi
