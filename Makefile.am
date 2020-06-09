## target programs, to be built and installed in $(prefix)/sbin
sbin_PROGRAMS = fcoeadm fcoemon fcping fipvlan fcnsq fcrls

## all targets should look for headers in the include directory
AM_CPPFLAGS = -I${srcdir}/include -I${builddir}/include
## pass the sysconfdir into the C proprocessor
AM_CPPFLAGS += -DSYSCONFDIR="\"${sysconfdir}\"" -D_FORTIFY_SOURCE=2
AM_CFLAGS = -Wall -Wformat=2 -Werror -Wextra -Wmissing-prototypes -Wstrict-prototypes

## rules for building fcoeadm
fcoeadm_SOURCES = fcoeadm.c fcoeadm_display.c
fcoeadm_LDADD = lib/libutil.a libopenfcoe.a $(PCIACCESS_LIBS)
fcoeadm_CFLAGS = $(AM_CFLAGS)

## rules for building fcoemon
fcoemon_SOURCES = fcoemon.c
fcoemon_LDADD = lib/libutil.a -lrt
fcoemon_CFLAGS = $(AM_CFLAGS) $(DCBD_CFLAGS)

## rules for building fcping
fcping_SOURCES = fcping.c
fcping_LDADD = lib/libutil.a libopenfcoe.a $(PCIACCESS_LIBS) -lrt
fcping_CFLAGS = $(AM_CFLAGS)

## rules for building fipvlan
fipvlan_SOURCES = fipvlan.c
fipvlan_LDADD = lib/libutil.a

AUTOMAKE_OPTIONS=subdir-objects
noinst_LIBRARIES = lib/libutil.a libopenfcoe.a
lib_libutil_a_SOURCES = lib/fcoe_utils.c lib/sa_log.c lib/sa_select.c \
	lib/sa_timer.c lib/sa_other.c lib/fip.c lib/rtnetlink.c lib/sa_sys.c \
	lib/sysfs_hba.c
libopenfcoe_a_SOURCES = libopenfcoe.c

## header files that need to be distributed
noinst_HEADERS = fcoeadm_display.h fcoe_clif.h fcoemon.h \
	include/fcoemon_utils.h include/fcoe_utils.h include/fc_scsi.h \
	include/fc_types.h include/fip.h include/net_types.h include/rtnetlink.h \
	include/libopenfcoe.h include/scsi_netlink_fc.h include/scsi_netlink.h \
	include/strarr.h include/fc_ns.h include/fc_gs.h include/fc_els.h include/scsi_bsg_fc.h \
	include/sysfs_hba.h include/linux/rtnetlink.h include/linux/types.h include/linux/dcbnl.h

## install configuration file in $(prefix)/etc/fcoe
fcoe_configdir = ${sysconfdir}/fcoe
dist_fcoe_config_DATA = etc/cfg-ethx

## install systemd service files
if HAVE_SYSTEMD
dist_systemdsystemunit_DATA = etc/systemd/fcoe.service etc/systemd/fcoemon.socket
endif

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

dist_noinst_DATA = README COPYING INSTALL CONFIGURE QUICKSTART fcoe-utils.spec etc/config

bashcompletiondir = $(datadir)/bash-completion/completions
dist_bashcompletion_DATA = contrib/bash_completion/fcoeadm contrib/bash_completion/fcoemon

install-data-hook:
	if [ ! -f ${DESTDIR}${fcoe_configdir}/config ] ; then \
		cp ${srcdir}/etc/config ${DESTDIR}${fcoe_configdir}/config; \
	fi;

uninstall-hook:
	rm ${DESTDIR}${fcoe_configdir}/config

AM_DISTCHECK_CONFIGURE_FLAGS = --with-systemdsystemunitdir='$${prefix}/lib/systemd/system'
