AC_INIT([fcoe-utils], [1.0.30], [fcoe-devel@open-fcoe.org])

m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AM_INIT_AUTOMAKE([foreign])

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_RANLIB

PKG_CHECK_MODULES([HBAAPI], [HBAAPI])
AC_SUBST([HBAAPI_CFLAGS])
AC_SUBST([HBAAPI_LIBS])

PKG_CHECK_MODULES([LLDPAD], [lldpad >= 0.9.46])
AC_SUBST([LLDPAD_CFLAGS])

PKG_CHECK_MODULES([LIBHBALINUX], [libhbalinux >= 1.0.17])
AC_SUBST([LIBHBALINUX_CFLAGS])

PKG_PROG_PKG_CONFIG
AC_ARG_WITH([systemdsystemunitdir],
        AS_HELP_STRING([--with-systemdsystemunitdir=DIR],
			[Directory for systemd service files]), [],
			[with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])
AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
AM_CONDITIONAL(HAVE_SYSTEMD, [test -n "$with_systemdsystemunitdir"])

AC_CONFIG_FILES([Makefile fcoe-utils.spec include/fcoe_utils_version.h])
AC_OUTPUT

