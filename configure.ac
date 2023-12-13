AC_INIT([fcoe-utils], [1.0.34], [https://github.com/openSUSE/fcoe-utils])

m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AM_INIT_AUTOMAKE([foreign])

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_RANLIB

PKG_CHECK_MODULES([LLDPAD], [lldpad >= 0.9.46])
AC_SUBST([LLDPAD_CFLAGS])

PKG_CHECK_MODULES([PCIACCESS], [pciaccess])
AC_SUBST([PCIACCESS_LIBS])

PKG_PROG_PKG_CONFIG
AC_ARG_WITH([systemdsystemunitdir],
        AS_HELP_STRING([--with-systemdsystemunitdir=DIR],
			[Directory for systemd service files]), [],
			[with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])
AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
AM_CONDITIONAL(HAVE_SYSTEMD, [test -n "$with_systemdsystemunitdir"])

AC_ARG_WITH([vendordir],
  AS_HELP_STRING([--with-vendordir=DIR], [Directory for distribution provided configuration files]),
  [], []
)

AC_SUBST([vendordir], [$with_vendordir])
AM_CONDITIONAL([USE_VENDORDIR], [test "x$with_vendordir" != x])
AS_IF([test "x$with_vendordir" != x], [
  AC_DEFINE([USE_VENDORDIR], [1], [Define to 1 to use vendordir])
])

AC_CONFIG_FILES([Makefile fcoe-utils.spec include/fcoe_utils_version.h])
AC_OUTPUT

AC_MSG_RESULT([

        prefix:                    ${prefix}
        exec prefix:               ${exec_prefix}
        bindir:                    ${bindir}
        sbindir:                   ${sbindir}
        libdir:                    ${libdir}
        includedir:                ${includedir}
        sysconfdir:                ${sysconfdir}
        systemdsystemunitdir:      ${with_systemdsystemunitdir}
        vendordir:                 ${with_vendordir}
	compiler:                  ${CC}
        ldflags:                   ${LDFLAGS}
        cflags:                    ${CFLAGS}
        warnings:                  ${WARN_CFLAGS}

 Type 'make' to compile.
])
