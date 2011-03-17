AC_INIT([fcoe-utils], [1.0.18], [devel@open-fcoe.org])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_RANLIB

PKG_CHECK_MODULES([HBAAPI], [HBAAPI])
AC_SUBST([HBAAPI_CFLAGS])
AC_SUBST([HBAAPI_LIBS])

PKG_CHECK_MODULES([LLDPAD], [lldpad])
AC_SUBST([LLDPAD_CFLAGS])

AC_CONFIG_FILES([Makefile fcoe-utils.spec include/fcoe_utils_version.h])
AC_OUTPUT

