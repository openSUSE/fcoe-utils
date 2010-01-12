AC_INIT([fcoe-utils], [1.0.10], [devel@open-fcoe.org])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AC_PROG_CC
AM_PROG_CC_C_O

PKG_CHECK_MODULES([HBAAPI], [HBAAPI])
AC_SUBST([HBAAPI_CFLAGS])
AC_SUBST([HBAAPI_LIBS])

AC_ARG_WITH([dcb],
	[AS_HELP_STRING([--without-dcb], [disable DCB support])],
	[],
	[with_dcb=yes])

AM_CONDITIONAL([WITH_DCB], [test "X$with_dcb" != Xno])

AS_IF([test "X$with_dcb" != Xno],
	[PKG_CHECK_MODULES([DCBD], [dcbd])
	AC_SUBST([DCBD_CFLAGS])])

AC_CONFIG_FILES([Makefile fcoe-utils.spec fcoe_utils.h])
AC_OUTPUT

