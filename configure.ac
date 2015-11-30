AC_INIT([flstats], [1.0])
AC_CONFIG_AUX_DIR(build-aux)
AC_CONFIG_MACRO_DIR([build-aux/m4])
AC_CONFIG_SRCDIR([.])

AM_INIT_AUTOMAKE

AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_CPP

LT_INIT

dnl there *is* a library of autoconf macros
dnl at http://www.gnu.org/software/autoconf-archive/
dnl but, it doesn't include pcap, and only looks for
dnl the tcl and wish executables.

dnl http://article.gmane.org/gmane.os.apple.fink.beginners/25062/match=zlib
dnl fink doesn't provide zlib, since macosx has it.  but, apparently,
dnl pkg-config doesn't know where to find it on macosx.

PKG_CHECK_MODULES([TCL],
                  [tcl],
                  [AC_DEFINE([HAVE_TCL], [1], [Have Tcl])],
                  [have_tcl=0])
AC_SUBST(TCL_CFLAGS)
AC_SUBST(TCL_LIBS)
CPPFLAGS="${CPPFLAGS} ${TCL_CFLAGS}"
LIBS="${LIBS} ${TCL_LIBS}"
AC_SUBST(have_tcl)

dnl now, find libpcap


AC_CONFIG_FILES([Makefile])
AC_OUTPUT
