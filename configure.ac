AC_INIT([flstats], [`cat VERSION`])
AC_CONFIG_AUX_DIR(build-aux)
AC_CONFIG_MACRO_DIR([build-aux/m4])
AC_CONFIG_HEADERS([config.h])

dnl from http://wiki.tcl.tk/5464 and
dnl http://core.tcl.tk/sampleextension/artifact/d88ec8fbb6adb474
TEA_INIT([3.9])
dnl AC_CONFIG_AUX_DIR(tclconfig)


AM_INIT_AUTOMAKE

AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_CPP

LT_INIT

# there *is* a library of autoconf macros
# at http://www.gnu.org/software/autoconf-archive/
# but, it doesn't include pcap, and only looks for
# the tcl and wish executables.

# http://article.gmane.org/gmane.os.apple.fink.beginners/25062/match=zlib
# fink doesn't provide zlib, since macosx has it.  but, apparently,
# pkg-config doesn't know where to find it on macosx.

# something w.r.t. finding Tcl:
#    http://computer-programming-forum.com/57-tcl/8bd748f9302c4cdc.htm

# tclconfig is a directory containing tcl.m4:
# http://wiki.tcl.tk/5464
# which suggests
# ----
# wget -qO- http://core.tcl.tk/tclconfig/tarball/tclconfig.tar.gz | tar xzv
# ----
# to get tcl.m4 in directory tclconfig


TEA_PATH_TCLCONFIG
TEA_LOAD_TCLCONFIG
TEA_PREFIX

# now, find pcap.h
AC_CHECK_HEADERS([pcap.h])

# now, find libpcap
AC_SEARCH_LIBS([pcap_open_offline], [pcap], [],
                                    [AC_MSG_ERROR([could not find libpcap])])

# now, check for asprintf
AC_CHECK_FUNCS([asprintf])
# check for <errno.h>
AC_CHECK_HEADERS([errno.h])


TEA_SETUP_COMPILER
TEA_PUBLIC_TCL_HEADERS
TEA_CONFIG_CFLAGS

CPPFLAGS="${CPPFLAGS} ${TCL_CFLAGS} ${TCL_INCLUDES}"
AC_SUBST(have_tcl)


AC_CONFIG_FILES([Makefile])
AC_OUTPUT
