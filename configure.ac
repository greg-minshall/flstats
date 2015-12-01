AC_INIT([flstats], [`cat VERSION`])
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

dnl  find tcl.  easiest is if pkg-config knows where it is
dnl  a good reference to PKG_CHECK_MODULES:
dnl  https://www.flameeyes.eu/autotools-mythbuster/pkgconfig/pkg_check_modules.html

PKG_CHECK_MODULES([TCL],
                  [tclx],       dnl XXX
                  [AC_DEFINE([HAVE_TCL], [1], [Have Tcl])],
                  [have_tcl=0])
AC_SUBST(TCL_CFLAGS)
AC_SUBST(TCL_LIBS)

AC_CHECK_PROG(have_tclsh, "tclsh", [yes], [])

if test ${have_tclsh} = "yes" ; then
   dnl if pkg-config didn't find it
   dnl try asking tclsh
   dnl if *that* didn't work, try tcl::pkgconfig
   dnl http://wiki.tcl.tk/11825 (first appeared in Tcl version 8.5)
   dnl http://autogen.sourceforge.net/acquoting.html explains the [[...]]
   if test "${have_tcl}" != "1" ; then
      TCL_CFLAGS=`echo 'puts [[tcl::pkgconfig get includedir,install]]' | tclsh`
      TCL_LIBS=`echo 'puts [[tcl::pkgconfig get libdir,install]]' | tclsh`
      have_tcl=1
   fi
   if test "${have_tcl}" != "1" ; then
      tcllib=`echo 'puts [[info library]]' | tclsh`
         AC_CHECK_FILE([${tcllib}/tclConfig.sh], [have_tcl=1], [])
         if test "$HAVE_FILE_TCLCONFIG_H"X != "X" ; then
            dnl read it in
            . ${tcllib}/tclConfig.sh
            TCL_LIBS=${TCL_LIB_SPEC} ${TCL_LIB_FLAG}
            TCL_CFLAGS=${TCL_INCLUDE_SPEC}
            have_tcl=1
        fi
    fi
fi

echo have_tcl ${have_tcl}
echo TCL_LIBS ${TCL_LIBS}
echo TCL_CFLAGS ${TCL_CFLAGS}

if test "${have_tcl}" = "0" ; then
   echo "can't find tcl!"
   exit 1
fi
   
CPPFLAGS="${CPPFLAGS} ${TCL_CFLAGS}"
LIBS="${LIBS} ${TCL_LIBS}"
AC_SUBST(have_tcl)

dnl now, find libpcap


AC_CONFIG_FILES([Makefile])
AC_OUTPUT
