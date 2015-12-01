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
                  [AC_DEFINE([HAVE_TCL], [yes], [Have Tcl])],
                  [have_tcl=no])
AC_SUBST(TCL_CFLAGS)
AC_SUBST(TCL_LIBS)



# _GGM_SEARCH(FILENAME, DIRECTORY-LIST, IF-SUCCESS, IF-FAIL)
dnl 
# search for a given filename in a list of directories.  defines
# HAVE_${FILENAME} (as it were) for each found file; the value of
# HAVE_${FILENAME} is the path to *a* directory (probably the first or
# the last) in which the file was found
AC_DEFUN(_GGM_SEARCH, [
   for __ggm_dir in $2 ; do 
      AC_CHECK_FILE($1, ${__ggm_dir}, [__ggm_found=yes], [__ggm_found=no])
      if test  ${__ggm_found} = yes ; then
         $3
         __ggm_search_name=AS_TR_SH($1)
         AS_VAR_SET(__ggm_search_name, ${__ggmdir})
         break;
      fi
   done
   if test ${__ggm_found} != yes ; then
      dnl not found
      $4
   fi
])

dnl XXX test _GGM_SEARCH
set -x
_GGM_SEARCH("tclConfig.sh", "/sw /sw/include /swx/include /usr/local /sw/include")


# _GGM_TCL_CONFIG_SH([IF-SUCCESS], [IF-FAIL])
dnl 
# try to find tclConfig.sh somewhere in the file system (it normally
# lives somewhere like /usr/lib/tclConfig.sh)
AC_DEFUN([_GGM_TCL_CONFIG_SH], [
   AC_MSG_NOTICE([checking for tclConfig.sh])
   __ggm_where=""
   # try to guess some places the file might be
   __ggm_where="${__ggm_where} `echo $LDFLAGS | sed 's/-[lL]//g' | sed 's/-//g'`"
   __ggm_where="${__ggm_where} `echo $LD_LIBRARY_PATH | sed 's/:/ /g'`"
   dnl http://www.edwardrosten.com/code/autoconf/
   
   dnl tcl::pkgconfig would be nice
   dnl http://wiki.tcl.tk/11825 (first appeared in Tcl version 8.5)
   dnl http://autogen.sourceforge.net/acquoting.html explains the [[...]]
   dnl do we have tcl::pkgconfig?  (apparently showed up in Tcl 8.5)
   if ${have_tcl} != yes ; then
   AC_CHECK_PROG(have_tclsh, "tclsh", [yes], [])
   if test ${have_tclsh} = "yes" ; then
      if echo "puts [[tcl::pkgconfig list]]" | \
                                       tclsh | grep -q "includedir,install" ; then
         __ggm_where="${__ggm_where} \
             `echo 'puts [[tcl::pkgconfig get includedir,install]]' | tclsh`"
         __ggm_where="${__ggm_where} \
             `echo 'puts [[tcl::pkgconfig get libdir,install]]' | tclsh`"
         dnl finally, ask tcl's [info library]
         __ggm_where="${__ggm_where} `echo 'puts [[info library]]' | tclsh`"
         _GGM_SEARCH([tclConfig.sh], [ $tclincldir $tcllibdir $tcllib ], [$1], [$2])
      fi
   fi
   AC_MSG_NOTICE([tclConfig.sh not found])
])

dnl if pkg-config didn't find it try asking tclConfig.sh.  but,
dnl where is it?  it might be in /usr/lib, or some such.  so, goal
dnl *now* is to find tclConfig.sh

set -x                          dnl XXX
_GGM_TCL_CONFIG_SH([], [])
if test X"${HAVE_TCLCONFIG_SH}" != X ; then
         dnl read it in
         . ${HAVE_TCLCONFIG_SH}/tclConfig.sh
         TCL_LIBS=${TCL_LIB_SPEC}
         TCL_CFLAGS=${TCL_INCLUDE_SPEC}
         have_tcl=yes
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
set +x                          dnl XXX

dnl now, find libpcap


AC_CONFIG_FILES([Makefile])
AC_OUTPUT
