AC_INIT([flstats], [`cat VERSION`])
AC_CONFIG_AUX_DIR(build-aux)
AC_CONFIG_MACRO_DIR([build-aux/m4])
AC_CONFIG_HEADERS([config.h])

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

#  find tcl.  easiest is if pkg-config knows where it is
#  a good reference to PKG_CHECK_MODULES:
#  https://www.flameeyes.eu/autotools-mythbuster/pkgconfig/pkg_check_modules.html

PKG_CHECK_MODULES([TCL],
                  [tcl],
                  [AC_DEFINE([HAVE_TCL], [yes], [Have Tcl])],
                  [have_tcl=no])
AC_SUBST(TCL_CFLAGS)
AC_SUBST(TCL_LIBS)



# _GGM_SEARCH(FILENAME, DIRECTORY-LIST, IF-SUCCESS, IF-FAIL)
# search for a given filename in a list of directories.  defines
# HAVE_${FILENAME} (as it were) for each found file; the value of
# HAVE_${FILENAME} is the path to *a* directory (probably the first or
# the last) in which the file was found
AC_DEFUN([_GGM_SEARCH], [
   for __ggm_dir in [$2] ; do
      AC_CHECK_FILE([[${__ggm_dir}]/$1], [__ggm_search_found=yes], \
                                         [__ggm_search_found=no])
      if test  X${__ggm_search_found} = Xyes ; then
         [$3]
         __ggm_search_name=m4_toupper(AS_TR_SH($1))
         eval "HAVE_${__ggm_search_name}=${__ggm_dir}"
         break;
      fi
   done
   if test X${__ggm_search_found} != Xyes ; then
      # not found
      echo -n                   # if..then..fi complains if $4 is empty
      [$4]
   fi
])

# _GGM_TCL_CONFIG_SH([IF-SUCCESS], [IF-FAIL])
# try to find tclConfig.sh somewhere in the file system (it normally
# lives somewhere like /usr/lib/tclConfig.sh)
AC_DEFUN([_GGM_TCL_CONFIG_SH], [
   AC_MSG_NOTICE([checking for tclConfig.sh])
   __ggm_where=""
   # try to guess some places the file might be
   __ggm_where="[${__ggm_where}] `echo [$LDFLAGS] | \
                                 sed 's/-[[lL]]//g' | sed 's/-//g'`"
   __ggm_where="$[{__ggm_where}] `echo [$LD_LIBRARY_PATH] | sed 's/:/ /g'`"
   _GGM_SEARCH([tclConfig.sh], [${__ggm_where}], [__ggm_tc_found=yes], \
                                                 [__ggm_tc_found=no])
   if test X${__ggm_tc_found} != Xyes ; then
      # http://www.edwardrosten.com/code/autoconf/
      # tcl::pkgconfig would be nice
      # http://wiki.tcl.tk/11825 (first appeared in Tcl version 8.5)
      # http://autogen.sourceforge.net/acquoting.html explains the [[...]]
      # do we have tcl::pkgconfig?  (apparently showed up in Tcl 8.5)
      AC_CHECK_PROG(have_tclsh, "tclsh", [yes], [])
      if test ${have_tclsh} = "yes" ; then
         __ggm_where=""
         if echo "puts [[tcl::pkgconfig list]]" | \
                                          tclsh | grep -q "includedir,install" ; then
            __ggm_where="${__ggm_where} \
                `echo 'puts [[tcl::pkgconfig get includedir,install]]' | tclsh`"
            __ggm_where="${__ggm_where} \
                `echo 'puts [[tcl::pkgconfig get libdir,install]]' | tclsh`"
            # finally, ask tcl's [info library]
            __ggm_where="${__ggm_where} `echo 'puts [[info library]]' | tclsh`"
          _GGM_SEARCH([tclConfig.sh], [${__ggm_where}], [__ggm_tc_found=yes], \
                                                        [__ggm_tc_found=no])
         fi
      fi
   fi
   if test X${__ggm_tc_found} == Xyes ; then
      AC_MSG_NOTICE([tclConfig.sh found in directory ${HAVE_TCLCONFIG_SH}])
   else
      AC_MSG_NOTICE([tclConfig.sh not found])
   fi
])

# pkg-config didn't find it try asking tclConfig.sh.  but,
# where is it?  it might be in /usr/lib, or some such.  so, goal
# *now* is to find tclConfig.sh

if test X${have_tcl} != Xyes ; then
   _GGM_TCL_CONFIG_SH([], [])
   if test X${HAVE_TCLCONFIG_SH} != X ; then
      # read it in
      . ${HAVE_TCLCONFIG_SH}/tclConfig.sh
      TCL_LIBS=${TCL_LIB_SPEC}
      TCL_CFLAGS=${TCL_INCLUDE_SPEC}
      have_tcl=yes
   fi
fi

if test "${have_tcl}" = "0" ; then
   echo "cannot find tcl!"
   exit 1
fi
   
CPPFLAGS="${CPPFLAGS} ${TCL_CFLAGS}"
LIBS="${LIBS} ${TCL_LIBS}"
AC_SUBST(have_tcl)

# now, find libpcap

# now, check for asprintf
AC_CHECK_FUNCS([asprintf])
# check for <errno.h>
AC_CHECK_HEADERS([errno.h])


AC_CONFIG_FILES([Makefile])
AC_OUTPUT
