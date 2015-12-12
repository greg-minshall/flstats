# $Id: Makefile.in,v 1.26 2009/11/01 18:30:22 minshall Exp $

# version for distribution...
VERS=`cat VERSION`


#have-gcc#CC = gcc
#have-gcc#WARNINGS	= -Wall
#have-gcc#LDFLAGS = -Xlinker
#have-SVR4#SVR4 = -DSVR4

CFLAGS	= -g ${INCLUDES} ${WARNINGS}

SOURCES = Makefile.in flstats.1 flstats.c flstats.tcl flstats.html \
							configure INSTALL

DISTRIBUTION = ${SOURCES} flstats.0 flstats.0.txt

SUFFIXES =	.c .h .o .tcl .char

# turn a .tcl file into a string for a .c file to process...
.tcl.char:
	sed 's/\\/\\\\/g' < $< | sed 's/"/\\"/g' | \
				sed 's/^/"/' | sed 's/$$/\\n"/' > $@


all:	flstats
flstats:		flstats.o
	${CC} ${CFLAGS} -o flstats ${LDFLAGS} \
			flstats.o ${LIBPATH} ${LIBS} ${LIBPCAP} -lm

flstats.o:	flstats.char flstats.c flstats.h config.h

flstats.char:	flstats.tcl

flstats.0:	flstats.1
	nroff -man flstats.1 > flstats.0

flstats.0.txt:	flstats.0
	colcrt < flstats.0 > flstats.0.txt

flstats.html:  flstats.vtml VERSION
	sed -e "s/__VERSION__/${VERS}/g" -e "s/__DATE__/`date "+%d %h %y"`/g" \
					    flstats.vtml > flstats.html

distribution:	fixrev tar.gz web.tar

clean:
	-rm -f flstats flstats.char flstats.o flstats.0 flstats.0.txt \
		flstats-*.tar flstats-*.tar.gz flstats-*.web.tar

# keep version numbers going... (assume always at least "x.y")

# 1.y.z -> 2.0
majorrev:
	co -l VERSION
	awk '{ \
	    n = split($$0,x,"."); \
	    print (x[1]+1)"."0 \
	}' < VERSION > VERSION.new
	mv VERSION.new VERSION
	ci -u -m"new fix version" VERSION

# x.2.z -> x.3
minorrev:
	co -l VERSION
	awk '{ \
	    n = split($$0,x,"."); \
	    print x[1]"."(x[2]+1) \
	}' < VERSION > VERSION.new
	mv VERSION.new VERSION
	ci -u -m"new fix version" VERSION

# x.y.3 -> x.y.4
fixrev:
	co -l VERSION
	awk '{ \
	    n = split($$0,x,"."); \
	    if (n == 2) { \
	        print x[1]"."x[2]".1" \
	    } else { \
	        print x[1]"."x[2]"."(x[3]+1) \
	    } \
	}' < VERSION > VERSION.new
	mv VERSION.new VERSION
	ci -u -m"new fix version" VERSION

tar.gz:	${DISTRIBUTION}
	tar cf flstats-${VERS}.tar ${DISTRIBUTION}
	rm -f flstats-${VERS}.tar.gz
	gzip flstats-${VERS}.tar

web.tar:	tar.gz flstats.html flstats.0.txt
	tar cf flstats-${VERS}.web.tar \
			    flstats-${VERS}.tar.gz flstats.html flstats.0.txt
