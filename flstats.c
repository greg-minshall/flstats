/*
 * Copyright (c) 1996
 *	Ipsilon Networks, Inc.
 *
 * please see terms and conditions of copyright at the end of this file
 */

/*
 * output flow statistics from a tcpdump file.
 *
 */

static char *flstats_c_rcsid = "$Id$"

#include "config.h"

#define _GNU_SOURCE		/* needed for asprintf(3) */

#if defined(HAVE_ERRNO_H)
/* http://blog.nirkabel.org/2009/01/18/errnoh-problem/comment-page-1/ */
#include <errno.h>
#endif /* defined(HAVE_ERRNO_H) */
#include <signal.h>
#if !defined(HAVE_ASPRINTF)
#include <stdarg.h>
#endif /* !defined(HAVE_ASPRINTF) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/types.h>

#include <pcap.h>
#include <tcl.h>

#include "flstats.h"


/* global variables */

u_char protohasports[256];

u_short IPtype = 0x800;

int fileeof = 0;
int filetype = 0;

flowentry_p buckets[31979];
flowentry_p onebehinds[NUM(buckets)];
flowentry_p table;			/* list of everything */
flowentry_p table_last;			/* last of everything */
flowentry_p flow_enum_state;

struct timeval curtime, starttime;

struct timeval ZERO = { 0, 0 };

ri_t ri;                        /* reporting interval structure */

/*
 * delta time reporting:
 *
 * (BOT == beginning of trace run; RI == reporting interval)
 *
 * absolute: absolute time (secs.usecs since epoch)
 * within_tr: BOT relative time (secs.usecs since BOT)
 * within_ri: RI relative time (secs.usecs within RI)
 *
 * (note that "within_ri" does *not* make sense for reporting the
 * start time of the RI itself; delta_ri.delta can *only* be
 * 'absolute' or 'within_tr')
 *
 * then, secs.usecs?  or, just secs?
 */

typedef enum { absolute, within_tr, within_ri, invalid } delta_t;
typedef enum { secs, usecs, invalid_usecs } usecs_t;

typedef struct {
    delta_t delta;
    usecs_t usecs;
} time_how_t, *time_how_p;

time_how_t th_wi, th_ri; /* "within ri", "reporting interval itself" */


int binsecs = 0;		/* number of seconds in a bin */

ftinfo_t ftinfo[10];		/* number of distinct flow types in use */

llcl_t llclasses[NUM(ftinfo)];

/*
 * application defined "classes".  Clstats[0] is special, in that
 * it gets any counts not tied to any other flow type or flow.
 */
clstats_t clstats[NUM(ftinfo)];
clstats_p class_enum_state;

int flow_types = 0;

pcap_t *pcap_descriptor;

int pcap_dlt,		/* data link type of input file */
    pcap_snap;		/* snap length of input file */

pcap_handler pcap_receiver;

char pcap_errbuf[PCAP_ERRBUF_SIZE];

/* FDDI stuff */

/*
 * This is a place where pcap is a bit messed up (should be two DLTs).
 */


#if defined(ultrix) || defined(__alpha)
#define FDDIPAD 3
#else
#define FDDIPAD 0
#endif

int fddipad = FDDIPAD;

int packet_error = 0;

int pending, pendingcaplen, pendingpktlen, pending_maxpktlen;
u_char *pending_packet, *pktbuffer;;

flowentry_t timers[150];

u_long pktcount, signalled, lastsignalled;

char	*args,			/* arguments... */
	argcount[200];		/* number of them */

char fl_tclprogram[] = 
#include "flstats.char"
;


/*
 * signal handling
 */

static void
gotsignal(int which)
{
    signalled++;
}


/*
 * forward declarations
 */

static void delete_flow(flowentry_p fe);


/*
 * return the microseconds from a struct timeval
 */

static long
tvusecs(suseconds_t su_usecs)
{
    long usecs = su_usecs;

    return usecs;
}

    
/*
 * return the correct secs (based on delta_wi) for a timeval
 */

static long
dtsecs(struct timeval *tv, time_how_t th)
{
    switch (th.delta) {
    case absolute:
        return tv->tv_sec;
    case within_tr:
        return TIMEDIFFSECS(tv, &starttime);
    case within_ri:
        return TIMEDIFFSECS(tv, &ri.ri_starttime);
    default:
        fprintf(stderr, "%s:%d: delta parameter, invalid value\n",
                __FILE__, __LINE__);
        exit(1);
        /*NOTREACHED*/
    }
}

/*
 * return the correct usecs (based on delta_wi) for a timeval
 */

static long
dtusecs(struct timeval *tv, time_how_t th) {
    switch (th.delta) {
    case absolute:
        return tvusecs(tv->tv_usec);
    case within_tr:
        return tvusecs(TIMEDIFFUSECS(tv, &starttime));
    case within_ri:
        return tvusecs(TIMEDIFFUSECS(tv, &ri.ri_starttime));
    default:
        fprintf(stderr, "%s:%d: delta parameter, invalid value\n",
                __FILE__, __LINE__);
        exit(1);
        /*NOTREACHED*/
    }
}


static long
dtsecs_wi(struct timeval *tv)
{
    return dtsecs(tv, th_wi);
}

static long
dtsecs_ri(struct timeval *tv)
{
    return dtsecs(tv, th_ri);
}

static long
dtusecs_wi(struct timeval *tv)
{
    return dtusecs(tv, th_wi);
}

static long
dtusecs_ri(struct timeval *tv)
{
    return dtusecs(tv, th_ri);
}



/*
 * save a string
 */

char *
strsave(const char *s)
{
    int n = strlen(s);
    char *new;

    new = (char *) malloc(n+1);
    if (new) {
        strncpy(new, s, n+1);
    }
    return new;
}

#if !defined(HAVE_ASPRINTF)
/*
 * slow, but simple (hopefully, almost *never* needed)
 */
static int
asprintf(char **where, const char *format, ...) {
    va_list ap;
    char foo[1];                 /* used in determining the correct size */
    char *place;
    int len;                    /*  */

    va_start(ap, format);
     /* this first call does no real printing, just determines size */
    len = vsnprintf(foo, 0, format, ap);

    place = malloc(len);
    if (place == 0) {
        *where = 0;
        return -1;              /* see man page for asprintf(3) */
    }

    vsnprintf(place, len, format, ap);
    *where = place;
    return len;
}
#endif /* !defined(HAVE_ASPRINTF) */

/*
 * delete a string returned from asprintf(3)
 * (in a way that makes Tcl_SetResult(3) happy, sigh)
 */

static void
tclasfree(char *tofree)
{
    free(tofree);
}


/*
 * identify a packet for an error message
 */

char *
pktloc()
{
    static char loc[100];

    sprintf(loc, "%ld", pktcount);
    return loc;
}

/*
 * a new file is being opened, so clean up from the last one.
 */

static int
newfile(Tcl_Interp *interp, int maxpktlen)
{
    flowentry_p fe, nfe;
    clstats_p cl;
    extern int errno;
    char *asret;

    fileeof = 0;
    flow_enum_state = 0;
    class_enum_state = 0;

    switch (filetype) {
    case TYPE_PCAP:
        if (pcap_descriptor != 0) {
            pcap_close(pcap_descriptor);
            pcap_descriptor = 0;
        }
        break;
    case TYPE_UNKNOWN:
        /* nothing to do */
        break;
    default:
        asprintf(&asret, "%s.%d: filetype %d unknown!\n",
                 __FILE__, __LINE__, filetype);
        Tcl_SetResult(interp, asret, tclasfree);
        return TCL_ERROR;
    }

    filetype = TYPE_UNKNOWN;		/* go into neutral... */

    memset(&clstats[0], 0, sizeof clstats);
    for (cl = &clstats[0]; cl < &clstats[NUM(clstats)]; cl++) {
        cl->cls_last_bin_active = 0xffffffff;
    }
    curtime = ZERO;
    starttime = ZERO;
    pending = 0;

    for (fe = table; fe; fe = nfe) {
        nfe = fe->fe_next_in_table;
        free(fe);
    }
    table = table_last = 0;
    memset(buckets, 0, sizeof buckets);
    memset(onebehinds, 0, sizeof onebehinds);

    /* if pending buffer is already set, free it */
    if (pending_packet) {
        free(pending_packet);
        pending_packet = 0; 	    /* empty the water bucket */
        pending_maxpktlen = 0;
    }

    /* allocate packet for pending buffer */
    pending_packet = malloc(maxpktlen); /* room for packet */
    if (pending_packet == 0) {
        asprintf(&asret, "no room for %d-byte packet buffer", maxpktlen);
        Tcl_SetResult(interp, asret, tclasfree);
        return TCL_ERROR;
    }
    pending_maxpktlen = maxpktlen; /* remember size of buffer */

    /* if we've already allocated a packet buffer, free it */
    if (pktbuffer) {
        free(pktbuffer);
        pktbuffer = 0;
    }

    pktbuffer = malloc(maxpktlen);		/* room for alignment */
    if (pktbuffer == 0) {
        asprintf(&asret, "no room for %d-byte packet buffer", maxpktlen);
        Tcl_SetResult(interp, asret, tclasfree);
        return TCL_ERROR;
    }

    return TCL_OK;
}


/*
 * Compute a checksum on a contiguous area of storage
 *
 * This is tailored to doing quite short data structures,
 * in particular, flow ids.
 */

static u_short
cksum(u_char *p, int len)
{
    int shorts = len/2;
    u_long sum = 0;

    while (shorts > 4) {
        /* 0*/	sum += PICKUP_NETSHORT(p); p += 2; sum += PICKUP_NETSHORT(p); p += 2;
        /* 2*/	sum += PICKUP_NETSHORT(p); p += 2; sum += PICKUP_NETSHORT(p); p += 2;
        /* 4*/	shorts -= 4;
    }

    while (shorts > 0) {
        sum += PICKUP_NETSHORT(p);
        p += 2;
        shorts--;
    }

    if (len&1) {
        sum += p[0]<<8;
    }

    /*
     * Reduce
     *
     * 0xffff + 0xffff = 0x1fffe.  So, 
     */
    sum = (sum&0xffff)+((sum>>16)&0xffff);
    sum = (sum&0xffff)+((sum>>16)&0xffff);	/* That's enough */

    return (u_short) (~htons(sum))&0xffff;
}



static char *
flow_type_to_string(ftinfo_p ft)
{
    static char result[MAX_FLOW_ID_BYTES*10];
    char *sep = "";
    atoft_p xp;
    int i;

    result[0] = 0;
    for (i = 0; i < ft->fti_type_indicies_len; i++) {
        xp = &atoft[ft->fti_type_indicies[i]];
        sprintf(result+strlen(result), "%s%s", sep, xp->name);
        sep = "/";
    }
    return result;
}


static char *
flow_id_to_string(ftinfo_p ft, u_char *id)
{
    static char result[MAX_FLOW_ID_BYTES*10];
    char fidstring[30], *fidp;
    char *sep = "", *dot, *fmt0xff, *fmt0xf;
    atoft_p xp;
    u_long decimal;
    int i, firstbit, numbits, lastbit;
    u_long byte;

    result[0] = 0;
    for (i = 0; i < ft->fti_type_indicies_len; i++) {
        xp = &atoft[ft->fti_type_indicies[i]];
        fidp = fidstring;
        dot = "";			/* for dotted decimal */
        decimal = 0;			/* for decimal */
        switch (xp->fmt) {
        case FMT_DECIMAL:
            break;			/* done in for loop (sigh) */
        case FMT_DOTTED:
            fmt0xff = "%s%d";
            fmt0xf = "%s%d";
            break;
        case FMT_HEX:
            fmt0xff = "%s%02x";
            fmt0xf = "%s%x";
            break;
        default:
            fprintf(stderr, "%s:%d:  %d is bad fmt\n",
                    __FILE__, __LINE__, xp->fmt);
            break;
        }

        firstbit = xp->firstbit;
        numbits = xp->numbits;
        while (numbits > 0) {
            byte = *id++;
            lastbit = (firstbit+numbits) > 8 ? 7 : firstbit+numbits-1;
            if (firstbit > 0) {
                byte = (byte<<(firstbit+24))>>(firstbit+24);
            }
            if (lastbit < 7) {
                byte = (byte>>(7-lastbit))<<(7-lastbit);
            }
            if (xp->fmt == FMT_DECIMAL) {
                decimal = (decimal<<(lastbit-firstbit+1))+(byte>>(7-lastbit));
            } else {
                if (firstbit < 4) {
                    sprintf(fidp, fmt0xff, dot, byte);
                } else {
                    sprintf(fidp, fmt0xf, dot, byte);
                }
                fidp += strlen(fidp);
            }
            numbits -= (8-firstbit);
            firstbit = 0;
            if (xp->fmt == FMT_DOTTED) {
                dot = ".";
            }
        }
        if (xp->fmt == FMT_DECIMAL) {
            sprintf(fidstring, "%ld", decimal);
        } else {
            *fidp = 0;
        }
        sprintf(result+strlen(result), "%s%s", sep, fidstring);
        sep = "/";
    }
    return result;
}


#if	0	/* not used */
static char *
flow_type_to_string(int ftype)
{
    static char result[MAX_FLOW_ID_BYTES*10];
    char *sep = "";
    int i;

    result[0] = 0;
    for (i = 0; i < ftinfo[ftype].fti_type_indicies_len; i++) {
        sprintf(result+strlen(result), "%s%s",
                sep, atoft[ftinfo[ftype].fti_type_indicies[i]].name);
        sep = "/";
    }
    return result;
}
#endif


/* 
 * formats for reporting flow, class statistics.  these can be read,
 * and modified, by the scripting language
 */

static char *flow_stats_template =
    "type %d class %d type %s id %s pkts %lu bytes "
    "%lu sipg %lu.%06lu created %ld.%06ld last %ld.%06ld",
    *flow_stats_format;

static char *
flow_statistics(flowentry_p fe)
{
    static char summary[2000];

    sprintf(summary, flow_stats_format,
            fe->fe_flow_type, fe->fe_class,
            flow_type_to_string(&ftinfo[fe->fe_flow_type]),
            flow_id_to_string(&ftinfo[fe->fe_flow_type], fe->fe_id),
            fe->fe_pkts-fe->fe_pkts_last_enum, fe->fe_bytes-fe->fe_bytes_last_enum,
            SIPG_TO_SECS(fe->fe_sipg), SIPG_TO_USECS(fe->fe_sipg),
            dtsecs_ri(&fe->fe_created), dtusecs_ri(&fe->fe_created),
            dtsecs_ri(&fe->fe_last_pkt_rcvd), dtusecs_ri(&fe->fe_last_pkt_rcvd));

    return summary;
}


static char *class_stats_template =
    "class %ld created %lu deleted %lu added %lu removed %lu "
    "active %lu pkts %lu bytes %lu sipg %lu.%06lu "
    " lastrecv %ld.%06ld",
    *class_stats_format;

static char *
class_statistics(clstats_p clsp)
{
    static char summary[10000];

    sprintf(summary, class_stats_format,
            clsp-clstats, clsp->cls_created, clsp->cls_deleted,
            clsp->cls_added, clsp->cls_removed, clsp->cls_active,
            clsp->cls_pkts, clsp->cls_bytes,
            SIPG_TO_SECS(clsp->cls_sipg), SIPG_TO_USECS(clsp->cls_sipg),
            dtsecs_ri(&clsp->cls_last_pkt_rcvd),
            dtusecs_ri(&clsp->cls_last_pkt_rcvd));

    return summary;
}

static char *ri_stats_template =
    "binno %lu ri_start %ld.%06ld ri_end %ld.%06ld "
    "ri_firstpkt %ld.%06ld ri_lastpkt %ld.%06ld "
    "ri_pkts %lu ri_bytes %lu "
    "ri_tsipg %lu.%06lu ri_isipg %lu.%06lu "
    "ignorepkts %lu ignorebytes %lu "
    "unclpkts %lu unclbytes %lu "
    "fragpkts %lu fragbytes %lu toosmallpkts %lu toosmallbytes %lu "
    "runtpkts %lu runtbytes %lu noportpkts %lu noportbytes %lu",
    *ri_stats_format;

static char *
ri_statistics() {
    char *asret;

    /* 
     * note: only ri_stime uses delta_ri; everything can be
     * relative to it
     */

    asprintf(&asret, ri_stats_format,
             ri.ri_binno,
             dtsecs_ri(&ri.ri_starttime), dtusecs_ri(&ri.ri_starttime),
             dtsecs_wi(&ri.ri_endtime), dtusecs_wi(&ri.ri_endtime),
             dtsecs_wi(&ri.ri_first_pkt_rcvd), dtusecs_wi(&ri.ri_first_pkt_rcvd),
             dtsecs_wi(&ri.ri_last_pkt_rcvd), dtusecs_wi(&ri.ri_last_pkt_rcvd),
             ri.ri_pkts, ri.ri_bytes,
             SIPG_TO_SECS(ri.ri_isipg), SIPG_TO_USECS(ri.ri_isipg),
             SIPG_TO_SECS(ri.ri_tsipg), SIPG_TO_USECS(ri.ri_tsipg),
             ri.ri_ignorepkts, ri.ri_ignorebytes,
             ri.ri_unclpkts, ri.ri_unclbytes,
             ri.ri_fragpkts, ri.ri_fragbytes,
             ri.ri_toosmallpkts, ri.ri_toosmallbytes,
             ri.ri_runtpkts, ri.ri_runtbytes,
             ri.ri_noportpkts, ri.ri_noportbytes);
    return asret;
}



/*
 * arrange for something to run shortly after "timertime"
 */

static void
timer_insert(flowentry_p fe, struct timeval *timertime)
{
    flowentry_p timer = &timers[timertime->tv_sec%NUM(timers)];

    timer->fe_prev_in_timer->fe_next_in_timer = fe;
    fe->fe_prev_in_timer = timer->fe_prev_in_timer;
    timer->fe_prev_in_timer = fe;
    fe->fe_next_in_timer = timer;
}

static void
timer_remove(flowentry_p fe)
{
    if (fe->fe_prev_in_timer) {
        fe->fe_prev_in_timer->fe_next_in_timer = fe->fe_next_in_timer;
        fe->fe_next_in_timer->fe_prev_in_timer = fe->fe_prev_in_timer;
    }
}

static flowentry_p
timer_get_slot()
{
    flowentry_p timer = &timers[curtime.tv_sec%NUM(timers)];
    flowentry_p slot = timer->fe_next_in_timer;

    if (slot == timer->fe_prev_in_timer) {
        return 0;		/* nothing */
    }

    /* keep ends from dangling */
    slot->fe_prev_in_timer = 0;
    timer->fe_prev_in_timer->fe_next_in_timer = 0;

    /* point to self */
    timer->fe_next_in_timer = timer;
    timer->fe_prev_in_timer = timer;

    return slot;
}


static void
do_timers(Tcl_Interp *interp)
{
    flowentry_p nfe, fe;
    ftinfo_p fti;
    char buf[100];
    int n;
    long usecs;

    nfe = timer_get_slot();

    while ((fe = nfe) != 0) {
        nfe = fe->fe_next_in_timer;
        fe->fe_next_in_timer = fe->fe_prev_in_timer = 0;
        if (TIME_LT(&fe->fe_timer_time, &curtime)) {
            fti = &ftinfo[fe->fe_flow_type];
            if ((fti->fti_timer_upcall == 0) ||
				TIME_EQ(&fe->fe_timer_time, &ZERO)) {
                continue;	/* maybe flow type changed? */
            }
            /*
             * call:	"timer_upcall timesecs.usecs FLOW flowstats"
             * result:  "command secs.usecs"
             *
             * XXX should this follow -D flag?
             */
            sprintf(buf, " %ld.%06ld ", curtime.tv_sec, tvusecs(curtime.tv_usec));
            if (Tcl_VarEval(interp,
                            ftinfo[fe->fe_flow_type].fti_timer_upcall, buf,
                            " FLOW ", flow_statistics(fe), 0) != TCL_OK) {
                packet_error = TCL_ERROR;
                return;
            }

            fe->fe_timer_time.tv_usec = 0;
            n = sscanf(Tcl_GetStringResult(interp), "%s %ld.%ld",
                       buf, &fe->fe_timer_time.tv_sec,
                       &usecs);
            fe->fe_timer_time.tv_usec = usecs;
            if ((n >= 1) && !strcmp(buf, "DELETE")) {
                delete_flow(fe);
            } else if (n >= 2) {
                if (!TIME_EQ(&fe->fe_timer_time, &ZERO)) {
                    TIME_ADD(&fe->fe_timer_time,
                             &fe->fe_timer_time, &curtime);
                    timer_insert(fe, &fe->fe_timer_time);
                }
            }
        } else {
            timer_insert(fe, &fe->fe_timer_time);
        }
    }
}

static void
set_time(Tcl_Interp *interp, long sec, long usec)
{
    struct timeval now;
    char *asret;

    now.tv_sec = sec;
    now.tv_usec = usec;

    if (TIME_LT(&now, &ZERO)) {
        asprintf(&asret,
                 "[%s] bad trace file format -- negative time in packet",

                pktloc());
        Tcl_SetResult(interp, asret, tclasfree);
        packet_error = TCL_ERROR;
        return;
    }

    if (TIME_EQ(&ri.ri_starttime, &ZERO)) {
        ri.ri_starttime = now;
    }
    ri.ri_endtime = now;

    if (TIME_EQ(&starttime, &ZERO)) {
        starttime = now;
        curtime = now;
    } else {
        if (TIME_LT(&now, &curtime)) {
#if	0
/*
 * OK.  Vern's tcpslice(1) doesn't worry about this (but, like this
 * #if 0, just doesn't update time for a while). hmm '
 */
            sprintf(interp->result,
                    "[%s] bad trace file format -- time goes backwards",
                    pktloc());
            packet_error = TCL_ERROR;
#endif	/* 0 */
            return;
        }
        /* call timers once per second */
        while (curtime.tv_sec != now.tv_sec) {
            do_timers(interp);
            curtime.tv_sec++;		/* advance the time */
        }
        curtime.tv_usec = now.tv_usec;
        if (TIME_EQ(&ri.ri_starttime, &ZERO)) {
            ri.ri_starttime = curtime;
        }
    }
    if (ri.ri_binno == -1) {
        ri.ri_binno = NOW_AS_BINNO();
    }
}


/* table lookup */

static flowentry_p
tbl_lookup(u_char *id, ftinfo_p ft)
{
    int id_len = ft->fti_id_len;
    int type_index = ft-ftinfo;
    u_short sum = cksum(id, id_len);
    flowentry_p fe = buckets[sum%NUM(buckets)];
    flowentry_p onebehind = onebehinds[sum%NUM(onebehinds)];
#define MATCH(id,len,sum,type_index,p)                              \
	((sum == (p)->fe_sum) && (type_index == (p)->fe_flow_type) &&   \
     (len == (p)->fe_id_len) && !memcmp(id, (p)->fe_id, len))

    if (onebehind && MATCH(id, id_len, sum, type_index, onebehind)) {
        return onebehind;
    }

    while (fe) {
        if (MATCH(id, id_len, sum, type_index, fe)) {
            onebehinds[sum%NUM(onebehinds)] = fe;
            break;
        }
        fe = fe->fe_next_in_bucket;
    }
    return fe;
}

static flowentry_p
tbl_add(u_char *id, int id_len)
{
    u_short sum = cksum(id, id_len);
    flowentry_p *hbucket = &buckets[sum%NUM(buckets)];
    flowentry_p fe;

    fe = (flowentry_p) malloc(sizeof *fe+id_len-1);
    if (fe == 0) {
        return 0;
    }
    memset(fe, 0, sizeof *fe);
    fe->fe_sum = sum;
    fe->fe_id_len = id_len;
    memcpy(fe->fe_id, id, id_len);

    fe->fe_next_in_bucket = *hbucket;
    if (fe->fe_next_in_bucket) {
        fe->fe_next_in_bucket->fe_prev_in_bucket = fe;
    }
    fe->fe_prev_in_bucket = 0;
    *hbucket = fe;

    fe->fe_next_in_table = 0;
    fe->fe_prev_in_table = table_last;
    if (table_last) {
        table_last->fe_next_in_table = fe;
    } else {
        table = fe;
    }
    table_last = fe;

    fe->fe_next_in_timer = fe->fe_prev_in_timer = 0;

    return fe;
}


static void
tbl_delete(flowentry_p fe)
{
    u_short sum = cksum(fe->fe_id, fe->fe_id_len);
    flowentry_p *hbucket = &buckets[sum%NUM(buckets)];
    flowentry_p *honebehind = &onebehinds[sum%NUM(onebehinds)];

    /* dequeue the silly thing... */

    /* out of timer */
    if (fe->fe_prev_in_timer) {
        timer_remove(fe);
    }

    /* out of bucket */
    if (fe->fe_prev_in_bucket) {
        fe->fe_prev_in_bucket->fe_next_in_bucket = fe->fe_next_in_bucket;
    } else {
        *hbucket = fe->fe_next_in_bucket;
    }
    if (fe->fe_next_in_bucket) {
        fe->fe_next_in_bucket->fe_prev_in_bucket = fe->fe_prev_in_bucket;
    }

    if (*honebehind == fe) {
        *honebehind = *hbucket;
    }

    /* out of table */
    if (fe->fe_prev_in_table) {
        fe->fe_prev_in_table->fe_next_in_table = fe->fe_next_in_table;
    } else {
        table = fe->fe_next_in_table;
    }
    if (fe->fe_next_in_table) {
        fe->fe_next_in_table->fe_prev_in_table = fe->fe_prev_in_table;
    } else {
        table_last = fe->fe_prev_in_table;
    }

    free(fe);
}




static void
delete_flow(flowentry_p fe)
{
    clstats[fe->fe_class].cls_deleted++;
    clstats[fe->fe_class].cls_last_bin_active = ri.ri_binno;
    tbl_delete(fe);
}


static flowentry_p
new_flow(Tcl_Interp *interp, ftinfo_p ft, u_char *flowid, int class)
{
    flowentry_p fe;

    fe = tbl_add(flowid, ft->fti_id_len);
    if (fe == 0) {
        return 0;
    }
    fe->fe_flow_type = ft-ftinfo;
    fe->fe_parent_ftype = ft->fti_parent_ftype;			 /* default */
    fe->fe_parent_class = ftinfo[ft->fti_parent_ftype].fti_class;/* default */
    fe->fe_class = class;
    fe->fe_last_bin_active = 0xffffffff;
    fe->fe_created = curtime;
    fe->fe_last_pkt_rcvd = ZERO;

    /*
     * now, if there is a "new flow" callout registered in this
     * flow type, call it.
     *
     * the callout is allowed to change certain parameters of
     * this flow entry: the class, the parent flow type,
     * the recv_upcall and parameters, and the timer_upcall
     * and parameters.
     */

    if (ft->fti_new_flow_upcall) {
        int n;
        u_long sipgsecs, sipgusecs;
        long usecs1, usecs2;
        char buf[1000];

        sprintf(buf, " %d %ld ", fe->fe_class, ft-ftinfo);
        if (Tcl_VarEval(interp, ft->fti_new_flow_upcall,
                        buf, flow_type_to_string(ft),
                        " ", flow_id_to_string(ft, fe->fe_id), 0) != TCL_OK) {
            packet_error = TCL_ERROR;
            return 0;
        }

        fe->fe_upcall_when_secs_ge.tv_usec = 0;
        fe->fe_timer_time.tv_usec = 0;
        sipgusecs = 0;

        n = sscanf(Tcl_GetStringResult(interp),
                   "%hd %hd %hd %ld.%ld %ld %lu.%lu %ld.%ld",
                   &fe->fe_class, &fe->fe_parent_class, &fe->fe_parent_ftype,
                   &fe->fe_upcall_when_secs_ge.tv_sec, &usecs1,
                   &fe->fe_upcall_when_pkts_ge,
                   &sipgsecs, &sipgusecs,
                   &fe->fe_timer_time.tv_sec, &usecs2);

        fe->fe_upcall_when_secs_ge.tv_usec = usecs1;
        fe->fe_timer_time.tv_usec = usecs2;
        /*
         * (yes, these "if" stmts could be nested, and thus
         * be more efficient; but, they would be less legible,
         * so...)
         */
        if (n >= 4) {
            if (!TIME_EQ(&fe->fe_upcall_when_secs_ge, &ZERO)) {
                /* returned value is relative to now, so make absolute */
                TIME_ADD(&fe->fe_upcall_when_secs_ge,
                         &fe->fe_upcall_when_secs_ge, &curtime);
            }
        }
        if (n >= 7) {
            fe->fe_upcall_when_sipg_lt = SECS_USECS_TO_SIPG(sipgsecs,sipgusecs);
        }
        if (n >= 9) {
            if (!TIME_EQ(&fe->fe_timer_time, &ZERO)) {
                /* returned value is relative to now, so make absolute */
                TIME_ADD(&fe->fe_timer_time, &fe->fe_timer_time, &curtime);
                timer_insert(fe, &fe->fe_timer_time);
            }
        }
    }
    clstats[fe->fe_class].cls_created++;
    clstats[fe->fe_class].cls_last_bin_active = ri.ri_binno;
    return fe;
}


/*
 * smoothed IPG (exponentially weighted moving average)
 *
 * sipg is expressed in units of 8 microseconds (usecs)
 */

static u_long
sipg_update(u_long cur_sipg, struct timeval *last_pkt)
{
    u_long sipg;

    if (TIME_EQ(last_pkt, &ZERO)) {
        return cur_sipg;
    }

    sipg  = (curtime.tv_sec - last_pkt->tv_sec)*1000000UL;
    sipg += (curtime.tv_usec - last_pkt->tv_usec);
    /* two lines from VJ '88 SIGCOMM */
    sipg -= (cur_sipg>>3);
    return cur_sipg + sipg;
}


/*
 * do per flow processing of a packet that has been received.
 *
 * this involves updating counters as well as calling out
 * to the "packet_received" callback routine if appropriate.
 */

static void
packetinflow(Tcl_Interp *interp, flowentry_p fe, int len)
{
    clstats_p cl;

    cl = &clstats[fe->fe_class];
    cl->cls_last_bin_active = ri.ri_binno;

    /* update statistics */

    cl->cls_pkts++;
    cl->cls_bytes += len;
    if (cl->cls_last_pkt_rcvd.tv_sec) {		/* sipg */
        cl->cls_sipg = sipg_update(cl->cls_sipg, &cl->cls_last_pkt_rcvd);
    }
    cl->cls_last_pkt_rcvd = curtime;

    fe->fe_pkts++;
    fe->fe_bytes += len;
    if (fe->fe_last_pkt_rcvd.tv_sec) {		/* sipg */
        fe->fe_sipg = sipg_update(fe->fe_sipg, &fe->fe_last_pkt_rcvd);
    }
    fe->fe_last_pkt_rcvd = curtime;

    /* count activity in this bin */
    if (fe->fe_last_bin_active != ri.ri_binno) {
        fe->fe_last_bin_active = ri.ri_binno;
        cl->cls_active++;
    }


    /* do we need to callout? */

	/*
	 * i can think of a few things this might be good for:
	 *
	 * 1.  if this should be switched, then after .N seconds,
	 *	switch to a "switched" statistics group.
	 * 2.  if we were running on a real system, with this
	 *	as the split between the "fast" code and the
	 *	"slow" (or, just a slow call between the two
	 *	halves), then if this was associated witha
	 *	flow coming in on a default label, and if
	 *	we had sent a redirect upstream, then we
	 *	could use this to detect that we were still
	 *	receiving on the default label after
	 *	N seconds.
	 */

    if (ftinfo[fe->fe_flow_type].fti_recv_upcall &&
		(fe->fe_pkts >= fe->fe_upcall_when_pkts_ge) &&
		(fe->fe_sipg < fe->fe_upcall_when_sipg_lt) &&
		TIME_GE(&curtime, &fe->fe_upcall_when_secs_ge)) {
        int n, outcls;
        u_long sipgsecs, sipgusecs;
        long usecs;
        struct timeval outtime;

        if (Tcl_VarEval(interp, ftinfo[fe->fe_flow_type].fti_recv_upcall,
                        " FLOW ", flow_statistics(fe), 0) != TCL_OK) {
            packet_error = TCL_ERROR;
            return;
        }

        fe->fe_upcall_when_secs_ge.tv_usec = 0;
        sipgusecs = 0;
        outcls = fe->fe_class;
        n = sscanf(Tcl_GetStringResult(interp), "%d %ld.%ld %ld %lu.%lu",
                   &outcls, &fe->fe_upcall_when_secs_ge.tv_sec, 
                   &usecs, &fe->fe_upcall_when_pkts_ge,
                   &sipgsecs, &sipgusecs);

        fe->fe_upcall_when_secs_ge.tv_usec = usecs;

        if (outcls != fe->fe_class) {
            /* class is changing --- update statistics */
            clstats[fe->fe_class].cls_removed++;
            fe->fe_class = outcls;
            clstats[fe->fe_class].cls_added++;
            clstats[fe->fe_class].cls_last_bin_active = ri.ri_binno;
        }
        if (n >= 2) {
            if (!TIME_EQ(&fe->fe_upcall_when_secs_ge, &ZERO)) {
                TIME_ADD(&fe->fe_upcall_when_secs_ge, &curtime, &outtime);
            }
        }
        if (n >= 5) {
            fe->fe_upcall_when_sipg_lt = SECS_USECS_TO_SIPG(sipgsecs,sipgusecs);
        }
    }
}


/*
 * This is the main packet input routine, called when a packet
 * has been received.
 *
 * We first map the incoming packet into a lower level
 * flow type (llft).  We use that to find the lower level
 * flow entry (llfe).  We also use the llft (possibly via
 * a callout routine) to find an upper level flow type (ulft).
 * We then use this ulft to find the upper level flow entry (ulfe).
 */

static void
packetin(Tcl_Interp *interp, const u_char *packet, int caplen, int pktlen)
{
    u_char llfid[MAX_FLOW_ID_BYTES], ulfid[MAX_FLOW_ID_BYTES];
    int llclindex;
    int pktprotohasports, pktbigenough, capbigenough, fragmented;
    flowentry_p llfe, ulfe;	/* lower and upper level flow entries */
    ftinfo_p llft, ulft;	/* lower and upper level flow types */

    /* check for a pending packet */
    if (pending) {
        if (caplen) {	/* shouldn't happen! */
            Tcl_SetResult(interp, "invalid condition in packetin", TCL_STATIC);
            packet_error = TCL_ERROR;
            return;
        }
        pending = 0;
        ri.ri_binno = NOW_AS_BINNO();
        /* use the pending packet */
        packet = (const u_char *)pending_packet;
        caplen = pendingcaplen;
        pktlen = pendingpktlen;
    } else if (ri.ri_binno != NOW_AS_BINNO()) {
        /* if we've gone over to another bin number... */
        pending = 1;
        memcpy(pending_packet, packet, MIN(caplen, pending_maxpktlen));
        pendingcaplen = caplen;
        pendingpktlen = pktlen;
        /* wait till next time */
        return;
    }

    pktcount++;
    ri.ri_pkts++;
    ri.ri_bytes += pktlen;
    if (TIME_EQ(&ri.ri_first_pkt_rcvd, &ZERO)) {
        ri.ri_first_pkt_rcvd = curtime;
    }
    ri.ri_isipg = sipg_update(ri.ri_isipg, &ri.ri_last_pkt_rcvd);
    ri.ri_tsipg = sipg_update(ri.ri_tsipg, &ri.ri_last_pkt_rcvd);
    ri.ri_last_pkt_rcvd = curtime;

    /* now, do the low level classification into a llft */
    pktprotohasports = protohasports[packet[9]];
    pktbigenough = 0;
    capbigenough = 0;
    fragmented = 0;
    for (llclindex = 0;
         llclindex < NUM(llclasses) && !LLCL_UNUSED(&llclasses[llclindex]);
         llclindex++) {
        llft = &ftinfo[llclasses[llclindex].llcl_fti];
        if (pktlen >= llft->fti_id_covers) {
            pktbigenough = 1;		/* packet was big enough */
            if (caplen >= llft->fti_id_covers) {
                capbigenough = 1;	/* and, we captured enough */
                /*
                 * if ft doesn't use ports, or this protocol has ports and we
                 * aren't fragmented, this is fine.
                 */
                if (FTI_USES_PORTS(llft)) {
                    if (pktprotohasports &&
                        ((PICKUP_NETSHORT(&packet[6])&0x1fff) == 0)) {
                        /*
                         * needed ports and the protocol in packet
                         * has ports and this isn't a fragment
                         */
                        break;	  /* accept this packet in this class */
                    } else {
                        /*
                         * needed ports, but got a packet with a protocol
                         * which doesn't have ports or got a fragment
                         */
                        fragmented = 1;
                    }
                } else {
                    /* don't need to worry about ports... */
                    break;    /* accept this packet in this class */
                }
            }
        }
    }

    if (llclindex >= NUM(llclasses)) {
        ri.ri_unclpkts++;
        ri.ri_unclbytes += pktlen;
        if (pktbigenough) {	/* packet was big enough, but... */
            /* never found a flow type into which it fit */
            if (capbigenough) {
                if (packet[6]&0x1fff) {
                    ri.ri_fragpkts++;
                    ri.ri_fragbytes += pktlen;
                } else {
                    /*
                     * this means there is no flow type for protocols
                     * which don't have a port number field (i.e., this
                     * is probably a bug...
                     */
                    ri.ri_noportpkts++;
                    ri.ri_noportbytes += pktlen;
                }
            } else {
                ri.ri_runtpkts++;
                ri.ri_runtbytes += pktlen;
            }
        } else {                /* packet was too small for *any* defined flow */
            ri.ri_toosmallpkts++;
            ri.ri_toosmallbytes += pktlen;
        }
        return;
    }

    /* create lower level flow id for this packet */
    FLOW_ID_FROM_HDR(llfid, packet, llft);

    /* find the lower level flow entry */
    llfe = tbl_lookup(llfid, llft);

    if (llfe == 0) {
        /* the lower level flow doesn't exist, so will need to be created */
        llfe = new_flow(interp, llft, llfid, llft->fti_class);
        if (llfe == 0) {
            if (packet_error == 0) {
                Tcl_SetResult(interp,
                              "unable to create a new lower level flow",
                              TCL_STATIC);
                packet_error = TCL_ERROR;
            }
            return;
        }
    }

    /* track packet stats */
    packetinflow(interp, llfe, pktlen);

    /* now, need to find ulfe from llfe */

    while ((llfe->fe_parent_ftype != 0) &&
           (llfe->fe_parent_ftype != llfe->fe_flow_type)) {
        ulft = &ftinfo[llfe->fe_parent_ftype];	/* get ll's parent flow type */

        /* create the ulfid */
        FLOW_ID_FROM_HDR(ulfid, packet, ulft);

        /* lookup the upper level flow entry */
        ulfe = tbl_lookup(ulfid, ulft);

        if (ulfe == 0) {
            /* the upper level flow doesn't exist -- create it */
            ulfe = new_flow(interp, ulft, ulfid, llfe->fe_parent_class);
            if (ulfe == 0) {
                if (packet_error == 0) {
                    Tcl_SetResult(interp, "unable to create a new upper level flow",
                                  TCL_STATIC);
                    packet_error = TCL_ERROR;
                }
                return;
            }
        }

        /*
         * there is a situation in which a UL flow is shared by
         * various LL flow types.  in this case, it may be that
         * the class of the UL flow depends on which LL flows are
         * using it.  this *could* cause us to call out every time
         * a new packet arrives (or, a packet arrives with a new
         * UL class, or ...).
         *
         * we use the following hack XXX :  we infer a priority based
         * on the class number.  if a packet comes in and the class
         * number in its parent_class field is greater than the class
         * numberin its parent, then the parent is "reclassed".
         *
         * i really don't know how to do this "right", sigh.
         */

        if (llfe->fe_parent_class > ulfe->fe_class) {
            /* class is changing --- update statistics */
            clstats[ulfe->fe_class].cls_removed++;
            clstats[ulfe->fe_class].cls_last_bin_active = ri.ri_binno;
            ulfe->fe_class = llfe->fe_parent_class;
            clstats[ulfe->fe_class].cls_added++;
            clstats[ulfe->fe_class].cls_last_bin_active = ri.ri_binno;
        }

        /* track packet stats */
        packetinflow(interp, ulfe, pktlen);

        /* OK, old ulfe is new llfe, and loop... */
        llfe = ulfe;
    }
}

/*
 * receive an ethernet frame.
 */

static void
receive_tcpd_en10mb(u_char *user, const struct pcap_pkthdr *h,
						const u_char *buffer)
{
    u_short type;
    Tcl_Interp *interp = (Tcl_Interp *)user;

    set_time(interp, h->ts.tv_sec, h->ts.tv_usec);

    if (h->caplen < 14) {
        /* need to call packetin to set counters, etc. */
        packetin(interp, buffer, 0, 0);
        return;
    }

    type = buffer[12]<<8|buffer[13];

    if (type != IPtype) {
        ri.ri_ignorepkts++;
        ri.ri_ignorebytes += h->caplen-14; /* not that 14 is a magic number... */
        return;         /* only IP packets */
    }

    packetin(interp, buffer+14, h->caplen-14, h->len-14);
}

/*
 * receive a slip frame
 */

static void
receive_tcpd_slip(u_char *user, const struct pcap_pkthdr *h,
						const u_char *buffer)
{
#if !defined(SLIP_HDRLEN)
#define SLIP_HDRLEN     16
#endif /* !defined(SLIP_HDRLEN) */

    Tcl_Interp *interp = (Tcl_Interp *)user;

    set_time(interp, h->ts.tv_sec, h->ts.tv_usec);

    if (h->caplen < SLIP_HDRLEN) {
        packetin(interp, buffer, 0, 0);
        return;
    }
    packetin(interp, buffer+SLIP_HDRLEN,
             h->caplen-SLIP_HDRLEN, h->len-SLIP_HDRLEN);
}


/*
 * receive a PPP frame
 */

static void
receive_tcpd_ppp(u_char *user, const struct pcap_pkthdr *h,
						const u_char *buffer)
{
#define PPP_HDRLEN 4
    Tcl_Interp *interp = (Tcl_Interp *)user;

    set_time(interp, h->ts.tv_sec, h->ts.tv_usec);

    if (h->caplen < PPP_HDRLEN) {
        packetin(interp, buffer, 0, 0);
        return;
    }
    packetin(interp, buffer+PPP_HDRLEN,
             h->caplen-PPP_HDRLEN, h->len-PPP_HDRLEN);
}

/*
 * receive a FDDI frame
 */


static void
receive_tcpd_fddi(u_char *user, const struct pcap_pkthdr *h,
						const u_char *buffer)
{
#define FDDI_HDRLEN 13
    int caplen = h->caplen, length = h->len;
    u_short type;
    Tcl_Interp *interp = (Tcl_Interp *)user;
    struct fddi_header *fddip;
    static u_char SNAPHDR[] = { LLC_SNAP_LSAP, LLC_SNAP_LSAP, LLC_UI, 0, 0, 0 };

    set_time(interp, h->ts.tv_sec, h->ts.tv_usec);

    if (caplen < FDDI_HDRLEN) {
        packetin(interp, buffer, 0, 0);
        return;
    }

    fddip = (struct fddi_header *)buffer;
    length -= FDDI_HDRLEN;
    buffer += FDDI_HDRLEN;
    caplen -= FDDI_HDRLEN;
    if ((fddip->fddi_fc&FDDIFC_CLFF) == FDDIFC_LLC_ASYNC) {
        if (caplen < sizeof SNAPHDR+2) {
            packetin(interp, buffer, 0, 0);
            return;
        }
        if (memcmp(buffer, SNAPHDR, sizeof SNAPHDR) == 0) {
            type = buffer[sizeof SNAPHDR]<<8|buffer[sizeof SNAPHDR+1];
            if (type == 0x0800) {
                caplen -= (sizeof SNAPHDR+2);
                length -= (sizeof SNAPHDR+2);
                buffer += (sizeof SNAPHDR+2);
                packetin(interp, buffer, caplen, length);
            } else {
                return;
            }  
        } else {
            return;
        }
    } else {
        return;
    }
}


/*
 * receive a null packet
 */


static void
receive_tcpd_null(u_char *user, const struct pcap_pkthdr *h,
						const u_char *buffer)
{
#define	NULL_HDRLEN 4
    Tcl_Interp *interp = (Tcl_Interp *)user;

    set_time(interp, h->ts.tv_sec, h->ts.tv_usec);

    if (h->caplen < NULL_HDRLEN) {
        packetin(interp, buffer, 0, 0);
        return;
    }

    packetin(interp, buffer+NULL_HDRLEN,
             h->caplen-NULL_HDRLEN, h->len-NULL_HDRLEN);
}


static int
process_one_packet(Tcl_Interp *interp)
{
    packet_error = TCL_OK;

    if (pending) {
        packetin(interp, 0, 0, 0);
    } else {
        switch (filetype) {
        case TYPE_PCAP:
            if (pcap_dispatch(pcap_descriptor, 1,
                              pcap_receiver, (u_char *)interp) == 0) {
                fileeof = 1;
                filetype = TYPE_UNKNOWN;
            }
            break;
        }
    }
    return packet_error;
}

/*
 * Read packets for one bin interval.
 *
 * Returns the current bin number.
 *
 * Returns -1 if EOF reached on the input file.
 */

static int
fl_read_one_bin(ClientData clientData, Tcl_Interp *interp,
		int argc, const char *argv[])
{
    int error;

    if (argc > 2) {
        Tcl_SetResult(interp, "Usage: fl_read_one_bin ?binsecs?", TCL_STATIC);
        return TCL_ERROR;
    } else if (argc == 2) {
        error = Tcl_GetInt(interp, argv[1], &binsecs);
        if (error != TCL_OK) {
            return error;
        }
    } else if (argc == 1) {
        ;		/* use old binsecs */
    }

    lastsignalled = signalled;
    /* reset ri statistics */
    {
        u_long savesipg = ri.ri_tsipg;
        struct timeval savestart = ri.ri_endtime;

        memset(&ri, 0, sizeof ri);
        ri.ri_starttime = ZERO;
        ri.ri_tsipg = savesipg;
        ri.ri_starttime = savestart; /* one ends, next starts */
    }
    

    ri.ri_binno = -1;

    if (!fileeof) {
        if (filetype == TYPE_UNKNOWN) {
            Tcl_SetResult(interp, "need to call fl_set_tcpd_file first",
                          TCL_STATIC);
            return TCL_ERROR;
        }
        if (flow_types == 0) {
            Tcl_SetResult(interp, "need to call fl_set_flow_type first", TCL_STATIC);
            return TCL_ERROR;
        }

        while (((ri.ri_binno == -1) || (ri.ri_binno == NOW_AS_BINNO())) &&
               (!fileeof) && (signalled == lastsignalled)) {
            error = process_one_packet(interp);
            if (error != TCL_OK) {
                return error;
            }
        }
    }

    if (TIME_EQ(&ri.ri_starttime, &ZERO)) {
        char *asret;

        asprintf(&asret, "");
        Tcl_SetResult(interp, asret, tclasfree);
    } else {
        Tcl_SetResult(interp, ri_statistics(), tclasfree);
    }
    return TCL_OK;
}

static int
set_flow_type(Tcl_Interp *interp, int ftype, int Ftype, int class,
              const char *name, char *new_flow_upcall,
				char *recv_upcall, char *timer_upcall)
{
    char initial[MAX_FLOW_ID_BYTES*5], after[MAX_FLOW_ID_BYTES*5]; /* 5 rndm */
    const char *curdesc;
    int bandm = 0;	/* number of bytes in fti_bytes_and_mask used */
    int indicies = 0;	/* index (in atoft) of each field in flow id */
    atoft_p xp;
    ftinfo_p fti = &ftinfo[ftype];

    /* forget current file type */
    fti->fti_bytes_and_mask_len = 0;
    fti->fti_id_covers = 0;
    fti->fti_id_len = 0;

    curdesc = name;

    if (strlen(name) >= NUM(initial)) {
        Tcl_SetResult(interp, "flow name too long", TCL_STATIC);
        return TCL_ERROR;
    }

    while (*curdesc) {
        int j, n;
        n = sscanf(curdesc, "%[a-zA-Z0-9]%s", initial, after);
        if (n == 0) {
            break;
        }
        if (n == 1) {
            curdesc = "";
        } else {
            curdesc = after+1;	/* +1 to strip off delimiter */
        }
        for (j = 0, xp = atoft; j < NUM(atoft); j++, xp++) {
            if (strcasecmp(xp->name, initial) == 0) {
                int off, firstbit, numbits, lastbit;
                u_long mask;
                off = xp->offset;
                firstbit = xp->firstbit;
                numbits = xp->numbits;
                while (numbits > 0) {
                    if (bandm >= (2*MAX_FLOW_ID_BYTES)) {
                        Tcl_SetResult(interp, "flow type specifier too long",
                                      TCL_STATIC);
                        return TCL_ERROR;
                    }
                    if (off > fti->fti_id_covers) {
                        fti->fti_id_covers = off;
                    }
                    mask = 0xff;
                    lastbit = (firstbit+numbits) > 8 ? 7 : (firstbit+numbits-1);
                    if (firstbit > 0) {
                        mask = (mask<<(firstbit+24))>>(firstbit+24);
                    }
                    if (lastbit < 7) {
                        mask = (mask>>(7-lastbit))<<(7-lastbit);
                    }
                    numbits -= (8-firstbit);
                    firstbit = 0;
                    fti->fti_bytes_and_mask[bandm++] = off++;
                    fti->fti_bytes_and_mask[bandm++] = mask;
                }
                if (indicies >= NUM(fti->fti_type_indicies)) {
                    Tcl_SetResult(interp, "too many fields in flow type specifier",
                                  TCL_STATIC);
                    return TCL_ERROR;
                }
                fti->fti_type_indicies[indicies++] = j;
                break;
            }
        }
        if (j >= NUM(atoft)) {
            char *asret;

            asprintf(&asret, "Bad flow field name %s in \"%s\"\n",
                     initial, name);
            Tcl_SetResult(interp, asret, tclasfree);
            return TCL_ERROR;
        }
    }

    fti->fti_bytes_and_mask_len = bandm;
    fti->fti_id_len = bandm/2;
    fti->fti_type_indicies_len = indicies;

    fti->fti_class = class;
    fti->fti_parent_ftype = Ftype;

    if (fti->fti_new_flow_upcall) {
        free(fti->fti_new_flow_upcall);
    }
    fti->fti_new_flow_upcall = new_flow_upcall;

    if (fti->fti_recv_upcall) {
        free(fti->fti_recv_upcall);
    }
    fti->fti_recv_upcall = recv_upcall;

    if (fti->fti_timer_upcall) {
        free(fti->fti_timer_upcall);
    }
    fti->fti_timer_upcall = timer_upcall;

    return TCL_OK;
}


/*
 * set a flow type.
 *
 * the caller manages the index since the way the system
 * works, an incoming packet will be mapped to a specific
 * flow type in a way which is dependent on the flow type
 * index.
 */

static int
fl_set_flow_type(ClientData clientData, Tcl_Interp *interp,
                 int argc, char const *argv[])
{
    int error;
    int ftype, Ftype, class;
    char *new_flow_upcall, *recv_upcall, *timer_upcall;
    char *asret;
    static char *usage =
		"Usage: fl_set_flow_type "
		"?-n new_flow_command? ?-r recv_command? "
		"?-t timer_command?  ?-c default_class? ?-f flow_type? "
		"?-F default_parent_flow_type? specifier";
    int op;
    extern char *optarg;
    extern int optind, opterr;

    ftype = 0;
    Ftype = 0;
    class = 0;
    new_flow_upcall = 0;
    recv_upcall = 0;
    timer_upcall = 0;
    opterr = 0;
    optind = 1;

    while ((op = getopt(argc, (char *const *)argv, "c:f:F:n:r:t:")) != EOF) {
        /* XXX ugly cast */
        switch (op) {
	    case 'c':
		    class = atoi(optarg);
		    break;
	    case 'f':
		    ftype = atoi(optarg);
		    break;
	    case 'F':
		    Ftype = atoi(optarg);
		    break;
	    case 'n':
		    new_flow_upcall = strsave(optarg);
		    if (new_flow_upcall == 0) {
                Tcl_SetResult(interp, "malloc failed", TCL_STATIC);
                return TCL_ERROR;
		    }
		    break;
	    case 'r':
		    recv_upcall = strsave(optarg);
		    if (recv_upcall == 0) {
                Tcl_SetResult(interp, "malloc failed", TCL_STATIC);
                return TCL_ERROR;
		    }
		    break;
	    case 't':
		    timer_upcall = strsave(optarg);
		    if (timer_upcall == 0) {
                Tcl_SetResult(interp, "malloc failed", TCL_STATIC);
                return TCL_ERROR;
		    }
		    break;
	    default:
		    Tcl_SetResult(interp, usage, TCL_STATIC);
		    return TCL_ERROR;
		    /*NOTREACHED*/
        }
    }

    argc -= optind;
    argv += optind;

    if (argc != 1) {
        Tcl_SetResult(interp, usage, TCL_STATIC);
        return TCL_ERROR;
    }

    if (ftype >= NUM(ftinfo)) {
        Tcl_SetResult(interp, "flow_type higher than maximum", TCL_STATIC);
        return TCL_ERROR;
    }

    error = set_flow_type(interp, ftype, Ftype, class, argv[0],
                          new_flow_upcall, recv_upcall, timer_upcall);
    if (error != TCL_OK) {
        return error;
    }

    flow_types = 1;		/* got a flow type */

    asprintf(&asret, "%d", ftype);
    Tcl_SetResult(interp, asret, tclasfree);
    return TCL_OK;
}

static int
fl_class_stats(ClientData clientData, Tcl_Interp *interp,
		int argc, const char *argv[])
{
    clstats_p clsp;

    if (argc != 2) {
        Tcl_SetResult(interp, "Usage: fl_class_stats class", TCL_STATIC);
        return TCL_ERROR;
    }

    if (atoi(argv[1]) >= NUM(clstats)) {
        Tcl_SetResult(interp, "class too high", TCL_STATIC);
        return TCL_ERROR;
    }

    clsp = &clstats[atoi(argv[1])];

    Tcl_SetResult(interp, class_statistics(clsp), TCL_VOLATILE);
    return TCL_OK;
}


/*
 * set up to enumerate the classes.
 */

static int
fl_start_class_enumeration(ClientData clientData, Tcl_Interp *interp,
		int argc, const char *argv[])
{
    class_enum_state = clstats;
    return TCL_OK;
}

static int
fl_continue_class_enumeration(ClientData clientData, Tcl_Interp *interp,
		int argc, const char *argv[])
{
    u_long sipg;
    struct timeval last_rcvd;
    clstats_p cl;

    while (class_enum_state) {
        cl = class_enum_state;
        class_enum_state++;
        if (class_enum_state >= &clstats[NUM(clstats)]) {
            class_enum_state = 0;
        }
        if (cl->cls_last_bin_active == ri.ri_binno) {
            Tcl_SetResult(interp, class_statistics(cl), TCL_VOLATILE);
            /* now, clear stats for next go round... */
            /* but, preserve sipg and last rcvd... */
            sipg = cl->cls_sipg;
            last_rcvd = cl->cls_last_pkt_rcvd;
            memset(cl, 0, sizeof *cl);
            cl->cls_last_bin_active = ri.ri_binno;
            cl->cls_sipg = sipg;
            cl->cls_last_pkt_rcvd = last_rcvd;
            return TCL_OK;
        }
    }
    Tcl_SetResult(interp, "", TCL_STATIC);
    return TCL_OK;
}



/*
 * set up to enumerate the flows.
 */

static int
fl_start_flow_enumeration(ClientData clientData, Tcl_Interp *interp,
		int argc, const char *argv[])
{
    flow_enum_state = table;
    return TCL_OK;
}

static int
fl_continue_flow_enumeration(ClientData clientData, Tcl_Interp *interp,
		int argc, const char *argv[])
{
    while (flow_enum_state) {
        if (flow_enum_state->fe_last_bin_active == ri.ri_binno) {
            Tcl_SetResult(interp,
                          flow_statistics(flow_enum_state), TCL_VOLATILE);
            flow_enum_state->fe_pkts_last_enum = flow_enum_state->fe_pkts;
            flow_enum_state->fe_bytes_last_enum = flow_enum_state->fe_bytes;
            flow_enum_state = flow_enum_state->fe_next_in_table;
            return TCL_OK;
        }
        flow_enum_state = flow_enum_state->fe_next_in_table;
    }
    Tcl_SetResult(interp, "", TCL_STATIC);
    return TCL_OK;
}



static int
set_tcpd_file(ClientData clientData, Tcl_Interp *interp, const char *filename)
{
    char *asret;
    /*
     * need to do this here (rather than in newfile()), because
     * we are about to overwrite pcap_descriptor.
     */
    if (filetype == TYPE_PCAP) {
        pcap_close(pcap_descriptor);
        pcap_descriptor = 0;
    }

    pcap_descriptor = pcap_open_offline(filename, pcap_errbuf);
    if (pcap_descriptor == 0) {
        asprintf(&asret, "%s", pcap_errbuf);
        Tcl_SetResult(interp, asret, tclasfree);
        return TCL_ERROR;
    }

    pcap_dlt = pcap_datalink(pcap_descriptor);
    pcap_snap = pcap_snapshot(pcap_descriptor);

    switch (pcap_dlt) {
    case DLT_EN10MB:
        pcap_receiver = receive_tcpd_en10mb;
        break;
    case DLT_SLIP:
        pcap_receiver = receive_tcpd_slip;
        break;
    case DLT_PPP:
        pcap_receiver = receive_tcpd_ppp;
        break;
    case DLT_FDDI:
        pcap_receiver = receive_tcpd_fddi;
        break;
    case DLT_NULL:
        pcap_receiver = receive_tcpd_null;
        break;
    default:
        asprintf(&asret, "unknown data link type %d", pcap_dlt);
        Tcl_SetResult(interp, asret, tclasfree);
        return TCL_ERROR;
    }

    if (newfile(interp, pcap_snap) != TCL_OK) {
        return TCL_ERROR;
    }

    filetype = TYPE_PCAP;
    return TCL_OK;
}

static int
fl_set_file(ClientData clientData, Tcl_Interp *interp,
		int argc, const char *argv[])
{
    static char *usage = "Usage: fl_set_file filename tcpd";

    if ((argc < 2) || (argc > 3)) {
        Tcl_SetResult(interp, usage, TCL_STATIC);
        return TCL_ERROR;
    }
    if ((argc == 2) || !strcmp(argv[2], "tcpd")) {
        return set_tcpd_file(clientData, interp, argv[1]);
    } else {
        Tcl_SetResult(interp, usage, TCL_STATIC);
        return TCL_ERROR;
    }
}

static int
fl_set_ll_classifier(ClientData clientData, Tcl_Interp *interp,
		int argc, const char *argv[])
{
    llcl_p llcl;

    if ((argc < 2) || (argc > 3)) {
        Tcl_SetResult(interp,
                      "Usage: fl_set_ll_classifier ll_classifier_index "
                      "[associated_flow_type_index]", TCL_STATIC);
        return TCL_ERROR;
    }
    llcl = &llclasses[atoi(argv[1])];
    if (llcl >= &llclasses[NUM(llclasses)]) {
        Tcl_SetResult(interp, "fl_set_ll_classifier ll_classifier_index too high",
                      TCL_STATIC);
        return TCL_ERROR;
    }
    if (argc == 3) {
        llcl->llcl_inuse = 1;
        llcl->llcl_fti = atoi(argv[2]);
        if (llcl->llcl_fti >= NUM(ftinfo)) {
            llcl->llcl_inuse = 0;
            Tcl_SetResult(interp,
                          "fl_set_ll_classifier associated_flow_type_index too high",
                          TCL_STATIC);
            return TCL_ERROR;
        }
    } else {
        llcl->llcl_inuse = 0;
    }
    return TCL_OK;
}

static int
fl_tcl_code(ClientData clientData, Tcl_Interp *interp,
		int argc, const char *argv[])
{
    if (argc != 1) {
        Tcl_SetResult(interp, "Usage: fl_tcl_code", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_SetResult(interp, fl_tclprogram, TCL_STATIC);
    return TCL_OK;
}


static int
fl_class_stats_format(ClientData clientData, Tcl_Interp *interp,
                       int argc, const char *argv[])
{
    char *new;

    switch (argc) {
    case 2:
        new = strsave(argv[1]);
        if (new == 0) {
            Tcl_SetResult(interp,
                       "fl_class_stats_format: unable to allocate space for format",
                       TCL_STATIC);
            return TCL_ERROR;
        }
        free(class_stats_format);
        class_stats_format = new;
        /* fall through */
    case 1:
        Tcl_SetResult(interp, class_stats_format, TCL_VOLATILE);
        break;
    default:
        Tcl_SetResult(interp,
                      "Usage: fl_class_stats_format [newformat]", TCL_STATIC);
        return TCL_ERROR;
    }
    return TCL_OK;
}


static int
fl_flow_stats_format(ClientData clientData, Tcl_Interp *interp,
                       int argc, const char *argv[])
{
    char *new;

    switch (argc) {
    case 2:
        new = strsave(argv[1]);
        if (new == 0) {
            Tcl_SetResult(interp,
                         "fl_flow_stats_format: unable to allocate space for format",
                         TCL_STATIC);
            return TCL_ERROR;
        }
        free(flow_stats_format);
        flow_stats_format = new;
        /* fall through */
    case 1:
        Tcl_SetResult(interp, flow_stats_format, TCL_VOLATILE);
        break;
    default:
        Tcl_SetResult(interp,
                      "Usage: fl_flow_stats_format [newformat]", TCL_STATIC);
        return TCL_ERROR;
    }
    return TCL_OK;
}



static int
fl_ri_stats_format(ClientData clientData, Tcl_Interp *interp,
                       int argc, const char *argv[])
{
    char *new;

    switch (argc) {
    case 2:
        new = strsave(argv[1]);
        if (new == 0) {
            Tcl_SetResult(interp,
                         "fl_ri_stats_format: unable to allocate space for format",
                         TCL_STATIC);
            return TCL_ERROR;
        }
        free(ri_stats_format);
        ri_stats_format = new;
        /* fall through */
    case 1:
        Tcl_SetResult(interp, ri_stats_format, TCL_VOLATILE);
        break;
    default:
        Tcl_SetResult(interp,
                      "Usage: fl_ri_stats_format [newformat]", TCL_STATIC);
        return TCL_ERROR;
    }
    return TCL_OK;
}


static int
fl_catch_signal(ClientData clientData, Tcl_Interp *interp,
		int argc, const char *argv[])
{
    struct sigaction act, oact;
    char *asret;

    act.sa_handler = gotsignal;
    if (sigemptyset(&act.sa_mask) == -1) {
        asprintf(&asret, "sigemptyset: %s", strerror(errno));
        Tcl_SetResult(interp, asret, tclasfree);
        return TCL_ERROR;
    }
    act.sa_flags = SA_RESTART;  /* w/out this, we take only one
                                 * signal, die on next */
    
    if (sigaction(SIGUSR1, &act, &oact) == -1) {
        asprintf(&asret, "sigaction: %s", strerror(errno));
        Tcl_SetResult(interp, asret, tclasfree);
        return TCL_ERROR;
    }
    return TCL_OK;
}

static delta_t
delta_decode(const char *string)
{
    if (!strcasecmp(string, "absolute")) {
        return absolute;
    } else if (!strcasecmp(string, "within_tr")) {
        return within_tr;
    } else if (!strcasecmp(string, "within_ri")) {
        return within_ri;
    } else {
        return invalid;
    }
}

static usecs_t
delta_usecs_decode(const char *string)
{
    if (!strcasecmp(string, "secs")) {
        return secs;
    } else if (!strcasecmp(string, "usecs")) {
        return usecs;
    } else {
        return invalid_usecs;
    }
}

        
static int
fl_time_format(ClientData clientData, Tcl_Interp *interp,
              int argc, const char *argv[])
{
    static char usage[] =
        "Usage: fl_time_format {absolute|within_tr_within_ri} {secs|usecs} "
        "{absolute|within_tr} {secs|usecs}";
    char *asret;
    delta_t l_delta_wi, l_delta_ri;
    usecs_t l_usecs_wi, l_usecs_ri;
    
    if (argc != 5) {
        /* XXX return current settings... */
        Tcl_SetResult(interp, usage, TCL_STATIC);
        return TCL_ERROR;
    }

    l_delta_wi = delta_decode(argv[1]);
    l_usecs_wi = delta_usecs_decode(argv[2]);
    l_delta_ri = delta_decode(argv[3]);
    l_usecs_ri = delta_usecs_decode(argv[4]);

    if (l_delta_wi == invalid) {
        asprintf(&asret, "invalid \"within\" delta parameter: %s.\n%s\n",
                 argv[1], usage);
        Tcl_SetResult(interp, asret, tclasfree);
        return TCL_ERROR;
    }
    if (l_usecs_wi == invalid_usecs) {
        asprintf(&asret, "invalid \"within\" usecs parameter: %s.\n%s\n",
                 argv[2], usage);
        Tcl_SetResult(interp, asret, tclasfree);
        return TCL_ERROR;
    }
    if ((l_delta_ri == invalid) || (l_delta_ri == within_ri)) {
        asprintf(&asret,
                 "invalid \"reporting interval\" delta parameter: %s.\n%s\n",
                 argv[3], usage);
        Tcl_SetResult(interp, asret, tclasfree);
        return TCL_ERROR;
    }
    if (l_usecs_ri == invalid_usecs) {
        asprintf(&asret,
                 "invalid \"reporting interval\" usecs parameter: %s.\n%s\n",
                 argv[4], usage);
        Tcl_SetResult(interp, asret, tclasfree);
        return TCL_ERROR;
    }

    th_wi.delta = l_delta_wi;
    th_wi.usecs = l_usecs_wi;
    th_ri.delta = l_delta_ri;
    th_ri.usecs = l_usecs_ri;
    
    return TCL_OK;
}


static int
fl_version(ClientData clientData, Tcl_Interp *interp,
		int argc, const char *argv[])
{
    if (argc != 1) {
        Tcl_SetResult(interp, "Usage: fl_set_version", TCL_STATIC);
        return TCL_ERROR;
    }
    Tcl_SetResult(interp, flstats_c_rcsid, TCL_STATIC);
    return TCL_OK;
}


int
Tcl_AppInit(Tcl_Interp *interp)
{

#if	0
    /* We *don't* call Tcl_Init(), since that requires Tcl to be
     * installed on the execution machine (and, we want to run
     * on lots of execution machines, requiring as little as
     * possible on each machine).
     */
    if (Tcl_Init(interp) == TCL_ERROR) {
        return TCL_ERROR;
    }
#endif	/* 0 */

    Tcl_CreateCommand(interp, "fl_catch_signal", fl_catch_signal,
                      NULL, NULL);
    Tcl_CreateCommand(interp, "fl_class_stats_format", 
                      fl_class_stats_format, NULL, NULL);
    Tcl_CreateCommand(interp, "fl_class_stats", fl_class_stats,
                      NULL, NULL);
    Tcl_CreateCommand(interp, "fl_continue_class_enumeration",
                      fl_continue_class_enumeration, NULL, NULL);
    Tcl_CreateCommand(interp, "fl_continue_flow_enumeration",
                      fl_continue_flow_enumeration, NULL, NULL);
    Tcl_CreateCommand(interp, "fl_time_format", fl_time_format,
                      NULL, NULL);
    Tcl_CreateCommand(interp, "fl_flow_stats_format", 
                      fl_flow_stats_format, NULL, NULL);
    Tcl_CreateCommand(interp, "fl_read_one_bin", fl_read_one_bin,
                      NULL, NULL);
    Tcl_CreateCommand(interp, "fl_ri_stats_format", 
                      fl_ri_stats_format, NULL, NULL);
    Tcl_CreateCommand(interp, "fl_set_file", fl_set_file,
                      NULL, NULL);
    Tcl_CreateCommand(interp, "fl_set_flow_type", fl_set_flow_type,
                      NULL, NULL);
    Tcl_CreateCommand(interp, "fl_set_ll_classifier", fl_set_ll_classifier,
                      NULL, NULL);
    Tcl_CreateCommand(interp, "fl_start_class_enumeration",
                      fl_start_class_enumeration, NULL, NULL);
    Tcl_CreateCommand(interp, "fl_start_flow_enumeration",
                      fl_start_flow_enumeration, NULL, NULL);
    Tcl_CreateCommand(interp, "fl_tcl_code", fl_tcl_code,
                      NULL, NULL);
    Tcl_CreateCommand(interp, "fl_version", fl_version,
                      NULL, NULL);

    /* call out to Tcl to set up whatever... */
    if (Tcl_GlobalEval(interp, fl_tclprogram) != TCL_OK) {
        return TCL_ERROR;
    }

    return Tcl_VarEval(interp, "fl_startup ",
                       argcount, " { ",
                       args, " }", (char *) NULL);
}

int
main(int argc, char *const argv[])
{
    int i;

    for (i = 0; i < NUM(timers); i++) {
        timers[i].fe_next_in_timer = timers[i].fe_prev_in_timer = &timers[i];
    }

    protohasports[6] = protohasports[17] = 1;
    flow_stats_format = strsave(flow_stats_template);
    class_stats_format = strsave(class_stats_template);
    ri_stats_format = strsave(ri_stats_template);
    th_wi.delta = th_ri.delta = absolute;
    th_wi.usecs = th_ri.usecs = usecs;
    if ((flow_stats_format == 0) || (class_stats_format == 0)) {
        fprintf(stderr,
                "%s:%d: no room for allocating formats\n", __FILE__, __LINE__);
        exit(1);
    }

    args = Tcl_Merge(argc-1, (const char *const *)(argv+1)); /* XXX ugly cast */
    sprintf(argcount, "%d", argc-1);

    /* we lie to Tcl_Main(), because, by gum, *WE* control argument parsing */
    Tcl_Main(1, (char **)argv, Tcl_AppInit); /* XXX ugly cast */
    exit(0);
}

/*
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Ipsilon Networks, Inc.
 * 4. The name of Ipsilon Networks, Inc., may not be used to endorse or
 *    promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY IPSILON NETWORKS, INC., ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL IPSILON NETWORKS, INC., BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
