/*
 * output flow statistics from a tcpdump file.
 *
 * TODO:
 *	1.	Make non-ethernet specific!
 *	2.	Use indicies for *external* communication, but use
 *		pointers internally (ftype, class).
 *	3.	Support for #pkts, sipg, to trigger pkt-recv
 *		callout.
 *	4.	Document: [simul_setup], [flow_details],
 *		[class_details], [fl_read_one_bin].  Give
 *		examples of use; warn about memory consumption.
 *	7.	Verify the results of callouts (new flow, recv,
 *		timer) are valid.
 *  	8.  	Set atoft[] from Tcl code.  (Need to change "alltags"
 *		in [fl_setft]; or delete!)
 *  	9.  	Protohasports...
 *     11.  	Specify trace file/format on command line;
 *  	    	add fl_fileinfo (returns name and format).
 *     12.  	Change atoft[] to allow spec of (SHIFT_RIGHT|IN_PLACE)
 *		(to decouple output base from shifting) and DOTTED as
 *		a flag; make fmt == char * ("%d", say)?
 *     13.  	"dump tcl code" command.
 *     14.	Call to retrieve RCS Id.
 *     15.	set_file, takes "filename format".  make tcl
 *  	    	-tracefile parms a list.
 *     16.	Change "low level" comments to general lattice.
 */

static char *rcsid =
	"$Id: flstats.c,v 1.63 1996/03/14 05:59:28 minshall Exp minshall $";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>
#include <tcl.h>

/* global preprocessor defines */
#define	MAX_PACKET_SIZE		1518

#define	MAX_FLOW_ID_BYTES	24	/* maximum number of bytes in flow id */

#define	NUM(a)	(sizeof (a)/sizeof ((a)[0]))
#define	MIN(a,b)	((a) < (b) ? (a):(b))

#define PICKUP_NETSHORT(p)       ((((u_char *)p)[0]<<8)|((u_char *)p)[1])

#define	TIME_ADD(r,a,b)	{ \
		(r)->tv_sec = (a)->tv_sec + (b)->tv_sec; \
		(r)->tv_usec = (a)->tv_usec + (b)->tv_usec; \
		if ((r)->tv_usec >= 1000000) { /* deal with carry */ \
		    (r)->tv_sec++; \
		    (r)->tv_usec -= 1000000; \
		} \
	    }

#define	TIME_LE(a,b) \
		(((a)->tv_sec <= (b)->tv_sec) \
			|| (((a)->tv_sec == (b)->tv_sec) && \
			    ((a)->tv_usec <= (b)->tv_usec)))

#define	TIME_LT(a,b) \
		(((a)->tv_sec < (b)->tv_sec) \
			|| (((a)->tv_sec == (b)->tv_sec) && \
			    ((a)->tv_usec < (b)->tv_usec)))

#define	TIME_EQ(a,b) \
		(((a)->tv_sec == (b)->tv_sec) && \
			    ((a)->tv_usec == (b)->tv_usec))

#define	TIMEDIFFSECS(now,then) \
		(((now)->tv_sec-(then)->tv_sec) -\
			((now)->tv_usec < (then)->tv_usec ? 1 : 0))

#define	NOW_AS_BINNO() (binsecs == 0 ? 0 : \
		(TIMEDIFFSECS(&curtime, &starttime)/binsecs))

#define	FLOW_ID_FROM_HDR(fid,hdr,ftip) { \
	int i, j; \
	for (i = 0, j = 0; j < ftip->fti_bytes_and_mask_len; i++, j += 2) { \
	    (fid)[i] = (hdr)[ftip->fti_bytes_and_mask[j]] \
					&ftip->fti_bytes_and_mask[j+1]; \
	} \
    }


/* Types of input files to be processed */
#define	TYPE_UNKNOWN	0
#define	TYPE_PCAP	2
#define	TYPE_FIX	3

/* type defines */

/*
 * This is the basic hash table entry.
 */

typedef struct flowentry flowentry_t, *flowentry_p;

struct flowentry {
    /* fields for application use */
    u_short
	fe_flow_type,		/* which flow type is this? */
	fe_class,		/* class of this flow */
	fe_parent_ftype,	/* parent's flow type */
	fe_parent_class;	/* parent's class */
    u_long
	fe_pkts,		/* number of packets received */
	fe_bytes,		/* number of bytes received */
	fe_sipg,		/* smoothed interpacket gap (units of 8 usec) */
	fe_created_bin,
	fe_last_bin_active,	/* last bin this saw activity */
	fe_upcall_when_pkts_ge,	/* num pkts needs to be >= m */
	fe_upcall_when_sipg_lt;	/* sipg needs to be < p */
				/* (0xffffffff ==> ignore sipg) */
				/* (0 ==> never call out) */
    struct timeval
	fe_created,		/* time created */
	fe_last_pkt_rcvd,	/* time most recent packet seen */
	fe_upcall_when_secs_ge,	/* recv_upcall won't run till this time */
	fe_timer_time;	    	/* time to run timer routine */
    /* fields for hashing */
    u_short fe_sum;		/* hash of id, speeds up searching */
    u_char  fe_id_len;		/* length of id */
    flowentry_p
	    fe_next_in_bucket,
	    fe_prev_in_bucket,
	    fe_next_in_table,
	    fe_prev_in_table,
	    fe_next_in_timer,
	    fe_prev_in_timer;
    u_char  fe_id[1];		/* variable sized (KEEP AT END!) */
};

/*
 * At the lower level, application-defined "classes" are merely
 * known as a place to record some statistics.  Flow types and
 * flows map into classes.
 *
 * At this lower level, there is *no* representation of policy.
 * Instead, various policy parameters are set into the flow
 * type and/or flow entry structures.
 *
 * (If the *classifier* were moved into the lower level, then we
 * would represent policies specifically here.)
 */

typedef struct clstats {
    u_long  cls_created,		/* num flows created in this class */
	    cls_deleted,		/* num flows created in this class */
	    cls_added,			/* num flows added to this class */
	    cls_removed,		/* num flows removed from this class */
	    cls_active,			/* flows active this interval */
	    cls_pkts,			/* packets read */
	    cls_bytes,			/* bytes read */
	    cls_sipg,			/* smoothed ipg (in 8 usec units) */
	    cls_fragpkts,		/* fragments seen (using ports) */
	    cls_fragbytes,		/* bytes seen in those frags */
	    cls_toosmallpkts,		/* packet length too small */
	    cls_toosmallbytes,		/* bytes seen in those frags */
	    cls_runtpkts,		/* captured portion too small */
	    cls_runtbytes,		/* bytes seen in those frags */
	    cls_noportpkts,		/* packet had no ports (but needed) */
	    cls_noportbytes;		/* bytes seen in those frags */
    struct timeval
	    cls_last_pkt_rcvd;		/* time last packet received in class */
} clstats_t, *clstats_p;



/*
 * The following represents a flow type.  A flow type defines
 * the bits in the header used to separate packets into different
 * flows (within the same flow type).
 *
 * The way things work here is that the lower level turns incoming
 * packets into flows within a given flow type (based on a very
 * simple classifier which tries to match the packet with the most
 * specific flow type; this classifier knows about port numbers,
 * for example).  Then, if this is
 * a new flow, it will call into the upper level.  The upper level
 * can then specify a *different* flow type for packets of this
 * flow (in addition to some other parameters for this flow).
 * In essence, the more specific lower level flow is used to map
 * incoming packets into a higher level flow type.  One constraint
 * in doing this is that two packets which are in the same
 * *lower level* flow * cannot be in two *different* higher
 * level flows.
 *
 * The lower level *keeps* its specific flow entry, and points
 * it at the flow entry specified by the upper level.  Future
 * packets received at the specific flow are thus correlated
 * with the higher level flow without any interaction with the
 * higher level.
 *
 * When the upper level enumerates flows, it doesn't see any of
 * these more-specific lower level flows.
 *
 * (Note, however, that the upper level can indicate that the
 * flow type used by the lower level is the same flow type which
 * the upper level would like to use for a flow.  In this case,
 * enumerating the flows will cause that flow entry to be revealed.)
 *
 * To aid in this separation between lower-level and higher-level
 * flow types, the low-level classifier tries to fit the packet
 * into flow types starting at index 0, and stops when it runs
 * into a flow type that hasn't been initialized.  Thus, the
 * application can initialize the lower-level flow types, leave
 * a gap, and then initialize upper-level flow types, knowing
 * that the packet receive routine won't ever use "its" flow
 * types.  (In practice, this may not be needed at all.)
 * Fragmentation is painful here, since packets that *should* be
 * in a more-specific (i.e., including ports) flow type will be
 * classified in a less-specific flow type.
 */

typedef struct ftinfo ftinfo_t, *ftinfo_p;

struct ftinfo {
    u_char  fti_type_indicies[MAX_FLOW_ID_BYTES],
            fti_bytes_and_mask[2*MAX_FLOW_ID_BYTES];
    int	    fti_bytes_and_mask_len,
	    fti_type_indicies_len,
	    fti_id_len,		/* length of a flow id for this type */
	    fti_id_covers,	/* how far into pkt hdr the flow id reaches */
	    fti_class,		/* default class (overridable by upcall) */
	    fti_parent_ftype;	/* default PARENT flow type (ditto) */
    char    *fti_new_flow_upcall;
	    /*
	     * routine:	fti_new_flow_upcall
	     * call:	"fti_new_flow_upcall class flowtype flowid"
	     * result:	"class upper_class upper_ftype recvsecs.usecs"
	     *						timersecs.usecs" 
	     *
	     * 'class' is the class of the new flow.  'upper_class'
	     * is the class for any parent flow that might be created.
	     * 'upper_ftype' is the flow type for a created parent flow.
	     * recvsecs.usecs after the current time in the output flow,
	     * a received packet will cause the flow types receive routine
	     * to be called.  timersecs.usecs from now, the flow type's
	     * timer routine will be called for this flow.
	     */
    char    *fti_recv_upcall;	/* command to call when a pkt received */
	    /*
	     * routine:	recv_upcall
	     * call:	"recv_upcall class ftype flowid FLOW flowstats"
	     * result:	"class recvsecs.usecs" 
	     *
	     * if, on output, recvsecs is null,
	     * zero will be used (which means that recv_upcall will be
	     * called the next time a packet is received on that flow,
	     * no matter how soon it arrives).
	     */
    char    *fti_timer_upcall;	/* timer command (if registered) */
	    /*
	     * routine: timer_upcall
	     * call:	"timer_upcall class ftype flowid FLOW flowstats"
	     * result:  "command timersecs.usecs"
	     *
	     * if "command" is "DELETE", the associated flow will be
	     * deleted.  if "command" starts with '-', it will be ignored.
	     * other values for "command" are TBD.
	     */
};

#define	FTI_USES_PORTS(p) ((p)->fti_id_covers > 20)
#define	FTI_UNUSED(p)		((p)->fti_id_len == 0)

typedef struct llcl {
    int	llcl_inuse;
    int llcl_fti;	/* flow type index */
} llcl_t, *llcl_p;

#define	LLCL_UNUSED(p)		((p)->llcl_inuse == 0)

/*
 * This describes the IP header and relevant fields of TCP/UDP header.
 *
 * This is used for translating flow_types to an internal form (and
 * going backwards).
 *
 * This is also used for turning flowids into ascii, as well as
 * packet headers into ascii.  For the latter application, it is important
 * that the elements in the array 'atoft' be specified in the order in
 * which they occur in the packet header.
 */

typedef struct {
	char	*name;		/* external name */
	u_char	offset,		/* where in header */
		firstbit,	/* where the first bit is (0 == MSB) */
		numbits,	/* number of bits */
		fmt;		/* format for output (see below) */
} atoft_t, *atoft_p;

#define	FMT_DECIMAL	0	/* 123 */
#define	FMT_DOTTED	1	/* 1.2.3.4 (i.e., IP addresses) */
#define	FMT_HEX		2	/* 0x2a */

atoft_t atoft[] = {
	{ "ihv", 0, 0, 4 }, { "ihl", 0, 4, 4 }, { "tos", 1, 0, 8 },
	{ "len", 2, 0, 16 }, { "id", 4, 0, 16 },
	{ "df", 6, 1, 1}, { "mf", 6, 2, 1}, { "foff", 6, 3, 13},
	{ "ttl", 8, 0, 8}, { "prot", 9, 0, 8}, { "sum", 10, 0, 16},
	{ "src", 12, 0, 32, FMT_DOTTED}, { "dst", 16, 0, 32, FMT_DOTTED},
	{ "sport", 20, 0, 16}, { "dport", 22, 0, 16}
};


/* definition of FIX packet format */

/*
 * The input of the file looks like:
 *
 *         +-------------------------------------+  
 *      0  |        timestamp in seconds         |
 *         +-------------------------------------+
 *      1  |      timestamp in microseconds      |
 *         +-------------------------------------+
 *      2  |          IP source address          |
 *         +-------------------------------------+
 *      3  |       IP destination address        |
 *         +--------+---------+------------------+
 *      4  | IPProt | TCPflags|  Packet-length   |
 *         +--------+---------+------------------+
 *      5  | destination port |   source port    |
 *         +------------------+------------------+
 */         
            
            
struct fix24pkt {
    u_long  secs,
            usecs,
            src,
            dst;
#if (BYTE_ORDER == BIG_ENDIAN)  /* byte order makes my head hurt... */
    u_char  prot,
            tflags;
    u_short len,
            dport,  
            sport;  
#endif      
#if (BYTE_ORDER == LITTLE_ENDIAN)
    u_short len;
    u_char  prot,
            tflags;
    u_short sport,
            dport;
#endif
};

/* global variables */

u_char protohasports[256];

u_short IPtype = 0x800;

int fileeof = 0;
int filetype = 0;

flowentry_p buckets[31979];
flowentry_p onebehinds[NUM(buckets)];
flowentry_p table;			/* list of everything */
flowentry_p enum_state;

struct timeval curtime, starttime;

struct timeval ZERO = { 0, 0 };

int binsecs = 0;		/* number of seconds in a bin */

ftinfo_t ftinfo[10];		/* number of distinct flow types in use */

llcl_t llclasses[NUM(ftinfo)];

/*
 * application defined "classes".  Clstats[0] is special, in that
 * it gets any counts not tied to any other flow type or flow.
 */
clstats_t clstats[NUM(ftinfo)];

int flow_types = 0;

pcap_t *pcap_descriptor;
char pcap_errbuf[PCAP_ERRBUF_SIZE];

FILE *fix24_descriptor;

int packet_error = 0;

int pending, pendingcaplen, pendingpktlen;
u_char *pending_packet[MAX_PACKET_SIZE];

flowentry_t timers[150];

u_long binno;

char fl_tclprogram[] = 
#include "flstats.char"
;

/*
 * save a string
 */

char *
strsave(char *s)
{
    int n = strlen(s);
    char *new;

    new = (char *) malloc(n+1);
    if (new) {
	strncpy(new, s, n+1);
    }
    return new;
}


/*
 * a new file is being opened, so clean up from the last one.
 */

static void
newfile(void)
{
    flowentry_p fe, nfe;

    fileeof = 0;
    enum_state = 0;
    switch (filetype) {
    case TYPE_PCAP:
	filetype = TYPE_UNKNOWN;
	pcap_close(pcap_descriptor);
	break;
    case TYPE_FIX:
	filetype = TYPE_UNKNOWN;
	if (fclose(fix24_descriptor) == EOF) {
	    perror("fclose");
	    exit(2);
	}
	break;
    case TYPE_UNKNOWN:
	/* nothing to do */
	break;
    default:
	fprintf(stderr, "%s.%d: filetype %d unknown!\n", __FILE__, __LINE__, filetype);
	exit(2);
    }
    memset(&clstats[0], 0, sizeof clstats);
    curtime = ZERO;
    starttime = ZERO;
    pending = 0;

    for (fe = table; fe; fe = nfe) {
	nfe = fe->fe_next_in_table;
	free(fe);
    }
    table = 0;
    memset(buckets, 0, sizeof buckets);
    memset(onebehinds, 0, sizeof onebehinds);
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
    u_long sum;

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
	sprintf(result+strlen(result), "%s%s/%s", sep, xp->name, fidstring);
	/* sprintf(result+strlen(result), "%s%s", sep, fidstring); */
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

static char *
flow_statistics(flowentry_p fe)
{
    static char summary[100];

    sprintf(summary,
	    "created %ld.%06ld last %ld.%06ld pkts %lu bytes %lu sipg %lu",
	    fe->fe_created.tv_sec, fe->fe_created.tv_usec,
	    fe->fe_last_pkt_rcvd.tv_sec, fe->fe_last_pkt_rcvd.tv_usec,
	    fe->fe_pkts, fe->fe_bytes, fe->fe_sipg>>3);

    return summary;
}



static char *
class_statistics(clstats_p clsp)
{
    static char summary[100];

    sprintf(summary, "created %lu deleted %lu added %lu removed %lu "
	"active %lu pkts %lu bytes %lu sipg %lu fragpkts %lu fragbytes %lu "
	"toosmallpkts %lu toosmallbytes %lu runtpkts %lu runtbytes %lu "
        "noportpkts %lu noportbytes %lu lastrecv %ld.%06ld",
	clsp->cls_created, clsp->cls_deleted,
	clsp->cls_added, clsp->cls_removed, clsp->cls_active,
	clsp->cls_pkts, clsp->cls_bytes, clsp->cls_sipg>>3, clsp->cls_fragpkts,
	clsp->cls_fragbytes, clsp->cls_toosmallpkts, clsp->cls_toosmallbytes,
	clsp->cls_runtpkts, clsp->cls_runtbytes, clsp->cls_noportpkts,
	clsp->cls_noportbytes, clsp->cls_last_pkt_rcvd.tv_sec,
	clsp->cls_last_pkt_rcvd.tv_usec);

    return summary;
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
timer_delete(flowentry_p fe)
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
    char buf[100], buf2[100];
    int n;
    static void delete_flow(flowentry_p fe);

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
	     * call:	"timer_upcall class ftype flowid FLOW flowstats"
	     * result:  "command secs.usecs"
	     */
	    sprintf(buf, " %d %d ", fe->fe_class, fe->fe_flow_type);
	    sprintf(buf2, " %ld.%06ld ", curtime.tv_sec, curtime.tv_usec);
	    if (Tcl_VarEval(interp,
		    ftinfo[fe->fe_flow_type].fti_timer_upcall, buf,
		    flow_id_to_string(&ftinfo[fe->fe_flow_type], fe->fe_id),
		    buf2, " FLOW ", flow_statistics(fe), 0) != TCL_OK) {
		packet_error = TCL_ERROR;
		return;
	    }

	    fe->fe_timer_time.tv_usec = 0;
	    n = sscanf(interp->result, "%s %ld.%ld",
			buf, &fe->fe_timer_time.tv_sec,
			&fe->fe_timer_time.tv_usec);
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
set_time(Tcl_Interp *interp, u_long secs, u_long usecs)
{
    if ((starttime.tv_sec == ZERO.tv_sec) && 
				(starttime.tv_usec == ZERO.tv_usec)) {
	starttime.tv_sec = secs;
	starttime.tv_usec = usecs;
	curtime = starttime;
    } else {
	/* call timers once per second */
	while (curtime.tv_sec != secs) {
	    do_timers(interp);
	    curtime.tv_sec++;		/* advance the time */
	}
	curtime.tv_usec = usecs;
    }
    if (binno == -1) {
	binno = NOW_AS_BINNO();
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
#define MATCH(id,len,sum,type_index,p) \
	((sum == (p)->fe_sum) && (type_index == (p)->fe_flow_type) && \
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
    fe->fe_sum = sum;
    fe->fe_id_len = id_len;
    memcpy(fe->fe_id, id, id_len);

    fe->fe_next_in_bucket = *hbucket;
    if (fe->fe_next_in_bucket) {
	fe->fe_next_in_bucket->fe_prev_in_bucket = fe;
    }
    fe->fe_prev_in_bucket = 0;
    *hbucket = fe;

    fe->fe_next_in_table = table;
    if (fe->fe_next_in_table) {
	fe->fe_next_in_table->fe_prev_in_table = fe;
    }
    fe->fe_prev_in_table = 0;
    table = fe;

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
	timer_delete(fe);
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
    }

    free(fe);
}




static void
delete_flow(flowentry_p fe)
{
    clstats[fe->fe_class].cls_deleted++;
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
    fe->fe_pkts = 0;
    fe->fe_bytes = 0;
    fe->fe_sipg = 0;
    fe->fe_created_bin = binno;
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
	char buf[100];

	sprintf(buf, " %d %d ", fe->fe_class, ft-ftinfo);
	if (Tcl_VarEval(interp, ft->fti_new_flow_upcall,
		buf, flow_id_to_string(ft, fe->fe_id), 0) != TCL_OK) {
	    packet_error = TCL_ERROR;
	    return 0;
	}
	fe->fe_upcall_when_secs_ge.tv_usec = 0;
	fe->fe_timer_time.tv_usec = 0;

	n = sscanf(interp->result, "%hd %hd %hd %ld.%ld %ld %ld %ld.%ld",
		&fe->fe_class, &fe->fe_parent_class, &fe->fe_parent_ftype,
			    &fe->fe_upcall_when_secs_ge.tv_sec,
			    &fe->fe_upcall_when_secs_ge.tv_usec,
			    &fe->fe_upcall_when_pkts_ge,
			    &fe->fe_upcall_when_sipg_lt,
			    &fe->fe_timer_time.tv_sec,
			    &fe->fe_timer_time.tv_usec);

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
	if (n >= 8) {
	    if (!TIME_EQ(&fe->fe_timer_time, &ZERO)) {
		/* returned value is relative to now, so make absolute */
		TIME_ADD(&fe->fe_timer_time, &fe->fe_timer_time, &curtime);
		timer_insert(fe, &fe->fe_timer_time);
	    }
	}
    }
    clstats[fe->fe_class].cls_created++;
    return fe;
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

    /* update statistics */

    cl->cls_pkts++;
    cl->cls_bytes += len;
    if (cl->cls_last_pkt_rcvd.tv_sec) {		/* sipg */
	register u_long ipg;
	ipg = (curtime.tv_sec-cl->cls_last_pkt_rcvd.tv_sec)*1000000UL;
	ipg += (curtime.tv_usec - cl->cls_last_pkt_rcvd.tv_usec);
	/* two lines from VJ '88 SIGCOMM */
	ipg -= (cl->cls_sipg>>3);
	cl->cls_sipg += ipg;
    }
    cl->cls_last_pkt_rcvd = curtime;

    fe->fe_pkts++;
    fe->fe_bytes += len;
    if (fe->fe_last_pkt_rcvd.tv_sec) {		/* sipg */
	register u_long ipg;
	ipg = (curtime.tv_sec-fe->fe_last_pkt_rcvd.tv_sec)*1000000UL;
	ipg += (curtime.tv_usec - fe->fe_last_pkt_rcvd.tv_usec);
	/* two lines from VJ '88 SIGCOMM */
	ipg -= (fe->fe_sipg>>3);
	fe->fe_sipg += ipg;
    }
    fe->fe_last_pkt_rcvd = curtime;

    /* count activity in this bin */
    if (fe->fe_last_bin_active != binno) {
	fe->fe_last_bin_active = binno;
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
		(fe->fe_upcall_when_pkts_ge >= fe->fe_pkts) &&
		(fe->fe_upcall_when_sipg_lt < fe->fe_sipg) &&
		TIME_LE(&curtime, &fe->fe_upcall_when_secs_ge) &&
		!TIME_EQ(&fe->fe_upcall_when_secs_ge, &ZERO)) {
	char buf[60];
	int n, outcls;
	struct timeval outtime;

	sprintf(buf, " %d %d ", fe->fe_class, fe->fe_flow_type);

	if (Tcl_VarEval(interp, ftinfo[fe->fe_flow_type].fti_recv_upcall, buf,
		    flow_id_to_string(&ftinfo[fe->fe_flow_type], fe->fe_id),
				" FLOW ", flow_statistics(fe), 0) != TCL_OK) {
	    packet_error = TCL_ERROR;
	    return;
	}

	outcls = fe->fe_class;
	n = sscanf(interp->result, "%d %ld.%ld %ld %ld", &outcls,
				    &fe->fe_upcall_when_secs_ge.tv_sec,
				    &fe->fe_upcall_when_secs_ge.tv_usec,
				    &fe->fe_upcall_when_pkts_ge,
				    &fe->fe_upcall_when_sipg_lt);

	if (outcls != fe->fe_class) {
	    /* class is changing --- update statistics */
	    clstats[fe->fe_class].cls_removed++;
	    fe->fe_class = outcls;
	    clstats[fe->fe_class].cls_added++;
	}
	if (n >= 2) {
	    if (!TIME_EQ(&fe->fe_upcall_when_secs_ge, &ZERO)) {
		TIME_ADD(&fe->fe_upcall_when_secs_ge, &curtime, &outtime);
	    }
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
	    interp->result = "invalid condition in packetin";
	    packet_error = TCL_ERROR;
	    return;
	}
	pending = 0;
	binno = NOW_AS_BINNO();
	/* use the pending packet */
	packet = (const u_char *)pending_packet;
	caplen = pendingcaplen;
	pktlen = pendingpktlen;
    } else if (binno != NOW_AS_BINNO()) {
	/* if we've gone over to another bin number... */
	pending = 1;
	memcpy(pending_packet, packet, MIN(caplen, sizeof pending_packet));
	pendingcaplen = caplen;
	pendingpktlen = pktlen;
	/* wait till next time */
	return;
    }

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
		    if (pktprotohasports && (!packet[6]&0x1fff)) {
			break;
		    } else {
			fragmented = 1;	/* needed ports, but got a fragment */
		    }
		} else {
		    break;
		}
	    }
	}
    }

    if (llclindex >= NUM(llclasses)) {
	clstats[0].cls_pkts++;
	clstats[0].cls_bytes += pktlen;
	if (pktbigenough) {	/* packet was big enough, but... */
	    if (capbigenough) {
		if (packet[6]&0x1fff) {
		    clstats[0].cls_fragpkts++;
		    clstats[0].cls_fragbytes += pktlen;
		} else {
		    /*
		     * this means there is no flow type for protocols
		     * which don't have a port number field (i.e., this
		     * is probably a bug...
		     */
		    clstats[0].cls_noportpkts++;
		    clstats[0].cls_noportbytes += pktlen;
		}
	    } else {
		clstats[0].cls_runtpkts++;
		clstats[0].cls_runtbytes += pktlen;
	    }
	} else {
	    /* never found a flow type into which it fit */
	    clstats[0].cls_toosmallpkts++;
	    clstats[0].cls_toosmallbytes += pktlen;
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
		interp->result = "unable to create a new lower level flow";
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
		    interp->result = "unable to create a new upper level flow";
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
	    ulfe->fe_class = llfe->fe_parent_class;
	    clstats[ulfe->fe_class].cls_added++;
	}

	/* track packet stats */
	packetinflow(interp, ulfe, pktlen);

	/* OK, old ulfe is new llfe, and loop... */
	llfe = ulfe;
    }
}

static void
receive_tcpd(u_char *user, const struct pcap_pkthdr *h, const u_char *buffer)
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
                return;         /* only IP packets */
        }

        packetin(interp, buffer+14, h->caplen-14, h->len-14);
}


static void
receive_fix24(Tcl_Interp *interp, struct fix24pkt *pkt)
{
    static char pseudopkt[24] = {
	0x45, 0, 0, 0, 0, 0, 0, 0,
	0x22, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0};

    set_time(interp, ntohl(pkt->secs), ntohl(pkt->usecs));

    *(u_short *)&pseudopkt[2] = pkt->len;
    pseudopkt[9] = pkt->prot;
    /* src and dst are in ??? intel order ??? */
    *(u_long *)&pseudopkt[12] = ntohl(pkt->src);
    *(u_long *)&pseudopkt[16] = ntohl(pkt->dst);
    *(u_short *)&pseudopkt[20] = pkt->sport;
    *(u_short *)&pseudopkt[22] = pkt->dport;

    packetin(interp, pseudopkt, sizeof pseudopkt, ntohs(pkt->len));
}


static int
process_one_packet(Tcl_Interp *interp)
{
    packet_error = TCL_OK;

    if (pending) {
	packetin(interp, 0, 0, 0);
    } else {
	if (filetype == TYPE_PCAP) {
	    if (pcap_dispatch(pcap_descriptor, 1,
				receive_tcpd, (u_char *)interp) == 0) {
		fileeof = 1;
		filetype = TYPE_UNKNOWN;
	    }
	} else {	/* TYPE_FIX */
	    struct fix24pkt fix24packet;
	    int count;

	    count = fread(&fix24packet, sizeof fix24packet, 1, fix24_descriptor);
	    if (count == 0) {
		if (feof(fix24_descriptor)) {
		    fileeof = 1;
		    filetype = TYPE_UNKNOWN;
		} else {
		    interp->result = "error on read";
		    return TCL_ERROR;
		}
	    } else if (ntohs(fix24packet.len) != 65535) {
		/* 65535 ==> not IP packet (ethertype in dport) */
		receive_fix24(interp, &fix24packet);
	    }
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
		int argc, char *argv[])
{
    int error;
    char buf[20];

    if (argc > 2) {
	interp->result = "Usage: fl_read_one_bin ?binsecs?";
	return TCL_ERROR;
    } else if (argc == 2) {
	error = Tcl_GetInt(interp, argv[1], &binsecs);
	if (error != TCL_OK) {
	    return error;
	}
    } else if (argc == 1) {
	;		/* use old binsecs */
    }

    binno = -1;
    if (!fileeof) {
	if (filetype == TYPE_UNKNOWN) {
	    interp->result = "need to call fl_set_{tcpd,fix24}_file first";
	    return TCL_ERROR;
	}
	if (flow_types == 0) {
	    interp->result = "need to call fl_set_flow_type first";
	    return TCL_ERROR;
	}

	while (((binno == -1) || (binno == NOW_AS_BINNO())) && !fileeof) {
	    error = process_one_packet(interp);
	    if (error != TCL_OK) {
		return error;
	    }
	}
    }

    sprintf(buf, "%ld", binno);
    Tcl_SetResult(interp, buf, TCL_VOLATILE);
    return TCL_OK;
}

static int
set_flow_type(Tcl_Interp *interp, int ftype, int Ftype, int class,
				char *name, char *new_flow_upcall,
				char *recv_upcall, char *timer_upcall)
{
    char initial[MAX_FLOW_ID_BYTES*5], after[MAX_FLOW_ID_BYTES*5]; /* 5 rndm */
    char *curdesc;
    int bandm = 0;	/* number of bytes in fti_bytes_and_mask used */
    int indicies = 0;	/* index (in atoft) of each field in flow id */
    atoft_p xp;
    ftinfo_p fti = &ftinfo[ftype];

    /* forget current file type */
    fti->fti_bytes_and_mask_len = 0;
    fti->fti_id_covers = 0;
    fti->fti_id_len = 0;

    curdesc = name;

    if (strlen(name) > NUM(initial)) {
	interp->result = "flow name too long";
	return TCL_ERROR;
    }

    while (*curdesc) {
	int j, n;
	n = sscanf(curdesc, "%[a-zA-Z]%s", initial, after);
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
			interp->result = "flow type specifier too long";
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
		    interp->result = "too many fields in flow type specifier";
		    return TCL_ERROR;
		}
		fti->fti_type_indicies[indicies++] = j;
		break;
	    }
	}
	if (j >= NUM(atoft)) {
	    static char errbuf[100];

	    interp->result = errbuf;
	    sprintf(errbuf, "Bad flow field name %s in \"%s\"\n",
							initial, name);
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
					    int argc, char *argv[])
{
    int error;
    int ftype, Ftype, class;
    char *new_flow_upcall, *recv_upcall, *timer_upcall;
    static char result[20];
    static char *usage =
		"Usage: fl_set_flow_type "
		"?-n new_flow_command? ?-r recv_command? "
		"?-t timer_command?  ?-c default_class? ?-f flow_type? "
		"?-F default_parent_flow_type? specifier";
    int op;
    extern char *optarg;
    extern int optind, opterr, optreset;

    ftype = 0;
    Ftype = 0;
    class = 0;
    new_flow_upcall = 0;
    recv_upcall = 0;
    timer_upcall = 0;
    opterr = 0;
    optreset = 1;
    optind = 1;
    while ((op = getopt(argc, argv, "c:f:F:n:r:t:")) != EOF) {
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
			interp->result = "malloc failed";
			return TCL_ERROR;
		    }
		    break;
	    case 'r':
		    recv_upcall = strsave(optarg);
		    if (recv_upcall == 0) {
			interp->result = "malloc failed";
			return TCL_ERROR;
		    }
		    break;
	    case 't':
		    timer_upcall = strsave(optarg);
		    if (timer_upcall == 0) {
			interp->result = "malloc failed";
			return TCL_ERROR;
		    }
		    break;
	    default:
		    interp->result = usage;
		    return TCL_ERROR;
		    /*NOTREACHED*/
	}
    }

    argc -= optind;
    argv += optind;

    if (argc != 1) {
	interp->result = usage;
	return TCL_ERROR;
    }

    if (ftype >= NUM(ftinfo)) {
	interp->result = "flow_type higher than maximum";
	return TCL_ERROR;
    }

    error = set_flow_type(interp, ftype, Ftype, class, argv[0],
				new_flow_upcall, recv_upcall, timer_upcall);
    if (error != TCL_OK) {
	return error;
    }

    flow_types = 1;		/* got a flow type */

    sprintf(result, "%d", ftype);
    interp->result = result;
    return TCL_OK;
}

static int
fl_class_stats(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    clstats_p clsp;

    if (argc != 2) {
	interp->result = "Usage: fl_class_stats class";
	return TCL_ERROR;
    }

    if (atoi(argv[1]) >= NUM(clstats)) {
	interp->result = "class too high";
	return TCL_ERROR;
    }

    clsp = &clstats[atoi(argv[1])];

    Tcl_SetResult(interp, class_statistics(clsp), TCL_VOLATILE);
    return TCL_OK;
}


static int
fl_summary(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    if (argc != 1) {
	interp->result = "Usage: fl_summary";
	return TCL_ERROR;
    }

    Tcl_SetResult(interp, class_statistics(&clstats[0]), TCL_VOLATILE);
    return TCL_OK;
}


/*
 * set up to enumerate the flows.
 */

static int
fl_start_enumeration(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    enum_state = table;
    return TCL_OK;
}

static int
fl_continue_enumeration(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    char buf[200];

    if (enum_state) {
	Tcl_ResetResult(interp);
	sprintf(buf, "type %d class %d id ",
			    enum_state->fe_flow_type, enum_state->fe_class);
	Tcl_AppendResult(interp, buf,
		flow_id_to_string(&ftinfo[enum_state->fe_flow_type],
						enum_state->fe_id),
		" ", flow_statistics(enum_state), 0);
	enum_state = enum_state->fe_next_in_table;
    } else {
	interp->result = "";
    }
    return TCL_OK;
}


static int
set_tcpd_file(ClientData clientData, Tcl_Interp *interp, char *filename)
{
    newfile();
    pcap_descriptor = pcap_open_offline(filename, pcap_errbuf);
    if (pcap_descriptor == 0) {
	sprintf(interp->result, "%s", pcap_errbuf);
	return TCL_ERROR;
    }
    filetype = TYPE_PCAP;
    return TCL_OK;
}

static int
set_fix24_file(ClientData clientData, Tcl_Interp *interp, char *filename)
{
    newfile();
    fix24_descriptor = fopen(filename, "r");
    if (fix24_descriptor == 0) {
	interp->result = "error opening file";
	return TCL_ERROR;
    }
    filetype = TYPE_FIX;
    return TCL_OK;
}

static int
fl_set_file(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    static char *usage = "Usage: fl_set_file filename [tcpd|fix24]";

    if ((argc < 2) || (argc > 3)) {
	interp->result = usage;
	return TCL_ERROR;
    }
    if ((argc == 2) || !strcmp(argv[2], "tcpd")) {
	return set_tcpd_file(clientData, interp, argv[1]);
    } else if (!strcmp(argv[2], "fix24")) {
	return set_fix24_file(clientData, interp, argv[1]);
    } else {
	interp->result = usage;
	return TCL_ERROR;
    }
}

static int
fl_set_ll_classifier(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    llcl_p llcl;

    if ((argc < 2) || (argc > 3)) {
	interp->result = "Usage: fl_set_ll_classifier ll_classifier_index "
			    "[associated_flow_type_index]";
	return TCL_ERROR;
    }
    llcl = &llclasses[atoi(argv[1])];
    if (llcl >= &llclasses[NUM(llclasses)]) {
	interp->result = "fl_set_ll_classifier ll_classifier_index too high";
	return TCL_ERROR;
    }
    if (argc == 3) {
	llcl->llcl_inuse = 1;
	llcl->llcl_fti = atoi(argv[2]);
	if (llcl->llcl_fti > NUM(ftinfo)) {
	    llcl->llcl_inuse = 0;
	    interp->result =
		    "fl_set_ll_classifier associated_flow_type_index too high";
	    return TCL_ERROR;
	}
    } else {
	llcl->llcl_inuse = 0;
    }
    return TCL_OK;
}

static int
fl_tcl_code(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    if (argc != 1) {
	interp->result = "Usage: fl_set_version";
	return TCL_ERROR;
    }
    interp->result = fl_tclprogram;
    return TCL_OK;
}
static int
fl_version(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    if (argc != 1) {
	interp->result = "Usage: fl_set_version";
	return TCL_ERROR;
    }
    interp->result = rcsid;
    return TCL_OK;
}


int
Tcl_AppInit(Tcl_Interp *interp)
{
    if (Tcl_Init(interp) == TCL_ERROR) {
	return TCL_ERROR;
    }

    Tcl_CreateCommand(interp, "fl_class_stats", fl_class_stats,
								NULL, NULL);
    Tcl_CreateCommand(interp, "fl_continue_enumeration",
					fl_continue_enumeration, NULL, NULL);
    Tcl_CreateCommand(interp, "fl_read_one_bin", fl_read_one_bin,
								NULL, NULL);
    Tcl_CreateCommand(interp, "fl_set_file", fl_set_file,
								NULL, NULL);
    Tcl_CreateCommand(interp, "fl_set_flow_type", fl_set_flow_type,
								NULL, NULL);
    Tcl_CreateCommand(interp, "fl_set_ll_classifier", fl_set_ll_classifier,
								NULL, NULL);
    Tcl_CreateCommand(interp, "fl_start_enumeration", fl_start_enumeration,
								NULL, NULL);
    Tcl_CreateCommand(interp, "fl_summary", fl_summary,
								NULL, NULL);
    Tcl_CreateCommand(interp, "fl_tcl_code", fl_tcl_code,
								NULL, NULL);
    Tcl_CreateCommand(interp, "fl_version", fl_version,
								NULL, NULL);
    /* call out to Tcl to set up whatever... */
    if (Tcl_GlobalEval(interp, fl_tclprogram) != TCL_OK) {
	return TCL_ERROR;
    }
    return Tcl_Eval(interp, "fl_startup");
}

int
main(int argc, char *argv[])
{
    int i;

    for (i = 0; i < NUM(timers); i++) {
	timers[i].fe_next_in_timer = timers[i].fe_prev_in_timer = &timers[i];
    }

    protohasports[6] = protohasports[17] = 1;

    Tcl_Main(argc, argv, Tcl_AppInit);
    exit(0);
}
