/*
 * output flow statistics from a tcpdump file.
 *
 * TODO:
 *	1.	Make non-ethernet specific!
 *	2.	Use indicies for *external* communication, but use
 *		pointers internally (ftype, class).
 */


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
#define	TIME_LT(a,b) \
		(((a)->tv_sec < (b)->tv_sec) \
			|| (((a)->tv_sec == (b)->tv_sec) && \
			    ((a)->tv_usec < (b)->tv_usec)))

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

typedef struct hentry hentry_t, *hentry_p;

struct hentry {
    /* fields for application use */
    u_short
	flow_type,		/* which flow type is this? */
	parent_ftype,		/* parent's flow type index */
	class;			/* class of this flow */
    u_long
	packets,		/* number of packets received */
	created_bin,
	last_bin_active;

    char
	*pkt_recv_cmd;		/* command to call when a pkt received */
	    /*
	     * routine:	pkt_recv_cmd
	     * call:	"pkt_recv_cmd class flowtype flowid"
	     * result:	"class pkt_recv_cmd secs.usecs" 
	     *
	     * if, on output, pkt_recv_cmd is null, no command will
	     * be run.  if, on output, secs is null, zero will be used
	     * (which means that pkt_recv_cmd will be called the next
	     * time a packet is received on that flow, no matter how
	     * soon it arrives).
	     */

    char
	*timeout_cmd;		/* timeout command (if registered) */
	    /*
	     * routine: timeout_cmd
	     * call:	"timeout_cmd cookie class flowtype flowid
	     *				FLOW flowstats CLASS classstats"
	     * result:  "timeout_cmd secs.usecs cookie"
	     */
    void
	*timeout_cookie;	/* cookie for timeout routine */
    struct timeval
	created,		/* time created */
	last_pkt_rcvd,		/* time most recent packet seen */
	pkt_recv_cmd_time,	/* pkt_recv_cmd won't run till this time */
	timeout_time;		/* time to run timeout routine */
    /* fields for hashing */
    u_short sum;		/* hash of key, speeds up searching */
    u_char  key_len,		/* length of key */
	    level;		/* "level" - to allow same key at diff */
    hentry_p
	    next_in_bucket;
    hentry_p
	    next_in_table;
    u_char  key[1];		/* variable sized (KEEP AT END!) */
};

/* we define two levels; LOWER is for the low level machinery; HIGHER is ... */
#define	LEVEL_LOWER	0
#define	LEVEL_UPPER	1

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
    int	    cls_added,			/* flows added to this class */
	    cls_removed,		/* flows removed from this class */
	    cls_active,			/* flows active this interval */
	    cls_packets,		/* packets read */
	    cls_fragments,		/* fragments seen (using ports) */
	    cls_runts,			/* runt (too short) packets seen */
	    cls_noports;		/* packet had no ports (but needed) */
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
            fti_bytes_and_mask[2*MAX_FLOW_ID_BYTES],
	    fti_class;	/* default */
    int	    fti_bytes_and_mask_len,
	    fti_type_indicies_len,
	    fti_id_len,
	    fti_id_covers;

    char    *fti_new_flow_cmd;
	    /*
	     * routine:	fti_new_flow_cmd
	     * call:	"fti_new_flow_cmd class flowtype flowid"
	     * result:	"class flowtype pkt_recv_cmd secs.usecs" 
	     *
	     * the output flowtype is the application (upper
	     * level) flowtype (this flowtype must already exist/have
	     * been initialized); the class index is the index to be
	     * used by the new flow; pkt_recv_cmd is the command
	     * executed when a packet in the new flow is received
	     * secs.usecs after the current time in the output flow.
	     * note that if the output flowtype and flowid map to
	     * an existing flow, the class, pkt_recv, and
	     * secs.usecs return values are not used.
	     */
};

#define	FTI_USES_PORTS(p) ((p)->fti_id_covers > 20)
#define	FTI_UNUSED(p)		((p)->fti_id_len == 0)


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
		numbytes,	/* length of field */
		mask,		/* mask for data */
		fmt;		/* format for output (see below) */
} atoft_t, *atoft_p;

#define	FMT_DECIMAL	0	/* 123 */
#define	FMT_DOTTED	1	/* 1.2.3.4 (i.e., IP addresses) */
#define	FMT_HEX		2	/* 0x2a */

atoft_t atoft[] = {
	{ "ihv", 0, 1, 0xf0 }, { "ihl", 0, 1, 0x0f }, { "tos", 1, 1 },
	{ "len", 2, 2 }, { "id", 4, 2 }, { "foff", 6, 2}, { "ttl", 8, 1},
	{ "prot", 9, 1}, { "sum", 10, 2},
	{ "src", 12, 4, 0, FMT_DOTTED}, { "dst", 16, 4, 0, FMT_DOTTED},
	{ "sport", 20, 2}, { "dport", 22, 2}
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
            
            
struct fixpkt {
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

hentry_p buckets[31979];
hentry_p onebehinds[NUM(buckets)];
hentry_p table;			/* list of everything */
hentry_p enum_state;

struct timeval curtime, starttime;

struct timeval ZERO = { 0, 0 };

int binsecs = 0;		/* number of seconds in a bin */

ftinfo_t ftinfo[10];		/* number of distinct flow types in use */

/*
 * application defined "classes".  Clstats[0] is special, in that
 * it gets any counts not tied to any other flow type or flow.
 */
clstats_t clstats[NUM(ftinfo)];

int flow_types = 0;

pcap_t *pcap_descriptor;
char pcap_errbuf[PCAP_ERRBUF_SIZE];

FILE *fix_descriptor;

int packet_error = 0;

int pending;
u_char *pending_packet[MAX_PACKET_SIZE];

u_long binno;

char teho_tclprogram[] = 
#include "tehone.char"
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
    hentry_p hent, nhent;

    fileeof = 0;
    enum_state = 0;
    switch (filetype) {
    case TYPE_PCAP:
	filetype = TYPE_UNKNOWN;
	pcap_close(pcap_descriptor);
	break;
    case TYPE_FIX:
	filetype = TYPE_UNKNOWN;
	if (fclose(fix_descriptor) == EOF) {
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

    for (hent = table; hent; hent = nhent) {
	nhent = hent->next_in_table;
	free(hent);
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
 *
 * The seed parameter biases things slightly.
 */

static u_short
cksum(u_char *p, int len, u_long seed)
{
    int shorts = len/2;

    while (shorts > 4) {
/* 0*/	seed += PICKUP_NETSHORT(p); p += 2; seed += PICKUP_NETSHORT(p); p += 2;
/* 2*/	seed += PICKUP_NETSHORT(p); p += 2; seed += PICKUP_NETSHORT(p); p += 2;
/* 4*/	shorts -= 4;
    }

    while (shorts > 0) {
	seed += PICKUP_NETSHORT(p);
	p += 2;
	shorts--;
    }

    if (len&1) {
	seed += p[0]<<8;
    }

    /*
     * Reduce
     *
     * 0xffff + 0xffff = 0x1fffe.  So, 
     */
    seed = (seed&0xffff)+((seed>>16)&0xffff);
    seed = (seed&0xffff)+((seed>>16)&0xffff);	/* That's enough */

    return (u_short) (~htons(seed))&0xffff;
}
/* table lookup */

static hentry_p
tbl_lookup(u_char *key, int key_len, int level)
{
    u_short sum = cksum(key, key_len, level);
    hentry_p hent = buckets[sum%NUM(buckets)];
    hentry_p onebehind = onebehinds[sum%NUM(onebehinds)];
#define MATCH(key,len,sum,level,p) \
	((sum == (p)->sum) && (level == (p)->level) && (len == (p)->key_len) \
			&& !memcmp(key, (p)->key, len))

    if (onebehind && MATCH(key, key_len, sum, level, onebehind)) {
	return onebehind;
    }

    while (hent) {
	if (MATCH(key, key_len, sum, level, hent)) {
	    onebehinds[sum%NUM(onebehinds)] = hent;
	    break;
	}
	hent = hent->next_in_bucket;
    }
    return hent;
}

static hentry_p
tbl_add(u_char *key, int key_len, int level)
{
    u_short sum = cksum(key, key_len, level);
    hentry_p *bucket = &buckets[sum%NUM(buckets)];
    hentry_p hent;

    hent = (hentry_p) malloc(sizeof *hent+key_len-1);
    if (hent == 0) {
	return 0;
    }
    hent->sum = sum;
    hent->key_len = key_len;
    hent->level = level;
    hent->next_in_bucket = *bucket;
    *bucket = hent;
    hent->next_in_table = table;
    table = hent;
    memcpy(hent->key, key, key_len);
    return hent;
}


static void
set_time(u_long secs, u_long usecs)
{
    curtime.tv_sec = secs;
    curtime.tv_usec = usecs;
    if ((starttime.tv_sec == ZERO.tv_sec) && 
				(starttime.tv_usec == ZERO.tv_usec)) {
	starttime = curtime;
    }
    if (binno == -1) {
	binno = NOW_AS_BINNO();
    }
}


static char *
flow_id_to_string(ftinfo_p ft, u_char *id)
{
    static char result[MAX_FLOW_ID_BYTES*10];
    char fidstring[30], *fidp;
    char *sep = "", *dot, *fmt0xff, *fmt0xf;
    atoft_p xp;
    u_long decimal;
    int i, j;

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
	/* (clearly, mask 0xf0 or 0x0f is incompatible with numbytes > 1) */
	for (j = 0; j < xp->numbytes; j++) {
	    if ((xp->mask == 0) || (xp->mask == 0xff)) {
		if (xp->fmt == FMT_DECIMAL) {
		    decimal = (decimal<<8)+*id++;
		} else {
		    sprintf(fidp, fmt0xff, dot, *id++);
		    fidp += strlen(fidp);
		}
	    } else if (xp->mask == 0xf0) {
		if (xp->fmt == FMT_DECIMAL) {
		    decimal = (decimal<<4)+((*id++)>>4);
		} else {
		    sprintf(fidp, fmt0xf, dot, (*id++)>>4);
		    fidp += strlen(fidp);
		}
	    } else if (xp->mask == 0x0f) {
		if (xp->fmt == FMT_DECIMAL) {
		    decimal = (decimal<<4)+((*id++)&0xf);
		} else {
		    sprintf(fidp, fmt0xf, dot, (*id++)&0xf);
		    fidp += strlen(fidp);
		}
	    } else {
		/* unknown value for mask */
		fprintf(stderr,
			"%s:%d --- mask value %x of index %d of atoft bad!\n",
				__FILE__, __LINE__, xp->mask, i);
	    }
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


static hentry_p
new_flow(Tcl_Interp *interp, ftinfo_p ft, u_char *flowid, int level)
{
    hentry_p fe;

    fe = tbl_add(flowid, ft->fti_id_len, level);
    if (fe == 0) {
	return 0;
    }
    fe->flow_type = ft-ftinfo;
    fe->class = ft->fti_class;
    fe->packets = 0;
    fe->created_bin = binno;
    fe->last_bin_active = 0xffffffff;
    fe->pkt_recv_cmd = 0;
    fe->created = curtime;
    fe->pkt_recv_cmd_time = ZERO;

    /*
     * now, if there is a "new flow" callout registered in this
     * flow type, call it.
     *
     * the callout is allowed to change certain parameters of
     * this flow entry: the class, the parent flow type,
     * the pkt_recv_cmd and parameters, and the timeout_cmd
     * and parameters.
     */

    if (ft->fti_new_flow_cmd) {
	char buf[60], buf2[60];
	int n;

	sprintf(buf, " %d %d ", fe->class, ft-ftinfo);
	if (Tcl_VarEval(interp, ft->fti_new_flow_cmd,
		buf, flow_id_to_string(ft, fe->key), 0) != TCL_OK) {
	    packet_error = TCL_ERROR;
	    return 0;
	}
	buf[0] = 0;
	buf2[0] = 0;
	fe->pkt_recv_cmd_time.tv_usec = 0;
	fe->timeout_time.tv_usec = 0;
	fe->timeout_cookie = 0;

	n = sscanf(interp->result, "%hd %hd %s %ld.%ld %s %ld.%ld %p",
		&fe->class, &fe->parent_ftype, buf,
			    &fe->pkt_recv_cmd_time.tv_sec,
			    &fe->pkt_recv_cmd_time.tv_usec,
			    buf2, &fe->timeout_time.tv_sec,
			    &fe->timeout_time.tv_usec,
			    &fe->timeout_cookie);

	/*
	 * (yes, these "if" stmts could be nested, and thus
	 * be more efficient; but, they would be less legible,
	 * so...)
	 */
	if (buf[0] && (buf[0] != '-')) {
	    fe->pkt_recv_cmd = strsave(buf);
	} else {
	    fe->pkt_recv_cmd = 0;
	}
	if (n >= 4) {
	    /* returned value is relative to now, so make absolute */
	    TIME_ADD(&fe->pkt_recv_cmd_time,
			    &fe->pkt_recv_cmd_time, &curtime);
	}

	if (buf2[0] && (buf2[0] != '-')) {
	    fe->timeout_cmd = strsave(buf2);
	} else {
	    fe->timeout_cmd = 0;
	}
	if (n >= 7) {
	    /* returned value is relative to now, so make absolute */
	    TIME_ADD(&fe->timeout_time, &fe->timeout_time, &curtime);
	}
    }
    clstats[fe->class].cls_added++;
    return fe;
}


/*
 * do per flow processing of a packet that has been received.
 *
 * this involves updating counters as well as calling out
 * to the "packet_received" callback routine if appropriate.
 */

static void
packetinflow(Tcl_Interp *interp, hentry_p fe)
{
    ftinfo_p ft;
    clstats_p cl;

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
	 * 3.  if this is associated with a more coarse
	 *	statistics group, but some packets in that
	 *	statistics group might want to be in a different
	 *	(more fine grained) statistics group.
	 *	(i'm not sure about this, though; if the initial
	 *	flow types are as fine as you get, then this will
	 *	get accomplished when you create the new fine-grained
	 *	flow entry -- at that point you would have associated
	 *	that fine-grained flow entry with the more coarse-
	 *	grained statistics group.)
	 * 4.  as a way of "timing out" flows;  i.e., if this
	 *	has been idle for more than NNN seconds, then
	 *	this should be deleted.  by using the timer,
	 *	this can make the deletion "data driven" (by the
	 *	*next* packet received in the same flow).
	 */

    if (fe->pkt_recv_cmd && TIME_LT(&curtime, &fe->pkt_recv_cmd_time)) {
	char buf[60];
	int n;
	struct timeval outtime;

	sprintf(buf, " %d %d ", fe->class, fe->flow_type);

	if (Tcl_VarEval(interp, fe->pkt_recv_cmd,
		    buf, flow_id_to_string(ft, fe->key), 0) != TCL_OK) {
	    packet_error = TCL_ERROR;
	    return;
	}

	n = sscanf(interp->result, "%hd %s %ld.%ld",
				    &fe->class, buf,
				    &fe->pkt_recv_cmd_time.tv_sec,
				    &fe->pkt_recv_cmd_time.tv_usec);

	if (n >= 2) {
	    free(fe->pkt_recv_cmd);
	    if (buf[0] != '-') {
		fe->pkt_recv_cmd = strsave(buf);
	    } else {
		fe->pkt_recv_cmd = 0;
	    }
	    if (n >= 3) {
		TIME_ADD(&fe->pkt_recv_cmd_time, &curtime, &outtime);
	    }
	}
    }

    cl = &clstats[fe->class];
    /* update counters (after callout has had a chance to change things) */
    cl->cls_packets++;
    fe->packets++;
    fe->last_pkt_rcvd = curtime;
    if (fe->last_bin_active != binno) {
	fe->last_bin_active = binno;
	cl->cls_active++;
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
packetin(Tcl_Interp *interp, const u_char *packet, int len)
{
    u_char llfid[MAX_FLOW_ID_BYTES], ulfid[MAX_FLOW_ID_BYTES];
    int pkthasports, bigenough;
    hentry_p llfe, ulfe;	/* lower and upper level flow entries */
    ftinfo_p llft, ulft;	/* lower and upper level flow types */
    clstats_p llcl;		/* lower level class */

    /* if we've gone over to another bin number... */
    if (binno != NOW_AS_BINNO()) {
	if (pending) {
	    interp->result = "pending pending pending";
	    packet_error = TCL_ERROR;
	    return;
	}
	pending = 1;
	memcpy(pending_packet, packet, MIN(len, sizeof pending_packet));
	/* wait till next time */
	return;
    }

    /* check for a pending packet */
    if (pending) {
	if (len) {	/* shouldn't happen! */
	    interp->result = "invalid condition in packetin";
	    packet_error = TCL_ERROR;
	    return;
	}
	pending = 0;
	binno = NOW_AS_BINNO();
	/* use the pending packet */
	packet = (const u_char *)pending_packet;
    }

    /* now, do the low level classification into a llft */
    pkthasports = protohasports[packet[9]];
    bigenough = 0;
    for (llft = ftinfo; (llft < &ftinfo[NUM(ftinfo)]) && !FTI_UNUSED(llft);
								    llft++) {
	if (len >= llft->fti_id_covers) {
	    bigenough = 1;
	    if (pkthasports || !FTI_USES_PORTS(llft)) {
		break;
	    }
	}
    }

    if (llft >= &ftinfo[NUM(ftinfo)]) {
	clstats[0].cls_packets++;
	if (bigenough) {	/* packet was big enough, but... */
	    clstats[0].cls_noports++;
	} else {
	    /* never found a flow type into which it fit */
	    clstats[0].cls_runts++;
	}
	return;
    }

    llcl = &clstats[llft->fti_class];
    if ((packet[6]&0x1fff) && FTI_USES_PORTS(llft)) { /* XXX */
	llcl->cls_packets++;
	llcl->cls_fragments++;
	return;
    }

    /* create lower level flow id for this packet */
    FLOW_ID_FROM_HDR(llfid, packet, llft);

    /* find the lower level flow entry */
    llfe = tbl_lookup(llfid, llft->fti_id_len, LEVEL_LOWER);

    if (llfe == 0) {
	/* the lower level flow doesn't exist, so will need to be created */
	llfe = new_flow(interp, llft, llfid, LEVEL_LOWER);
	if (llfe == 0) {
	    if (packet_error == 0) {
		interp->result = "unable to create a new lower level flow";
		packet_error = TCL_ERROR;
	    }
	    return;
	}
    }

    /* now, need to find ulfe from llfe */

    ulft = &ftinfo[llfe->parent_ftype];		/* get ll's parent flow type */

    /* create the ulfid */
    FLOW_ID_FROM_HDR(ulfid, packet, ulft);

    /* lookup the upper level flow entry */
    ulfe = tbl_lookup(ulfid, ulft->fti_id_len, LEVEL_UPPER);

    if (ulfe == 0) {
	/* the upper level flow doesn't exist -- create it */
	ulfe = new_flow(interp, ulft, ulfid, LEVEL_UPPER);
	if (ulfe == 0) {
	    if (packet_error == 0) {
		interp->result = "unable to create a new upper level flow";
		packet_error = TCL_ERROR;
	    }
	    return;
	}
    }

    /* now, track packets in both the lower and upper flows */
    /* (notice this doesn't happen if any error above occurs...) */
    packetinflow(interp, llfe);
    packetinflow(interp, ulfe);
}

static void
receive_tcpd(u_char *user, const struct pcap_pkthdr *h, const u_char *buffer)
{
        u_short type;

	set_time(h->ts.tv_sec, h->ts.tv_usec);

        if (h->caplen < 14) {
		/* need to call packetin to set counters, etc. */
		packetin((Tcl_Interp *)user, buffer, 0);
                return;
        }

        type = buffer[12]<<8|buffer[13];

        if (type != IPtype) {
                return;         /* only IP packets */
        }

        packetin((Tcl_Interp *)user, buffer+14, h->caplen-14);
}


static void
receive_fix(Tcl_Interp *interp, struct fixpkt *pkt)
{
    static char pseudopkt[24] = {
	0x45, 0, 0, 0, 0, 0, 0, 0,
	0x22, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0};

    set_time(ntohl(pkt->secs), ntohl(pkt->usecs));

    *(u_short *)&pseudopkt[2] = pkt->len;
    pseudopkt[9] = pkt->prot;
    /* src and dst are in ??? intel order ??? */
    *(u_long *)&pseudopkt[12] = ntohl(pkt->src);
    *(u_long *)&pseudopkt[16] = ntohl(pkt->dst);
    *(u_short *)&pseudopkt[20] = pkt->sport;
    *(u_short *)&pseudopkt[22] = pkt->dport;

    packetin(interp, pseudopkt, sizeof pseudopkt);
}


static int
process_one_packet(Tcl_Interp *interp)
{
    packet_error = TCL_OK;

    if (pending) {
	packetin(interp, 0, 0);
    } else {
	if (filetype == TYPE_PCAP) {
	    if (pcap_dispatch(pcap_descriptor, 1,
				receive_tcpd, (u_char *)interp) == 0) {
		fileeof = 1;
		filetype = TYPE_UNKNOWN;
	    }
	} else {	/* TYPE_FIX */
	    struct fixpkt fixpacket;
	    int count;

	    count = fread(&fixpacket, sizeof fixpacket, 1, fix_descriptor);
	    if (count == 0) {
		if (feof(fix_descriptor)) {
		    fileeof = 1;
		    filetype = TYPE_UNKNOWN;
		} else {
		    interp->result = "error on read";
		    return TCL_ERROR;
		}
	    } else {
		receive_fix(interp, &fixpacket);
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
teho_read_one_bin(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    int error;
    char buf[20];

    if (argc > 2) {
	interp->result = "Usage: teho_read_one_bin ?binsecs?";
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
	    interp->result = "need to call teho_set_{tcpd,fix}_file first";
	    return TCL_ERROR;
	}
	if (flow_types == 0) {
	    interp->result = "need to call teho_set_flow_type first";
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
set_flow_type(Tcl_Interp *interp, int ftype, char *name,
					int class, char *new_flow_cmd)
{
    char initial[MAX_FLOW_ID_BYTES*5], after[MAX_FLOW_ID_BYTES*5]; /* 5 rndm */
    char *curdesc;
    int bandm = 0;	/* number of bytes in fti_bytes_and_mask used */
    int indicies = 0;	/* index (in atoft) of each field in flow id */
    atoft_p xp;

    /* forget current file type */
    ftinfo[ftype].fti_bytes_and_mask_len = 0;
    ftinfo[ftype].fti_id_covers = 0;
    ftinfo[ftype].fti_id_len = 0;

    curdesc = name;

    if (strlen(name) > NUM(initial)) {
	interp->result = "flow name too long";
	return TCL_ERROR;
    }

    while (*curdesc) {
	int j, n;
	n = sscanf(curdesc, "%[a-zA-Z]%s", initial, after);
	if (n == 0) {
	    goto goodout;
	}
	if (n == 1) {
	    curdesc = "";
	} else {
	    curdesc = after+1;	/* +1 to strip off delimiter */
	}
	for (j = 0, xp = atoft; j < NUM(atoft); j++, xp++) {
	    if (strcasecmp(xp->name, initial) == 0) {
		int off, num, mask;
		off = xp->offset;
		num = xp->numbytes;
		mask = xp->mask ? xp->mask : 0xff;
		while (num--) {
		    if (bandm >= (2*MAX_FLOW_ID_BYTES)) {
			interp->result = "flow type too long";
			return TCL_ERROR;
		    }
		    if (off > ftinfo[ftype].fti_id_covers) {
			ftinfo[ftype].fti_id_covers = off;
		    }
		    ftinfo[ftype].fti_bytes_and_mask[bandm++] = off++;
		    ftinfo[ftype].fti_bytes_and_mask[bandm++] = mask;
		}
		if (indicies >= NUM(ftinfo[ftype].fti_type_indicies)) {
		    interp->result = "too many fields in flow type";
		    return TCL_ERROR;
		}
		ftinfo[ftype].fti_type_indicies[indicies++] = j;
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
goodout:
    ftinfo[ftype].fti_bytes_and_mask_len = bandm;
    ftinfo[ftype].fti_id_len = bandm/2;
    ftinfo[ftype].fti_type_indicies_len = indicies;
    ftinfo[ftype].fti_class = class;
    ftinfo[ftype].fti_new_flow_cmd = new_flow_cmd;
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
teho_set_flow_type(ClientData clientData, Tcl_Interp *interp,
					    int argc, char *argv[])
{
    int error;
    int ftype, class;
    char *new_flow_cmd;
    static char result[20];
    static char *usage =
		"Usage: teho_set_flow_type ?-s class?"
			" ?-c new_flow_command? ?-f flow_type string";
    int op;
    extern char *optarg;
    extern int optind, opterr, optreset;

    ftype = 0;
    class = 0;
    new_flow_cmd = 0;
    opterr = 0;
    optreset = 1;
    optind = 1;
    while ((op = getopt(argc, argv, "f:s:c:")) != EOF) {
	switch (op) {
	    case 'f':
		    ftype = atoi(optarg);
		    break;
	    case 's':
		    class = atoi(optarg);
		    break;
	    case 'c':
		    new_flow_cmd = strsave(optarg);
		    if (new_flow_cmd == 0) {
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

    if (class >= NUM(clstats)) {
	interp->result = "no room in ftinfo table";
	return TCL_ERROR;
    }

    error = set_flow_type(interp, ftype, argv[0], class, new_flow_cmd);
    if (error != TCL_OK) {
	return error;
    }

    flow_types = 1;		/* got a flow type */

    sprintf(result, "%d", ftype);
    interp->result = result;
    return TCL_OK;
}


static int
do_class_summary(Tcl_Interp *interp, clstats_p clsp)
{
    char summary[100];

    sprintf(summary,
	"added %d removed %d active %d pkts %d frags %d runts %d noports %d",
	clsp->cls_added, clsp->cls_removed, clsp->cls_active,
	clsp->cls_packets, clsp->cls_fragments, clsp->cls_runts,
	clsp->cls_noports);
    Tcl_SetResult(interp, summary, TCL_VOLATILE);
    return TCL_OK;
}

static int
teho_class_summary(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    clstats_p clsp;

    if (argc != 2) {
	interp->result = "Usage: teho_class_summary class";
	return TCL_ERROR;
    }

    if (atoi(argv[1]) >= NUM(clstats)) {
	interp->result = "class too high";
	return TCL_ERROR;
    }

    clsp = &clstats[atoi(argv[1])];

    return do_class_summary(interp, clsp);
}


static int
teho_summary(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    if (argc != 1) {
	interp->result = "Usage: teho_summary";
	return TCL_ERROR;
    }

    return do_class_summary(interp, &clstats[0]);
}


static char *
one_enumeration(hentry_p hp)
{
    return flow_id_to_string(&ftinfo[hp->flow_type], hp->key);
}


/*
 * set up to enumerate the flows.
 */

static int
teho_start_enumeration(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    enum_state = table;
    return TCL_OK;
}

static int
teho_continue_enumeration(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    char buf[20];

    if (enum_state) {
	Tcl_ResetResult(interp);
	sprintf(buf, "%d ", enum_state->flow_type);
	Tcl_AppendResult(interp, buf, one_enumeration(enum_state), 0);
	enum_state = enum_state->next_in_table;
    } else {
	interp->result = "";
    }
    return TCL_OK;
}


static int
teho_set_tcpd_file(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    if (argc != 2) {
	interp->result = "Usage: teho_set_tcpd_file filename";
	return TCL_ERROR;
    }
    newfile();
    pcap_descriptor = pcap_open_offline(argv[1], pcap_errbuf);
    if (pcap_descriptor == 0) {
	sprintf(interp->result, "%s", pcap_errbuf);
	return TCL_ERROR;
    }
    filetype = TYPE_PCAP;
    return TCL_OK;
}

static int
teho_set_fix_file(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    if (argc != 2) {
	interp->result = "Usage: teho_set_fix_file filename";
	return TCL_ERROR;
    }
    newfile();
    fix_descriptor = fopen(argv[1], "r");
    if (fix_descriptor == 0) {
	interp->result = "error opening file";
	return TCL_ERROR;
    }
    filetype = TYPE_FIX;
    return TCL_OK;
}


int
Tcl_AppInit(Tcl_Interp *interp)
{
    if (Tcl_Init(interp) == TCL_ERROR) {
	return TCL_ERROR;
    }

    Tcl_CreateCommand(interp, "teho_set_flow_type", teho_set_flow_type,
								NULL, NULL);
    Tcl_CreateCommand(interp, "teho_read_one_bin", teho_read_one_bin,
								NULL, NULL);
    Tcl_CreateCommand(interp, "teho_start_enumeration", teho_start_enumeration,
								NULL, NULL);
    Tcl_CreateCommand(interp, "teho_continue_enumeration",
					teho_continue_enumeration, NULL, NULL);
    Tcl_CreateCommand(interp, "teho_set_tcpd_file", teho_set_tcpd_file,
								NULL, NULL);
    Tcl_CreateCommand(interp, "teho_set_fix_file", teho_set_fix_file,
								NULL, NULL);
    Tcl_CreateCommand(interp, "teho_class_summary", teho_class_summary,
								NULL, NULL);
    Tcl_CreateCommand(interp, "teho_summary", teho_summary,
								NULL, NULL);
    /* call out to Tcl to set up whatever... */
    if (Tcl_GlobalEval(interp, teho_tclprogram) != TCL_OK) {
	return TCL_ERROR;
    }
    return Tcl_Eval(interp, "teho_startup");
}

int
main(int argc, char *argv[])
{
    protohasports[6] = protohasports[17] = 1;

    Tcl_Main(argc, argv, Tcl_AppInit);
    exit(0);
}
