/*
 * Copyright (c) 1996
 *	Ipsilon Networks, Inc.
 *
 * please see terms and conditions of copyright at the end of this file
 *
 */

/*
 * output flow statistics from a tcpdump file.
 *
 */

static char *flstats_h_rcsid = "$Id$";


/* global preprocessor defines */
#define	MAX_PACKET_SIZE		1518

#define	MAX_FLOW_ID_BYTES	30	/* maximum number of bytes in flow id */

#define	NUM(a)	(sizeof (a)/sizeof ((a)[0]))
#define	MIN(a,b)	((a) < (b) ? (a):(b))

#define PICKUP_NETSHORT(p)       ((((u_char *)p)[0]<<8)|((u_char *)p)[1])

#define	TIME_ADD(r,a,b)	{ \
		(r)->tv_sec = (a)->tv_sec + (b)->tv_sec;                \
		(r)->tv_usec = (a)->tv_usec + (b)->tv_usec;             \
		if ((r)->tv_usec >= 1000000) { /* deal with carry */    \
		    (r)->tv_sec++;                                      \
		    (r)->tv_usec -= 1000000;                            \
		}                                                       \
    }

#define	TIME_LE(a,b) \
		(((a)->tv_sec < (b)->tv_sec) \
			|| (((a)->tv_sec == (b)->tv_sec) && \
			    ((a)->tv_usec <= (b)->tv_usec)))

#define	TIME_LT(a,b) \
		(((a)->tv_sec < (b)->tv_sec) \
			|| (((a)->tv_sec == (b)->tv_sec) && \
			    ((a)->tv_usec < (b)->tv_usec)))

#define	TIME_GE(a,b)	(!TIME_LT((a),(b)))

#define	TIME_EQ(a,b) \
		(((a)->tv_sec == (b)->tv_sec) && \
			    ((a)->tv_usec == (b)->tv_usec))

#define	TIMEDIFFSECS(now,then) \
		(((now)->tv_sec-(then)->tv_sec) -\
			((now)->tv_usec < (then)->tv_usec ? 1 : 0))

#define	TIMEDIFFUSECS(now,then) \
		(((now)->tv_usec-(then)->tv_usec) +\
			((now)->tv_usec < (then)->tv_usec ? 1000000 : 0))

#define	NOW_AS_BINNO() (binsecs == 0 ? signalled : \
		(TIMEDIFFSECS(&curtime, &starttime)/binsecs))

#define	FLOW_ID_FROM_HDR(fid,hdr,ftip) { \
        int i, j;                                                       \
        for (i = 0, j = 0; j < ftip->fti_bytes_and_mask_len; i++, j += 2) { \
            (fid)[i] = (hdr)[ftip->fti_bytes_and_mask[j]]               \
                &ftip->fti_bytes_and_mask[j+1];                         \
        }                                                               \
    }

#define	SIPG_TO_SECS(x)	    (((x)>>3)/1000000)
#define	SIPG_TO_USECS(x)    (((x)>>3)%1000000)
#define	SECS_USECS_TO_SIPG(s,u)	((((s)*1000000)+(u))<<3)

/* Types of input files to be processed */
#define	TYPE_UNKNOWN	0
#define	TYPE_PCAP	2

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
        fe_pkts_last_enum,	/* number of packets *last* time enum done */
        fe_bytes,		/* number of bytes received */
        fe_bytes_last_enum,		/* number of bytes *last* time enum done */
        fe_sipg,		/* smoothed interpacket gap (units of 8 usec) */
        fe_last_bin_active,	/* last bin this saw activity */
        fe_upcall_when_pkts_ge,	/* num pkts needs to be >= m */
        fe_upcall_when_sipg_lt;	/* sipg needs to be < p */
    /* (0xffffffff ==> ignore sipg) */
    /* (0 ==> never call out) */
    struct timeval
	    fe_created,             /* time created */
        fe_last_pkt_rcvd,       /* time most recent packet seen */
        fe_upcall_when_secs_ge,	/* recv_upcall won't run till this time */
        fe_timer_time;	    	/* time to run timer routine */
    /* fields for hashing */
    u_short fe_sum;             /* hash of id, speeds up searching */
    u_char  fe_id_len;          /* length of id */
    flowentry_p
        fe_next_in_bucket,
	    fe_prev_in_bucket,
	    fe_next_in_table,
	    fe_prev_in_table,
	    fe_next_in_timer,
	    fe_prev_in_timer;
    u_char  fe_id[1];           /* variable sized (KEEP AT END!) */
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
    u_long
        cls_last_bin_active,	/* last bin this class saw activity */
	    cls_created,		/* num flows created in this class */
	    cls_deleted,		/* num flows created in this class */
	    cls_added,			/* num flows added to this class */
	    cls_removed,		/* num flows removed from this class */
	    cls_active,			/* flows active this interval */
	    cls_pkts,			/* packets read */
	    cls_bytes,			/* bytes read */
	    cls_sipg;			/* smoothed ipg (in 8 usec units) */
    struct timeval
        cls_last_pkt_rcvd;		/* time last packet received in class */
} clstats_t, *clstats_p;


/*
 * reporting interval structure
 *
 * only one, but defining for ease of use
 */

typedef struct ri {
    u_long ri_pkts,           /* number of packets received this ri */
        ri_bytes,             /* number of bytes seen this ri */
        ri_isipg,             /* smoothed ipg (w/in this ri) */
        ri_tsipg,             /* smoothed ipg (w/in trace) */
	    ri_fragpkts,          /* fragments seen (using ports) */
	    ri_fragbytes,         /* bytes seen in those frags */
	    ri_toosmallpkts,      /* packet length too small */
	    ri_toosmallbytes,     /* bytes seen in those frags */
	    ri_runtpkts,          /* captured portion too small */
	    ri_runtbytes,         /* bytes seen in those frags */
	    ri_noportpkts,        /* packet had no ports (but needed) */
	    ri_noportbytes;       /* bytes seen in those frags */
    struct timeval ri_starttime, /* time this ri started */
        ri_first_pkt_rcvd,    /* time first packet received this ri */
        ri_last_pkt_rcvd,     /* time last packet received this ri */
        ri_endtime;           /* time this ri ended */
} ri_t, *ri_p;



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
     * call:	"fti_new_flow_upcall class flowindex flowtype flowid"
     * result:	"class upper_class upper_ftype recvsecs.usecs"
     *			revcpkts recvsipg.usecs timersecs.usecs" 
     *
     * 'class' is the class of the new flow.  'upper_class'
     * is the class for any parent flow that might be created.
     * 'upper_ftype' is the flow type for a created parent flow.
     * recvsecs.usecs after the current time in the output flow,
     * a received packet will cause the flow types receive routine
     * to be called if recvpkts have been received and the smoothed
     * inter-packet gap is less that recvsipg.usecs.  timersecs.usecs
     * from now, the flow type's timer routine will be called for
     * this flow.
     */
    char    *fti_recv_upcall;	/* command to call when a pkt received */
    /*
     * routine:	recv_upcall
     * call:	"recv_upcall FLOW flowstats"
     * result:	"class recvsecs.usecs recvpkts sipgsecs.usecs" 
     *
     * if, on output, recvsecs is null (i.e., not returned),
     * then the recv_upcall will be made when the next packet
     * in this flow is received.
     */
    char    *fti_timer_upcall;	/* timer command (if registered) */
    /*
     * routine: timer_upcall
     * call:	"timer_upcall timesecs.usecs FLOW flowstats"
     * result:  "command secs.usecs"
     *
     * if "command" is "DELETE", the associated flow will be
     * deleted.  if "command" starts with '-', it will be ignored.
     * other values for "command" are TBD.
     *
     * if the flow is not deleted, the next timer upcall will
     * be made "secs.usecs" from the current time.  (A returned
     * value of "0" inhibits future timer upcalls for this flow.)
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
	{ "src8", 12, 0, 8, FMT_DOTTED}, { "dst8", 16, 0, 8, FMT_DOTTED},
	{ "src16", 12, 0, 16, FMT_DOTTED}, { "dst16", 16, 0, 16, FMT_DOTTED},
	{ "src24", 12, 0, 24, FMT_DOTTED}, { "dst24", 16, 0, 24, FMT_DOTTED},
	{ "src32", 12, 0, 32, FMT_DOTTED}, { "dst32", 16, 0, 32, FMT_DOTTED},
	{ "sport", 20, 0, 16}, { "dport", 22, 0, 16}
};



#if !defined(FDDIFC_LLC_ASYNC)
/*
 * if we can't find any FDDI header files...
 */     
        
struct fddi_header {
    u_char  fddi_fc; 
    u_char  fddi_dhost[6];              /* destination */
    u_char  fddi_shost[6];              /* source */
};      

#define FDDIFC_LLC_ASYNC    0x50
#endif  /* !defined(FDDIFC_LLC_ASYNC) */
 
#if !defined(FDDIFC_CLFF)
#define FDDIFC_CLFF         0xf0        /* length/class/format bits */
#endif /* !defined(FDDIFC_CLFF) */

            
#if !defined(LLC_UI)
/*              
 * if we can't find LLC header files...
 *                  
 * (this is a very minimal LLC header, sufficient only for our
 * limited needs.)
 */

struct llc {
    u_char  llc_dsap;                   /* source SAP (service access point) */
    u_char  llc_ssap;                   /* destination SAP */
    u_char  llc_control;                /* control byte (in some frames) */
};

#define LLC_UI          0x03            /* this is an unnumbered info frame */
#define LLC_SNAP_LSAP   0xaa            /* SNAP SAP */
#endif /* !defined(LLC_UI) */



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
