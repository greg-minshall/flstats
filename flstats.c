/*
 * output flow statistics from a tcpdump file.
 *
 * TODO:
 *	1.	Make non-ethernet specific!
 */

/* enable onebehind caching (disable for relative performance tests) */
#define	ONEBEHIND

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>
#include <tcl.h>

/* global preprocessor defines */

#define	NUM(a)	(sizeof (a)/sizeof ((a)[0]))

#define	MAX_FLOW_ID_BYTES	24	/* maximum number of bytes in flow id */

#define PICKUP_NETSHORT(p)       ((((u_char *)p)[0]<<8)|((u_char *)p)[1])

#define	TIMEDIFFSECS(now,then) \
		(((now)->tv_sec-(then)->tv_sec) -\
			((now)->tv_usec < (then)->tv_usec ? 1 : 0))

#define	NOW_AS_BINNO() (binsecs == 0 ? 0 : \
		(TIMEDIFFSECS(&curtime, &starttime)/binsecs))

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
    u_char
	flow_type_index,	/* which flow type is this? */
	stats_group_index;	/* where are statistics recorded? */
    u_long
	packets,
	last_pkt_sec,
	last_pkt_usec,
	created_sec,
	created_usec,
	created_bin,
	last_bin_active;
    /* fields for hashing */
    u_short sum;
    u_short key_len;
    hentry_p next_in_bucket;
    hentry_p next_in_table;
    u_char key[1];		/* variable sized (KEEP AT END!) */
};


typedef struct ftstats {
    int	    fts_created,		/* flows created */
	    fts_deleted,		/* flows deleted */
	    fts_active,			/* flows active this interval */
	    fts_packets,		/* packets read */
	    fts_packetsnewflows,	/* packets arriving for new flows */
	    fts_fragments,		/* fragments seen (using ports) */
	    fts_runts,			/* runt (too short) packets seen */
	    fts_noports;		/* packet had no ports (but needed) */
} ftstats_t, *ftstats_p;

typedef struct ftinfo ftinfo_t, *ftinfo_p;

struct ftinfo {
    u_char  fti_type_indicies[MAX_FLOW_ID_BYTES],
            fti_bytes_and_mask[2*MAX_FLOW_ID_BYTES],
	    fti_stats_group_index;	/* default */
    int	    fti_bytes_and_mask_len,
	    fti_type_indicies_len,
	    fti_id_len,
	    fti_id_covers;
    char    *fti_new_flow_cmd;
};

#define	FTI_USES_PORTS(p) ((p)->fti_id_covers > 20)


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
#if	defined(ONEBEHIND)
hentry_p onebehinds[NUM(buckets)];
#endif	defined(ONEBEHIND)
hentry_p table;			/* list of everything */
hentry_p enum_state;

struct timeval curtime, starttime;

int binsecs = 0;		/* number of seconds in a bin */

ftinfo_t ftinfo[10];
ftstats_t ftstats[NUM(ftinfo)];

int flow_types = 0;

pcap_t *pcap_descriptor;
char pcap_errbuf[PCAP_ERRBUF_SIZE];

FILE *fix_descriptor;

u_char pending_flow_id[MAX_FLOW_ID_BYTES];
int pending, pending_flow_type;
int packet_error = 0;

u_long binno;


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
	if (close(fix_descriptor) < 0) {
	    perror("close");
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
    memset(&ftstats[0], 0, sizeof ftstats);
    curtime.tv_sec = curtime.tv_usec = 0;
    starttime.tv_sec = starttime.tv_usec = 0;
    pending = 0;

    for (hent = table; hent; hent = nhent) {
	nhent = hent->next_in_table;
	free(hent);
    }
    table = 0;
    memset(buckets, 0, sizeof buckets);
#if	defined(ONEBEHIND)
    memset(onebehinds, 0, sizeof onebehinds);
#endif	defined(ONEBEHIND)
}

/*
 * Compute a checksum on a contiguous area of storage
 *
 * This is tailored to doing quite short data structures,
 * in particular, flow ids
 *
 * This does *NOT* do the ones complement...
 */

static u_short
cksum(u_char *p, int len)
{
    u_long sum = 0;
    int shorts = len/2;

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
/* table lookup */

static hentry_p
tbl_lookup(u_char *key, int key_len)
{
    u_short sum = cksum(key, key_len);
    hentry_p hent = buckets[sum%NUM(buckets)];
#if	defined(ONEBEHIND)
    hentry_p onebehind = onebehinds[sum%NUM(onebehinds)];
#endif	defined(ONEBEHIND)

#if	defined(ONEBEHIND)
    if (onebehind && (onebehind->sum == sum) &&
		    (onebehind->key_len == key_len) &&
		    !memcmp(key, onebehind->key, key_len)) {
	return onebehind;
    }
#endif	defined(ONEBEHIND)

    while (hent) {
	if ((hent->sum == sum) && (hent->key_len == key_len) &&
				(!memcmp(key, hent->key, key_len))) {
#if	defined(ONEBEHIND)
	    onebehinds[sum%NUM(onebehinds)] = hent;
#endif	defined(ONEBEHIND)
	    break;
	}
	hent = hent->next_in_bucket;
    }
    return hent;
}

static hentry_p
tbl_add(u_char *key, int key_len)
{
    u_short sum = cksum(key, key_len);
    hentry_p *bucket = &buckets[sum%NUM(buckets)];
    hentry_p hent;

    hent = (hentry_p) malloc(sizeof *hent+key_len-1);
    if (hent == 0) {
	return 0;
    }
    hent->sum = sum;
    hent->key_len = key_len;
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
    if ((starttime.tv_sec == 0) && (starttime.tv_usec == 0)) {
	starttime.tv_sec = curtime.tv_sec;
	starttime.tv_usec = curtime.tv_usec;
    }
    if (binno == -1) {
	binno = NOW_AS_BINNO();
    }
}


static char *
flow_id_to_string(int ft, u_char *id)
{
    static char result[MAX_FLOW_ID_BYTES*10];
    char fidstring[30], *fidp;
    char *sep = "", *dot, *fmt0xff, *fmt0xf;
    atoft_p xp;
    u_long decimal;
    int i, j;

    result[0] = 0;
    for (i = 0; i < ftinfo[ft].fti_type_indicies_len; i++) {
	xp = &atoft[ftinfo[ft].fti_type_indicies[i]];
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
		    decimal = (decimal<<4)+(*id++)>>4;
		} else {
		    sprintf(fidp, fmt0xf, dot, (*id++)>>4);
		    fidp += strlen(fidp);
		}
	    } else if (xp->mask == 0x0f) {
		if (xp->fmt == FMT_DECIMAL) {
		    decimal = (decimal<<4)+(*id++)&0xf;
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
	/*sprintf(result+strlen(result), "%s%s/%s", sep, xp->name, fidstring);*/
	sprintf(result+strlen(result), "%s%s", sep, fidstring);
	sep = "/";
    }
    return result;
}


static char *
flow_type_to_string(int ft)
{
    static char result[MAX_FLOW_ID_BYTES*10];
    char *sep = "";
    int i;

    result[0] = 0;
    for (i = 0; i < ftinfo[ft].fti_type_indicies_len; i++) {
	sprintf(result+strlen(result), "%s%s",
			    sep, atoft[ftinfo[ft].fti_type_indicies[i]].name);
	sep = "/";
    }
    return result;
}


static void
packetin(Tcl_Interp *interp, const u_char *packet, int len)
{
    u_char flow_id[MAX_FLOW_ID_BYTES];
    int i, j, ft, pkthasports, bigenough;
    hentry_p hent;
    ftinfo_p ftip;
    ftstats_p ftsp;

    /* if no packet pending, then process this packet */
    if (pending == 0) {
	pkthasports = protohasports[packet[9]];
	bigenough = 0;
	for (ft = 0; ft < NUM(ftinfo); ft++) {
	    if (len >= ftinfo[ft].fti_id_covers) {
		bigenough = 1;
		if (pkthasports || !FTI_USES_PORTS(&ftinfo[ft])) {
		    break;
		}
	    }
	}
	if (ft >= NUM(ftinfo)) {
	    ftstats[0].fts_packets++;
	    if (bigenough) {	/* packet was big enough, but... */
		ftstats[0].fts_noports++;
	    } else {
		ftstats[0].fts_runts++;
	    }
	    return;
	}
	ftip = &ftinfo[ft];
	ftsp = &ftstats[ftip->fti_stats_group_index];
	if ((packet[6]&0x1fff) && FTI_USES_PORTS(ftip)) { /* XXX */
	    ftsp->fts_packets++;
	    ftsp->fts_fragments++;
	    return;
	}

	/* create flow id for this packet */
	for (i = 0, j = 0; j < ftip->fti_bytes_and_mask_len; i++, j += 2) {
	    pending_flow_id[i] = packet[ftip->fti_bytes_and_mask[j]]
					    &ftip->fti_bytes_and_mask[j+1];
	}
    } else {
	pending = 0;
	if (len) {	/* shouldn't happen! */
	    interp->result = "invalid condition in packetin";
	    packet_error = TCL_ERROR;
	    return;
	}
	ft = pending_flow_type;
	ftip = &ftinfo[ft];
	ftsp = &ftstats[ftip->fti_stats_group_index];
	binno = NOW_AS_BINNO();
    }

    /* XXX shouldn't count runts, fragments, etc., if time hasn't arrived */
    if (binno != NOW_AS_BINNO()) {
	pending = 1;
	pending_flow_type = ft;
	return;
    }

    hent = tbl_lookup(pending_flow_id, ftip->fti_id_len);
    if (hent == 0) {
	hent = tbl_add(pending_flow_id, ftip->fti_id_len);
	if (hent == 0) {
	    interp->result = "no room for more flows";
	    packet_error = TCL_ERROR;
	    return;
	}
	hent->last_bin_active = 0xffffffff;
	hent->created_sec = curtime.tv_sec;
	hent->created_usec = curtime.tv_usec;
	hent->created_bin = binno;
	hent->flow_type_index = ft;
	if (ftip->fti_new_flow_cmd) {
	    char buf[20];
	    sprintf(buf, " %d ", ft);
	    if (Tcl_VarEval(interp, ftip->fti_new_flow_cmd,
			buf, flow_id_to_string(ft, hent->key), 0) != TCL_OK) {
		packet_error = TCL_ERROR;
		return;
	    }
	    hent->stats_group_index = atoi(interp->result);
	} else {
	    hent->stats_group_index = ftip->fti_stats_group_index; /* XXX */
	}
	ftsp = &ftstats[hent->stats_group_index];
	ftsp->fts_created++;
    }

    ftsp = &ftstats[hent->stats_group_index];
    ftsp->fts_packets++;

    hent->packets++;
    hent->last_pkt_sec = curtime.tv_sec;
    hent->last_pkt_usec = curtime.tv_usec;
    if (hent->last_bin_active != binno) {
	hent->last_bin_active = binno;
	ftsp->fts_active++;
    }
    if (hent->created_bin == binno) {
	ftsp->fts_packetsnewflows++;
    }
}

static void
newpacket(u_char *user, const struct pcap_pkthdr *h, const u_char *buffer)
{
        u_short type;
        u_long *longs;

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
    struct timeval cur;
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
				newpacket, (u_char *)interp) == 0) {
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
    if (filetype == TYPE_UNKNOWN) {
	interp->result = "need to call teho_set_{tcpd,fix}_file first";
	return TCL_ERROR;
    }
    if (flow_types == 0) {
	interp->result = "need to call teho_set_flow_type first";
	return TCL_ERROR;
    }

    binno = -1;

    if (!fileeof) {
	while (((binno == -1) || (binno == NOW_AS_BINNO())) && !fileeof) {
	    error = process_one_packet(interp);
	    if (error != TCL_OK) {
		return error;
	    }
	}
    }

    sprintf(buf, "%d", binno);
    Tcl_SetResult(interp, buf, TCL_VOLATILE);
    return TCL_OK;
}

static int
set_flow_type(Tcl_Interp *interp, int ft, char *name,
					int sgi, char *new_flow_cmd)
{
    char initial[MAX_FLOW_ID_BYTES*5], after[MAX_FLOW_ID_BYTES*5]; /* 5 rndm */
    char *curdesc;
    int bandm = 0;	/* number of bytes in fti_bytes_and_mask used */
    int indicies = 0;	/* index (in atoft) of each field in flow id */
    atoft_p xp;

    /* forget current file type */
    ftinfo[ft].fti_bytes_and_mask_len = 0;
    ftinfo[ft].fti_id_covers = 0;
    ftinfo[ft].fti_id_len = 0;

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
		    if (off > ftinfo[ft].fti_id_covers) {
			ftinfo[ft].fti_id_covers = off;
		    }
		    ftinfo[ft].fti_bytes_and_mask[bandm++] = off++;
		    ftinfo[ft].fti_bytes_and_mask[bandm++] = mask;
		}
		if (indicies >= NUM(ftinfo[ft].fti_type_indicies)) {
		    interp->result = "too many fields in flow type";
		    return TCL_ERROR;
		}
		ftinfo[ft].fti_type_indicies[indicies++] = j;
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
    ftinfo[ft].fti_bytes_and_mask_len = bandm;
    ftinfo[ft].fti_id_len = bandm/2;
    ftinfo[ft].fti_type_indicies_len = indicies;
    ftinfo[ft].fti_stats_group_index = sgi;
    ftinfo[ft].fti_new_flow_cmd = new_flow_cmd;
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
    int ft, sgi;
    char *new_flow_cmd;
    static char result[20];

    if ((argc < 3) || (argc > 5)) {
	interp->result =
		"Usage: teho_set_flow_type flow_type_index string ?statistics_group_index? ?new_flow_command?";
	return TCL_ERROR;
    }

    ft = atoi(argv[1]);

    if (ft >= NUM(ftinfo)) {
	interp->result = "flow_type_index higher than maximum";
	return TCL_ERROR;
    }

    if (argc >= 4) {
	sgi = atoi(argv[3]);
    } else {
	sgi = 0;
    }

    if (argc >= 5) {
	new_flow_cmd = strsave(argv[4]);
	if (new_flow_cmd == 0) {
	    interp->result = "malloc failed";
	    return TCL_ERROR;
	}
    } else {
	new_flow_cmd = 0;
    }

    if (sgi >= NUM(ftstats)) {
	interp->result = "no room in ftinfo table";
	return TCL_ERROR;
    }

    error = set_flow_type(interp, ft, argv[2], sgi, new_flow_cmd);
    if (error != TCL_OK) {
	return error;
    }

    flow_types = 1;		/* got a flow type */

    sprintf(result, "%d", ft);
    interp->result = result;
    return TCL_OK;
}


static int
teho_flow_type_summary(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    char summary[100];
    ftstats_p ftsp;

    if (argc != 2) {
	interp->result = "Usage: teho_summary statistics_group_index";
	return TCL_ERROR;
    }

    if (atoi(argv[1]) >= NUM(ftinfo)) {
	interp->result = "statistics_group_index too high";
	return TCL_ERROR;
    }

    ftsp = &ftstats[atoi(argv[1])];

    sprintf(summary, "%d %d %d %d %d",
		    ftsp->fts_created, ftsp->fts_active, ftsp->fts_packets,
		    ftsp->fts_packetsnewflows, ftsp->fts_fragments);
    Tcl_SetResult(interp, summary, TCL_VOLATILE);
    return TCL_OK;
}


static int
teho_summary(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    char summary[100];

    if (argc != 1) {
	interp->result = "Usage: teho_summary";
	return TCL_ERROR;
    }

    sprintf(summary, "%d %d %d %d %d %d",
		    ftstats[0].fts_created, ftstats[0].fts_active,
		    ftstats[0].fts_packets, ftstats[0].fts_packetsnewflows,
		    ftstats[0].fts_runts, ftstats[0].fts_fragments);
    Tcl_SetResult(interp, summary, TCL_VOLATILE);
    return TCL_OK;
}


static char *
one_enumeration(hentry_p hp)
{
    return flow_id_to_string(hp->flow_type_index, hp->key);
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
	sprintf(buf, "%d ", enum_state->flow_type_index);
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
    Tcl_CreateCommand(interp, "teho_flow_type_summary", teho_flow_type_summary,
								NULL, NULL);
    Tcl_CreateCommand(interp, "teho_summary", teho_summary,
								NULL, NULL);

    tcl_RcFileName = "~/.tehone.tcl";
    return TCL_OK;
}

main(int argc, char *argv[])
{
    protohasports[6] = protohasports[17] = 1;

    Tcl_Main(argc, argv, Tcl_AppInit);
    exit(0);
}
