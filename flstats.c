/*
 * output flow statistics from a tcpdump file.
 *
 * TODO:
 *	1.	Make non-ethernet specific!
 */

#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <tcl.h>

/* global preprocessor defines */

#define	NUM(a)	(sizeof (a)/sizeof ((a)[0]))

#define	MAX_FLOW_TYPE	24	/* maximum number of bytes in a flow id */

#define PICKUP_NETSHORT(p)       ((((u_char *)p)[0]<<8)|((u_char *)p)[1])

#define	TIMETOBINNO() (binsecs == 0 ? 0 : \
		(timesecs-starttimesecs)/binsecs - \
			(timeusecs < starttimeusecs ? 1:0))

/* type defines */

typedef struct hentry hentry_t, *hentry_p;

struct hentry {
    /* fields for application use */
    u_long
	packets,
	last_pkt_secs,
	last_pkt_usecs,
	created_secs,
	created_usecs,
	last_bin_active;
    /* fields for hashing */
    u_short sum;
    u_short key_len;
    hentry_p next_in_bucket;
    hentry_p next_in_table;
    u_char key[1];		/* variable sized (KEEP AT END!) */
};

/* global variables */

u_short IPtype = 0x800;

hentry_p buckets[3197];
hentry_p table;			/* list of everything */

u_long timesecs, timeusecs;
u_long starttimesecs, starttimeusecs;

int binsecs = 0;		/* number of seconds in a bin */

u_char flow_type[2*MAX_FLOW_TYPE];
int flow_type_len, flow_id_len, flow_type_covers;

pcap_t *pcap_descriptor;
char pcap_errbuf[PCAP_ERRBUF_SIZE];

u_char pending_flow_id[MAX_FLOW_TYPE];
int pending;
int packet_error = 0;

u_long binno;

/* various statistics */

int
    numflows,		/* number of flows */
    flowscreated,	/* flows created */
    flowsdeleted,	/* flows deleted */
    flowsactive,	/* flows active */
    packets,		/* number of packets read */
    packetsnewflows,	/* packets arriving for flows just created */
    runts,		/* runt (too short) packets seen */
    fragments;		/* fragments seen (when using ports) */

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

hentry_p
tbl_lookup(u_char *key, int key_len)
{
    u_short sum = cksum(key, key_len);
    hentry_p hent = buckets[sum%NUM(buckets)];

    while (hent) {
	if ((hent->sum == sum) && (hent->key_len == key_len) &&
				(!memcmp(key, hent->key, key_len))) {
	    break;
	}
    }
    return hent;
}

hentry_p
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
    timesecs = secs;
    timeusecs = usecs;
    if ((starttimesecs == 0) && (starttimeusecs == 0)) {
	starttimesecs = timesecs;
	starttimeusecs = timeusecs;
    }
    if (binno == -1) {
	binno = TIMETOBINNO();
    }
}


static void
packetin(Tcl_Interp *interp, const u_char *packet, int len)
{
    u_char flow_id[MAX_FLOW_TYPE];
    int i, j;
    hentry_p hent;

    packets++;

    /* if no packet pending, then process this packet */
    if (pending == 0) {

	if (len < flow_type_covers) {
	    runts++;
	    return;
	}
	if ((packet[6]&0x1fff) && (flow_type_covers > 20)) {
	    fragments++;	/* can't deal with if looking at ports */
	    return;
	}

	/* create flow id for this packet */
	for (i = 0, j = 0; j < flow_type_len; i++, j += 2) {
	    pending_flow_id[i] = packet[flow_type[j]]&flow_type[j+1];
	}

    } else {
	if (len) {	/* shouldn't happen! */
	    sprintf(interp->result, "invalid condition in packetin");
	    packet_error = TCL_ERROR;
	    return;
	}
	binno = TIMETOBINNO();
    }

    /* XXX shouldn't count runts, fragments, etc., if time hasn't arrived */
    if (binno != TIMETOBINNO()) {
	packets--;		/* undone by pending call packets++ above */
	pending = 1;
	return;
    } else {
	pending = 0;
    }

    hent = tbl_lookup(pending_flow_id, flow_id_len);
    if (hent == 0) {
	hent = tbl_add(pending_flow_id, flow_id_len);
	if (hent == 0) {
	    interp->result = "no room for more flows";
	    packet_error = TCL_ERROR;
	    return;
	}
	numflows++;
	hent->created_secs = timesecs;
	hent->created_usecs = timeusecs;
    }
    hent->packets++;
    hent->last_pkt_secs = timesecs;
    hent->last_pkt_usecs = timeusecs;
    if (hent->last_bin_active != binno) {
	flowsactive++;
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


process_one_packet(Tcl_Interp *interp)
{
    if (pending) {
	packetin(interp, 0, 0);
    } else {
	pcap_dispatch(pcap_descriptor, 1, newpacket, (u_char *)interp);
    }
}

/*
 * Read packets for one bin interval.
 */

static int
read_one_bin(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    u_int count = 0;
    int error;

    if (argc > 2) {
	interp->result = "Usage: read_one_bin ?binsecs?";
	return TCL_ERROR;
    } else if (argc == 2) {
	error = Tcl_GetInt(interp, argv[1], &binsecs);
	if (error != TCL_OK) {
	    return error;
	}
    } else if (argc == 1) {
	;		/* use old binsecs */
    }
    if (pcap_descriptor == 0) {
	interp->result = "need to call set_tcpd_file first";
	return TCL_ERROR;
    }
    if (flow_type_len == 0) {
	interp->result = "need to call set_flow_type first";
	return TCL_ERROR;
    }

    binno = -1;
    packet_error = TCL_OK;

    while (((binno == -1) || (binno == TIMETOBINNO())) &&
						(packet_error == TCL_OK)) {
	process_one_packet(interp);
	count++;
    }

    return TCL_OK;
}

static int
get_flow_type(Tcl_Interp *interp, char *name)
{
    char initial[200], after[200];
    char *curdesc;
    int i = 0;		/* number of bytes in flow_type used */
    static struct {
	char *name;	/* external name */
	char offset, numbytes, mask;	/* where in header, len, mask */
    } *xp, x[] = {
	{ "IHV", 0, 1, 0xf0 }, { "IHL", 0, 1, 0x0f }, { "TOS", 1, 1 },
	{ "LEN", 2, 2 }, { "ID", 4, 2 }, { "FOFF", 6, 2}, { "TTL", 8, 1},
	{ "PROT", 9, 1}, { "SUM", 10, 2}, { "SRC", 12, 4}, { "DST", 16, 4},
	{ "SPORT", 20, 2}, { "DPORT", 22, 2}
    };

    curdesc = name;

    if (strlen(name) > NUM(initial)) {
	interp->result = "flow_type too long";
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
	for (j = 0, xp = x; j < NUM(x); j++, xp++) {
	    if (strcasecmp(xp->name, initial) == 0) {
		int off, num, mask;
		off = xp->offset;
		num = xp->numbytes;
		mask = xp->mask ? xp->mask : 0xff;
		while (num--) {
		    if (i >= (2*MAX_FLOW_TYPE)) {
			interp->result = "flow_type too long";
			return TCL_ERROR;
		    }
		    if (off > flow_type_covers) {
			flow_type_covers = off;
		    }
		    flow_type[i++] = off++;
		    flow_type[i++] = mask;
		}
		break;
	    }
	}
	if (j >= NUM(x)) {
	    static char errbuf[100];

	    interp->result = errbuf;
	    sprintf(errbuf, "Bad flow field name %s in \"%s\"\n",
							initial, name);
	    return TCL_ERROR;
	}
    }
goodout:
    flow_type_len = i;
    flow_id_len = i/2;
    return TCL_OK;
}

static int
set_flow_type(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    int error;
    int i;
    char *sep;

    if (argc != 2) {
	interp->result = "Usage: set_flow_type flowtypedescription";
	return TCL_ERROR;
    }
    printf("argc %d, argv[0] %s, argv[1] %s\n", argc, argv[0], argv[1]);
    if (argc == 2) {
	error = get_flow_type(interp, argv[1]);
	if (error != TCL_OK) {
	    return error;
	}
	printf("flow type: ");
	sep = "";
	for (i = 0; i < flow_type_len; i += 2) {
	    printf("%s%02x%02x", sep, flow_type[i], flow_type[i+1]);
	    sep = ":";
	}
	printf("\n");
    }
    return TCL_OK;
}

static int
summary(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    if (argc != 1) {
	interp->result = "Usage: summary";
	return TCL_ERROR;
    }

    sprintf(interp->result, "%d %d %d %d %d %d %d %d",
				binno,
				numflows, flowscreated, flowsactive,
				packets, packetsnewflows,
				runts, fragments);
    return TCL_OK;
}


static int
start_enum(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    return TCL_OK;
}

static int
continue_enum(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    return TCL_OK;
}


static int
set_tcpd_file(ClientData clientData, Tcl_Interp *interp,
		int argc, char *argv[])
{
    if (argc != 2) {
	interp->result = "Usage: set_tcpd_file filename";
	return TCL_ERROR;
    }
    pcap_descriptor = pcap_open_offline(argv[1], pcap_errbuf);
    if (pcap_descriptor == 0) {
	sprintf(interp->result, "%s", pcap_errbuf);
	return TCL_ERROR;
    }
    return TCL_OK;
}


int
Tcl_AppInit(Tcl_Interp *interp)
{
    if (Tcl_Init(interp) == TCL_ERROR) {
	return TCL_ERROR;
    }

    Tcl_CreateCommand(interp, "set_flow_type", set_flow_type, NULL, NULL);
    Tcl_CreateCommand(interp, "read_one_bin", read_one_bin, NULL, NULL);
    Tcl_CreateCommand(interp, "start_enum", start_enum, NULL, NULL);
    Tcl_CreateCommand(interp, "continue_enum", continue_enum, NULL, NULL);
    Tcl_CreateCommand(interp, "set_tcpd_file", set_tcpd_file, NULL, NULL);
    Tcl_CreateCommand(interp, "summary", summary, NULL, NULL);

    tcl_RcFileName = "~/.tehone.tcl";
    return TCL_OK;
}

main(int argc, char *argv[])
{
    Tcl_Main(argc, argv, Tcl_AppInit);
    exit(0);
}
