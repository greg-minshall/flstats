### PARAMETERS ###

# some DEFINES
set CL_NONSWITCHED		3
set CL_TO_BE_SWITCHED		4
set CL_SWITCHED			5

set FT_LL_PORT			0
set FT_LL_NOPORT		1
set FT_GUARD			2
set FT_UL_PORT			3
set FT_UL_NOPORT		4

proc switchtime {} { return 0.300000 }	; # time to switch

#
# this routine is called when a low level flow
# is established.
#
# classify the incoming flow, and return the class and
# flow type of the upper level flow corresponding to this
# lower level flow
#
# additionally, start a timeout on the flow to reap it if unused
# over some period of time
#

proc\
classifier { class flowtype flowid }\
{
    global CL_NONSWITCHED CL_TO_BE_SWITCHED CL_SWITCHED
    global FT_UL_PORT FT_UL_NOPORT

    regexp {/prot/([^/]*)/} $flowid match prot
    switch -exact -- $prot {
    6 {return "$class $CL_SWITCHED $FT_UL_NOPORT - 0.0 \
							deleteflow 2.0 0x2"}
    11 {return "$class $CL_NONSWITCHED $FT_UL_NOPORT - 0.0 \
							deleteflow 2.0 0x2"}
    default {return "$class $CL_NONSWITCHED $FT_UL_NOPORT - 0.0 \
							deleteflow 2.0 0x2"}
    }
}

#
# this is called when a new upper level flow is established.
# this gives us a chance to start a packet_recv and timeout
# process
#

proc\
starttimeout { class flowtype flowid }\
{
    global CL_TO_BE_SWITCHED CL_NONSWITCHED

    if {$class == $CL_TO_BE_SWITCHED} {
	return "$class $class $flowtype getswitched [switchtime] \
							deleteflow 2.0 0x2"
    } else {
	return "$class $class $flowtype - 0.0  deleteflow 2.0 0x2"
    }
}

#
# this runs for both upper level and lower level flows
# to time them out.
#

proc\
deleteflow {cookie class ftype flowid time FLOW args}\
{
    global CL_SWITCHED CL_TO_BE_SWITCHED CL_NONSWITCHED

    # ahh, dr. regsub... 
    regsub -all {([a-zA-Z_]+) ([0-9.]+)} $args {[set x_\1 \2]} bar
    subst $bar

    if {[expr $time - $x_last] > $cookie} {
	return "DELETE"		; # gone...
    }

    set time [expr 2 * $cookie]
    if {$time > 64} {
	set time 64
    }

    return "- deleteflow $time.0 $time"
}


proc\
getswitched { class flowtype flowid args}\
{
    global CL_SWITCHED

    return "$CL_SWITCHED -"
}

### END OF PARAMTERS ###


# this doesn't need $pre, since the subst is performed at the caller...

proc\
get_summary_vec {class} \
{
	# ahh, dr. regsub... 
	regsub -all {([a-zA-Z_]+) ([0-9]+)} \
			[teho_class_summary $class] {[set ${pre}_\1 \2]} bar
	return $bar
}

# this doesn't need $pre, since the subst is performed at the caller...
#
# the $pre_\1 variables need to have been created prior to the
# call.  a call to get_summary_vec (and subst'ing) on the same
# class does this.

proc\
get_diff_vec {class} \
{
	# ahh, dr. regsub... 
	regsub -all {([a-zA-Z_]+) ([0-9]+)} [teho_class_summary $class] \
			{[set diff_${pre}_\1 [expr \2 - $${pre}_\1]]} bar
	return $bar
}

proc \
simul_setft { llflows ulflows } \
{
    set ftindex 0

    foreach flows [list $llflows $ulflows] {
	for {set whichflow 0} {$whichflow < [llength $flows]} \
					    { incr whichflow; incr ftindex } {
	    set flow [lindex $flows $whichflow]
	    puts "# flow $ftindex $flow"
	    set len [llength $flow]
	    if {$len >= 3} {
		global [lindex $flow 2]
		set $[lindex $flow 2] $ftindex
	    }
	    if {$len >= 2} {
		teho_set_flow_type -f $ftindex -c [lindex $flow 1] \
							    [lindex $flow 0]
	    } else {
		teho_set_flow_type -f $ftindex [lindex $flow 0]
	    }
	}
	incr ftindex			; # leave a gap between LL and UL
    }
}

# default flows...
# set LLFLOWS [list \
#     [list ihv/ihl/tos/ttl/prot/src/dst/sport/dport classifier] \
#     [list ihv/ihl/tos/ttl/prot/src/dst classifier]]
# set ULFLOWS [list \
#     [list ihv/ihl/tos/ttl/prot/src/dst/sport/dport starttimeout FT_UL_PORT] \
#     [list ihv/ihl/tos/ttl/prot/src/dst starttimeout FT_UL_NOPORT]]

set LLFLOWS { \
    { ihv/ihl/tos/ttl/prot/src/dst/sport/dport classifier } \
    { ihv/ihl/tos/ttl/prot/src/dst classifier }}
set ULFLOWS { \
    { ihv/ihl/tos/ttl/prot/src/dst/sport/dport starttimeout FT_UL_PORT } \
    { ihv/ihl/tos/ttl/prot/src/dst starttimeout FT_UL_NOPORT }}

proc \
simul_setup { fixortcpd filename {binsecs 1} \
		    { llflows $LLFLOWS } { ulflows $ULFLOWS }} \
{
    global LLFLOWS ULFLOWS

    set fname [glob $filename]

    if [regexp -nocase fix $fixortcpd] {
	teho_set_fix_file $fname
    } elseif [regexp -nocase tcpd $fixortcpd] {
	teho_set_tcpd_file $fname
    } else {
	puts "bad fixortcpd"
	return
    }

    file stat $fname filestats
    puts [format "# file %s size %d last written %d" \
			$fname $filestats(size) $filestats(mtime)]

    puts "#"
    simul_setft $LLFLOWS $ULFLOWS

    puts "#"
    puts "# binsecs $binsecs"

    puts "#"
}


proc \
flow_details { fixortcpd filename {binsecs 1} \
		{ llflows $LLFLOWS } { ulflows $ULFLOWS }} \
{
    global CL_NONSWITCHED CL_TO_BE_SWITCHED CL_SWITCHED
    global FT_LL_PORT FT_LL_NOPORT FT_UL_PORT FT_UL_NOPORT

    simul_setup $fixortcpd $filename $binsecs $llflows $ulflows

    while {1} {
	set bintime [lindex [split [time { \
			set binno [teho_read_one_bin $binsecs]}]] 0]
	if {$binno == -1} {
	    break;	# eof
	}
	set timeouttime [lindex [split [time { \
			set totalflows [teho_run_timeouts]}]] 0 ]

	teho_start_enumeration
	while { [set x [teho_continue_enumeration]] != ""} {
	    puts "$binno $x"
	}
    }
}


proc \
class_details { fixortcpd filename {binsecs 1} \
		{ llflows $LLFLOWS } { ulflows $ULFLOWS }}\
{
    global CL_NONSWITCHED CL_TO_BE_SWITCHED CL_SWITCHED
    global FT_LL_PORT FT_LL_NOPORT FT_UL_PORT FT_UL_NOPORT

    simul_setup $fixortcpd $filename $binsecs $llflows $ulflows

    puts "# plotvars 1 binno 2 pktsrouted 3 bytesrouted 4 pktsswitched"
    puts "# plotvars 5 bytesswitched 6 pktsdropped 7 bytesdropped"
    puts "# plotvars 8 created 9 deleted 10 numflows 11 totalflows"
    puts "# plotvars 12 bintime 13 timeouttime 14 vsz 15 rsz 16 cputime"

    # we are looking at 3 classes: 3, 4, 5
    #	3	non-switched flows
    #	4	to-be-switched flows
    #	5	switched flows

    set pid [pid]


    # preload the stats counters
    set pre non
    subst [get_summary_vec $CL_NONSWITCHED]
    set pre waiting
    subst [get_summary_vec $CL_TO_BE_SWITCHED]
    set pre switched
    subst [get_summary_vec $CL_SWITCHED]
    set pre gstats
    subst [get_summary_vec 0]

    while {1} {
	set bintime [lindex [split [time { \
			set binno [teho_read_one_bin $binsecs]}]] 0]
	if {$binno == -1} {
	    break;	# eof
	}
	set timeouttime [lindex [split [time { \
			set totalflows [teho_run_timeouts]}]] 0 ]

	# get differences from previous stats counters
	set pre non
	subst [get_diff_vec $CL_NONSWITCHED]
	set pre waiting
	subst [get_diff_vec $CL_TO_BE_SWITCHED]
	set pre switched
	subst [get_diff_vec $CL_SWITCHED]
	set pre gstats
	subst [get_diff_vec 0]

	# now, update the stats counters
	set pre non
	subst [get_summary_vec $CL_NONSWITCHED]
	set pre waiting
	subst [get_summary_vec $CL_TO_BE_SWITCHED]
	set pre switched
	subst [get_summary_vec $CL_SWITCHED]
	set pre gstats
	subst [get_summary_vec 0]
	set xx [exec ps lp$pid]
	set xx [lrange [split [join $xx]] 19 24]
	puts [format \
	    "%-7d %7d %7d %7d %7d %7d %7d %7d %7d %7d %7d %7d %7d %7d %7d %s" \
		$binno\
		[expr $diff_non_pkts + $diff_waiting_pkts] \
		[expr $diff_non_bytes + $diff_waiting_bytes] \
		$diff_switched_pkts \
		$diff_switched_bytes \
		[expr $diff_gstats_fragpkts + $diff_gstats_runtpkts \
			+ $diff_gstats_noportpkts] \
		[expr $diff_gstats_fragbytes + $diff_gstats_runtbytes \
			+ $diff_gstats_noportbytes] \
		[expr $diff_waiting_created + $diff_switched_created] \
		[expr $diff_waiting_deleted + $diff_switched_deleted] \
		[expr ($waiting_created + $switched_created + \
					$waiting_added + $switched_added) - \
			($waiting_deleted + $switched_deleted + \
					$waiting_removed + $switched_removed)] \
		$totalflows \
		$bintime \
		$timeouttime \
		[lindex $xx 0] \
		[lindex $xx 1] \
		[lindex $xx 5]]
	flush stdout
    }
}


# for compatibility...

proc \
simul { fixortcpd filename {binsecs 1} \
		{ llflows $LLFLOWS } { ulflows $ULFLOWS }} \
{
    class_details $fixortcpd $filename $binsecs
}
