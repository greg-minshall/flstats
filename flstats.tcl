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
    global flowscreated

    if {$class == $CL_TO_BE_SWITCHED} {
	return "$class $class $flowtype getswitched [switchtime] \
							deleteflow 2.0 0x2"
    } else {
	if {$class != $CL_NONSWITCHED} {
	    incr flowscreated
	}
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
    global CL_SWITCHED CL_TO_BE_SWITCHED
    global flowsdeleted

    # ahh, dr. regsub... 
    regsub -all {([a-zA-Z_]+) ([0-9.]+)} $args {[set x_\1 \2]} bar
    subst $bar

    if {[expr $time - $x_last] > $cookie} {
	if {($class == $CL_SWITCHED) || ($class == $CL_TO_BE_SWITCHED)} {
	    incr flowsdeleted
	}
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

proc\
deletellflow {cookie class ftype flowid time FLOW args}\
{
    # ahh, dr. regsub... 
    regsub -all {([a-zA-Z_]+) ([0-9.]+)} $args {[set x_\1 \2]} bar
    subst $bar

    if {[expr $time - $x_last] > $cookie} {
	puts "DELETE"		; # gone...
	return "DELETE"		; # gone...
    }

    set time [expr 2 * $cookie]
    if {$time > 64} {
	set time 64
    }

    puts "- deletellflow $time.0 $time"
    return "- deletellflow $time.0 $time"
}


proc\
vec_difference { l1 l2 }\
{
    set len [llength $l1]
    if {$len > [llength $l2]} {
	set len [llength $l2]
    }
    set output [list]

    for {set i 0} {$i < $len} {incr i} {
	lappend output [expr [lindex $l1 $i] - [lindex $l2 $i]]
    }
    return $output
}

proc\
get_summary_vec {class} \
{
	# ahh, dr. regsub... 
	regsub -all {([a-zA-Z_]+) ([0-9]+)} \
			[teho_class_summary $class] {[set ts_\1 \2]} bar
	subst $bar
	return [list $ts_added $ts_removed $ts_active $ts_pkts $ts_fragpkts \
			$ts_runtpkts $ts_noportpkts $ts_fragbytes \
			$ts_runtbytes $ts_noportbytes $ts_bytes]
}


proc \
simul { fixortcpd filename {binsecs 1} } \
{
    global CL_NONSWITCHED CL_TO_BE_SWITCHED CL_SWITCHED
    global FT_LL_PORT FT_LL_NOPORT FT_UL_PORT FT_UL_NOPORT
    global flowscreated flowsdeleted

    set fname [glob $filename]
    file stat $fname filestats
    puts [format "# file %s size %d last written %d" \
			$fname $filestats(size) $filestats(mtime)]
    puts "#"
    puts "# binsecs $binsecs"
    puts "#"

    if [regexp -nocase fix $fixortcpd] {
	teho_set_fix_file $fname
    } elseif [regexp -nocase tcpd $fixortcpd] {
	teho_set_tcpd_file $fname
    } else {
	puts "bad fixortcpd"
	return
    }

    # set lower level flow types
    teho_set_flow_type -f $FT_LL_PORT -c classifier \
				ihv/ihl/tos/ttl/prot/src/dst/sport/dport
    teho_set_flow_type -f $FT_LL_NOPORT -c classifier \
				ihv/ihl/tos/ttl/prot/src/dst

    # leave *2* uninitialized (as a guard)

    # set upper level flow types
    teho_set_flow_type -f $FT_UL_PORT -c starttimeout \
				ihv/ihl/tos/ttl/prot/src/dst/sport/dport
    teho_set_flow_type -f $FT_UL_NOPORT -c starttimeout \
				ihv/ihl/tos/ttl/prot/src/dst


    puts "# plotvars 1 binno 2 pktsrouted 3 bytesrouted 4 pktsswitched"
    puts "# plotvars 5 bytesswitched 6 pktsdropped 7 bytesdropped"
    puts "# plotvars 8 created 9 deleted 10 numflows 11 totalflows"
    puts "# plotvars 12 bintime 13 timeouttime 14 vsz 15 rsz 16 cputime"

    # we are looking at 3 classes: 3, 4, 5
    #	3	non-switched flows
    #	4	to-be-switched flows
    #	5	switched flows

    set pid [pid]
    set onon 		[list 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
    set owaiting 	[list 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
    set oswitched	[list 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
    set ogstats		[list 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
    set oflowscreated 0
    set flowscreated 0
    set oflowsdeleted 0
    set flowsdeleted 0
    while {1} {
	set bintime [lindex [split [time {set binno [teho_read_one_bin $binsecs]}]] 0]
	if {$binno == -1} {
	    break;	# eof
	}
	set timeouttime [lindex [split [time {set totalflows [teho_run_timeouts]}]] 0 ]
	set non [get_summary_vec $CL_NONSWITCHED]
#	puts "non $non"
	set waiting [get_summary_vec $CL_TO_BE_SWITCHED]
#	puts "waiting $waiting"
	set switched [get_summary_vec $CL_SWITCHED]
#	puts "switched $switched"
	set gstats [get_summary_vec 0]
#	puts "gstats $gstats"
	set diffnon [vec_difference $non $onon]
	set diffwaiting [vec_difference $waiting $owaiting]
	set diffswitched [vec_difference $switched $oswitched]
	set diffgstats [vec_difference $gstats $ogstats]
	set xx [exec ps lp$pid]
	set xx [lrange [split [join $xx]] 19 24]
	puts [format \
	    "%-7d %7d %7d %7d %7d %7d %7d %7d %7d %7d %7d %7d %7d %7d %7d %s" \
			$binno\
			[expr [lindex $diffnon 3] + [lindex $diffwaiting 3]] \
			[expr [lindex $diffnon 10] + [lindex $diffwaiting 10]] \
			[lindex $diffswitched 3] \
			[lindex $diffswitched 10] \
			[expr [lindex $diffgstats 4] + [lindex $diffgstats 5] \
				+ [lindex $diffgstats 6]] \
			[expr [lindex $diffgstats 7] + [lindex $diffgstats 8] \
				+ [lindex $diffgstats 9]] \
			[expr $flowscreated - $oflowscreated] \
			[expr $flowsdeleted - $oflowsdeleted] \
			[expr ([lindex $waiting 0] + [lindex $switched 0]) - \
				([lindex $waiting 1] + [lindex $switched 1])] \
			$totalflows $bintime $timeouttime \
			[lindex $xx 0] [lindex $xx 1] [lindex $xx 5]]
	flush stdout
	set onon $non
	set owaiting $waiting
	set oswitched $switched
	set ogstats $gstats
	set oflowscreated $flowscreated
	set oflowsdeleted $flowsdeleted
    }
}
