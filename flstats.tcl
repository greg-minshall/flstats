### PARAMETERS ###

# some DEFINES
set CL_NONSWITCHED	3
set CL_TO_BE_SWITCHED	4
set CL_SWITCHED		5

set FT_LL_PORT		0
set FT_LL_NOPORT	1
set FT_GUARD		2
set FT_UL_PORT		3
set FT_UL_NOPORT	4

proc switchtime {} { return 0.300000 }	; # time to switch

proc\
classifier { class flowtype flowid }\
{
    global CL_NONSWITCHED CL_TO_BE_SWITCHED CL_SWITCHED
    global FT_UL_PORT FT_UL_NOPORT FT_LL_NOPORT

#    6 {return "$CL_SWITCHED $FT_LL_NOPORT"}
    regexp {/prot/([^/]*)/} $flowid match prot
    switch -exact -- $prot {
    6 {return "$CL_TO_BE_SWITCHED $FT_UL_PORT getswitched [switchtime] \
							deleteflow 2.0 0x2"}
    11 {return "$CL_NONSWITCHED $FT_LL_NOPORT - 0.0 deleteflow 2.0 0x2"}
    default {return "$CL_NONSWITCHED $FT_LL_NOPORT - 0.0 deleteflow 2.0 0x2"}
    }
}

proc\
deleteflow {cookie class ftype flowid time FLOW args}\
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

    puts "- deleteflow $time.0 $time"
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
	return [list $ts_added $ts_removed $ts_active \
			$ts_pkts $ts_frags $ts_runts $ts_noports]
}


proc \
simul { fixortcpd filename {binsecs 1} } \
{
    global CL_NONSWITCHED CL_TO_BE_SWITCHED CL_SWITCHED

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

    # set low level flow types
    teho_set_flow_type -f 0 -s 1 -c classifier \
				ihv/ihl/tos/ttl/prot/src/dst/sport/dport
    teho_set_flow_type -f 1 -s 2 -c classifier ihv/ihl/tos/ttl/prot/src/dst
    # leave *2* uninitialized (as a guard)

    puts "# plotvars 1 binno 2 pktsrouted 3 pktsswitched 4 newflows 5 numflows"

    # we are looking at 3 classes: 3, 4, 5
    #	3	non-switched flows
    #	4	to-be-switched flows
    #	5	switched flows

    set onon [list 0 0 0 0 0 0 0]
    set owaiting [list 0 0 0 0 0 0 0]
    set oswitched [list 0 0 0 0 0 0 0]
    while {1} {
	set binno [teho_read_one_bin $binsecs]
	if {$binno == -1} {
	    break;	# eof
	}
	set non [get_summary_vec $CL_NONSWITCHED]
#	puts "non $non"
	set waiting [get_summary_vec $CL_TO_BE_SWITCHED]
#	puts "waiting $waiting"
	set switched [get_summary_vec $CL_SWITCHED]
#	puts "switched $switched"
	set diffnon [vec_difference $non $onon]
	set diffwaiting [vec_difference $waiting $owaiting]
	set diffswitched [vec_difference $switched $oswitched]
	# "binno pktsrouted pktsbypassed newflows numflows"
	puts [format "%-7d %7d %7d %7d %7d" \
			$binno\
			[expr [lindex $diffnon 3] + [lindex $diffwaiting 3]] \
			[lindex $diffswitched 3] \
			[lindex $diffwaiting 0] \
			[lindex $waiting 0]]
	teho_run_timeouts
	flush stdout
	set onon $non
	set owaiting $waiting
	set oswitched $switched
    }
}
