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

proc switchtime {} { return 0.3 }	; # time to switch

proc\
classifier { class flowtype flowid }\
{
    global CL_NONSWITCHED CL_TO_BE_SWITCHED
    global FT_UL_PORT FT_UL_NOPORT

    regexp {/prot/([^/]*)/} $flowid match prot
    switch -exact -- $prot {
    6 {return "$CL_TO_BE_SWITCHED $FT_UL_PORT getswitched [switchtime]"}
    11 {return "$CL_NONSWITCHED $FT_UL_PORT"}
    default {return "$CL_NONSWITCHED $FT_UL_NOPORT"}
    }
}

proc\
getswitched { class flowtype flowid }\
{
    global CL_SWITCHED

    return $CL_SWITCHED
}
### END OF PARAMTERS ###

proc\
vec_difference { l1 l2 }\
{
    set len [llength $l1]
    set output [list]

    for {set i 0} {$i < $len} {incr i} {
	lappend output [expr [lindex $l1 $i] - [lindex $l2 $i]]
    }
    return $output
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

    set onon [list 0 0 0 0 0]
    set owaiting [list 0 0 0 0 0]
    set oswitched [list 0 0 0 0 0]
    while {1} {
	set binno [teho_read_one_bin $binsecs]
	if {$binno == -1} {
	    break;	# eof
	}
	set non [split [teho_class_summary $CL_NONSWITCHED]]
#	puts $non
	set waiting [split [teho_class_summary $CL_TO_BE_SWITCHED]]
#	puts $waiting
	set switched [split [teho_class_summary $CL_SWITCHED]]
#	puts $switched
	set diff3 [vec_difference $non $onon]
	set diff4 [vec_difference $waiting $owaiting]
	set diff5 [vec_difference $switched $oswitched]
	# "binno pktsrouted pktsbypassed newflows numflows"
	puts [format "%-7d %7d %7d %7d %7d" \
			$binno\
			[expr [lindex $diff3 2] + [lindex $diff4 2]] \
			[lindex $diff5 2] \
			[lindex $diff4 0] \
			[lindex $waiting 0]]
	set onon $non
	set owaiting $waiting
	set oswitched $switched
    }
}
