### PARAMETERS ###

# some DEFINES

# (note that because of ordering of upgrading parent classes, the *numbers*
# here are important!  (sigh)
set CL_NONSWITCHED		3
set CL_TO_BE_SWITCHED		4
set CL_SWITCHED			5

# when these are used, the values are set in [teho_setft]
set FT_LL_PORT			0
set FT_LL_NOPORT		0
set FT_GUARD			0
set FT_UL_PORT			0
set FT_UL_NOPORT		0

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
teho_get_summary_vec {class} \
{
	# ahh, dr. regsub... 
	regsub -all {([a-zA-Z_]+) ([0-9]+)} \
			[teho_class_summary $class] {[set ${pre}_\1 \2]} bar
	return $bar
}

# this doesn't need $pre, since the subst is performed at the caller...
#
# the $pre_\1 variables need to have been created prior to the
# call.  a call to teho_get_summary_vec (and subst'ing) on the same
# class does this.

proc\
teho_get_diff_vec {class} \
{
	# ahh, dr. regsub... 
	regsub -all {([a-zA-Z_]+) ([0-9]+)} [teho_class_summary $class] \
			{[set diff_${pre}_\1 [expr \2 - $${pre}_\1]]} bar
	return $bar
}

proc\
teho_ll_delete {cookie class ftype flowid time FLOW args}\
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

    return "- teho_ll_delete $time.0 $time"
}



#
# set up the flow types, using the upper level flows.
#
# we create either one or two low level flows.  one is
# the "merge" of all the fields used in the upper level
# flows.  the second is only created if one or more of the
# upper level flows use ports, and it is the first minus
# the ports.
#
# classifier is the classifier to be used when new low level
# flows arrive and need to be correlated with an upper level
# flow.
#
# classifiertype is the "flow type string" (ihv/ihl/...) which
# the classifier needs to use to classify flows.
#
# ulflows is a list of lists.  the inner list has the form:
#
#		flow-type-string classifier flow-type-index-variable
#
# where a flow of type flow-type-string is set up with classifier
# the index is placed in the variable flow-type-index-variable.
#

proc \
teho_setft { classifier classifiertype ulflows } \
{
    set ULFLOWS { \
	{ ihv/ihl/tos/ttl/prot/src/dst starttimeout FT_UL_NOPORT } \
	{ ihv/ihl/tos/ttl/prot/src/dst/sport/dport starttimeout FT_UL_PORT }}
    set ftindex 0
    # the following is like atoft in the .c file:
    set alltags { ihv ihl tos len id foff ttl prot sum src dst sport dport }

    if {$ulflows == {}} {
	set ulflows $ULFLOWS
    }
    if {$classifier == {}} {
	set classifier classifier
    }

    # ok, scan thru upper layer flows, keeping track of used tags
    for {set whichflow 0} {$whichflow < [llength $ulflows]} \
						{ incr whichflow} {
	set type [lindex [lindex $ulflows $whichflow] 0]
	set types [split $type /]
	foreach type $types {
	    if {[lsearch -exact $alltags $type] == -1} {
		error "unknown flow type tag $type"
	    }
	    set fltags($type) 1
	}
    }

    # now, make sure we get all the stuff the classifier needs
    # (the point being to produce the union of everything)
    set classifiertype [split $classifiertype /]
    foreach type $classifiertype {
	if {[lsearch -exact $alltags $type] == -1} {
	    error "unknown flow type tag $type in classifiertype"
	}
	set fltags($type) 1
    }
    
    # now, know all the tags, build the flow type(s)
    set type1 {}
    set type2 {}
    set portsseen 0			; # have we seen any ports?
    foreach tag $alltags {
	if {[info exists fltags($tag)]} {
	    lappend type1 $tag
	    if {($tag == "sport") || ($tag == "dport")} {
		# don't put ports in type2
		set portsseen 1
	    } else {
		lappend type2 $tag
	    }
	}
    }
    set type1 [join $type1 /]
    set type2 [join $type2 /]
    puts "# flowtype $ftindex $type1 $classifier"
    teho_set_flow_type -f $ftindex -c $classifier $type1
    incr ftindex
    if {$portsseen != 0} {
	puts "# flowtype $ftindex $type2 $classifier"
	teho_set_flow_type -f $ftindex -c $classifier $type2
	incr ftindex
    }

    incr ftindex			; # leave a gap between LL and UL

    # now, scan thru the input list again, setting flows...
    for {set whichflow 0} {$whichflow < [llength $ulflows]} \
					{ incr whichflow; incr ftindex } {
	set flow [lindex $ulflows $whichflow]
	puts "# flowtype $ftindex $flow"
	set len [llength $flow]
	if {$len >= 3} {
	    global [lindex $flow 2]
	    set [lindex $flow 2] $ftindex
	}
	if {$len >= 2} {
	    teho_set_flow_type -f $ftindex -c [lindex $flow 1] \
							[lindex $flow 0]
	} else {
	    teho_set_flow_type -f $ftindex [lindex $flow 0]
	}
    }
}

proc \
teho_setup { fixortcpd filename {binsecs 1} {classifier {}} \
				{classifiertype {}} { ulflows {} }} \
{
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
    teho_setft $classifier $classifiertype $ulflows

    puts "#"
    puts "# binsecs $binsecs"

    puts "#"
}


proc \
teho_flow_details { fixortcpd filename {binsecs 1} {classifier {}} \
					{classifiertype {}} { ulflows {} }} \
{
    global CL_NONSWITCHED CL_TO_BE_SWITCHED CL_SWITCHED
    global FT_LL_PORT FT_LL_NOPORT FT_UL_PORT FT_UL_NOPORT

    teho_setup $fixortcpd $filename $binsecs $classifier \
					$classifiertype $ulflows

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
teho_class_details { fixortcpd filename {binsecs 1} {classifier {}} \
					{classifiertype {}} { ulflows {} }}\
{
    global CL_NONSWITCHED CL_TO_BE_SWITCHED CL_SWITCHED
    global FT_LL_PORT FT_LL_NOPORT FT_UL_PORT FT_UL_NOPORT

    teho_setup $fixortcpd $filename $binsecs $classifier \
					$classifiertype $ulflows

    puts "# plotvars 1 binno 2 pktsrouted 3 bytesrouted 4 pktsswitched"
    puts "# plotvars 5 bytesswitched 6 pktsdropped 7 bytesdropped"
    puts "# plotvars 8 created 9 deleted 10 numflows 11 totalflows"
    puts "# plotvars 12 bintime 13 timeouttime 14 vsz 15 rsz 16 cputime"

    # we look at 3 classes: CL_NONSWITCHED, CL_TO_BE_SWITCHED, CL_SWITCHED

    set pid [pid]


    # preload the stats counters
    set pre non
    subst [teho_get_summary_vec $CL_NONSWITCHED]
    set pre waiting
    subst [teho_get_summary_vec $CL_TO_BE_SWITCHED]
    set pre switched
    subst [teho_get_summary_vec $CL_SWITCHED]
    set pre gstats
    subst [teho_get_summary_vec 0]

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
	subst [teho_get_diff_vec $CL_NONSWITCHED]
	set pre waiting
	subst [teho_get_diff_vec $CL_TO_BE_SWITCHED]
	set pre switched
	subst [teho_get_diff_vec $CL_SWITCHED]
	set pre gstats
	subst [teho_get_diff_vec 0]

	# now, update the stats counters
	set pre non
	subst [teho_get_summary_vec $CL_NONSWITCHED]
	set pre waiting
	subst [teho_get_summary_vec $CL_TO_BE_SWITCHED]
	set pre switched
	subst [teho_get_summary_vec $CL_SWITCHED]
	set pre gstats
	subst [teho_get_summary_vec 0]
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
simul { fixortcpd filename {binsecs 1} {classifier {}} \
				{classifiertype {}} { ulflows {} }} \
{
    teho_class_details $fixortcpd $filename $binsecs $classifier $classifiertype $ulflows
}
