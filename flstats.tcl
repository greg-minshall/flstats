# for compatibility...

proc \
simul { fixortcpd filename {binsecs 1} {classifier {}} \
				{classifiertype {}} { ulflows {} }} \
{
    fsim_class_details $fixortcpd $filename \
			$binsecs $classifier $classifiertype $ulflows
}


### PARAMETERS ###

# some DEFINES

# (note that because of ordering of upgrading parent classes, the *numbers*
# here are important!  (sigh)
set CL_NONSWITCHED		3
set CL_TO_BE_SWITCHED		4
set CL_SWITCHED			5

# when these are used, the values are set in [fsim_setft]
set FT_UL_PORT			0
set FT_UL_NOPORT		0

proc \
fsimswitchtime {} \
{
    return 0.300000 	; # time to switch
}

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
fsimclassifier { class flowtype flowid }\
{
    global CL_NONSWITCHED CL_TO_BE_SWITCHED CL_SWITCHED
    global FT_UL_PORT FT_UL_NOPORT

    regexp {/prot/([^/]*)/} $flowid match prot
    switch -exact -- $prot {
    6 {return "$class $CL_SWITCHED $FT_UL_NOPORT 0.0 2.0"}
    11 {return "$class $CL_NONSWITCHED $FT_UL_NOPORT 0.0 2.0"}
    default {return "$class $CL_NONSWITCHED $FT_UL_NOPORT 0.0 2.0"}
    }
}

#
# this is called when a new upper level flow is established.
# this gives us a chance to start a packet_recv and timeout
# process
#

proc\
fsimstarttimeout { class flowtype flowid }\
{
    global CL_TO_BE_SWITCHED CL_NONSWITCHED

    if {$class == $CL_TO_BE_SWITCHED} {
	return "$class $class $flowtype [fsimswitchtime] 2.0"
    } else {
	return "$class $class $flowtype 0.0 2.0"
    }
}

#
# this runs for both upper level and lower level flows
# to time them out.
#

proc\
fsimdeleteflow {class ftype flowid time FLOW args}\
{
    # ahh, dr. regsub... 
    regsub -all {([a-zA-Z_]+) ([0-9.]+)} $args {[set x_\1 \2]} bar
    subst $bar

    set idle [expr $time - $x_last]
    set life [expr $x_last - $x_created]
    if {($idle > $life) || ($idle > 64)} {
	return "DELETE"		; # gone...
    }

    set time [expr 2 * $life]
    if {$time > 64} {
	set time 64
    }

    return "- $time.0"
}


proc\
fsimgetswitched { class flowtype flowid args}\
{
    global CL_SWITCHED

    return "$CL_SWITCHED -"
}

### END OF PARAMTERS ###


# this doesn't need $pre, since the subst is performed at the caller...

proc\
fsimget_summary_vec {class} \
{
	# ahh, dr. regsub... 
	regsub -all {([a-zA-Z_]+) ([0-9]+)} \
			[fsim_class_summary $class] {[set ${pre}_\1 \2]} bar
	return $bar
}

# this doesn't need $pre, since the subst is performed at the caller...
#
# the $pre_\1 variables need to have been created prior to the
# call.  a call to fsimget_summary_vec (and subst'ing) on the same
# class does this.

proc\
fsimget_diff_vec {class} \
{
	# ahh, dr. regsub... 
	regsub -all {([a-zA-Z_]+) ([0-9]+)} [fsim_class_summary $class] \
			{[set diff_${pre}_\1 [expr \2 - $${pre}_\1]]} bar
	return $bar
}

proc\
fsimll_delete {class ftype flowid time FLOW args}\
{
    # ahh, dr. regsub... 
    regsub -all {([a-zA-Z_]+) ([0-9.]+)} $args {[set x_\1 \2]} bar
    subst $bar

    set idle [expr $time - $x_last]
    set life [expr $x_last - $x_created]
    if {($idle > $life) || ($idle > 64)} {
	return "DELETE"		; # gone...
    }

    set time [expr 2 * $life]
    if {$time > 64} {
	set time 64
    }

    return "- $time.0"
}

#
# end of local
#
# start of global


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
#    flow-type-string flow-type-index-variable newflow_cmd recv_cmd timeout_cmd
#
# where a flow of type flow-type-string is set up with classifier
# the index is placed in the variable flow-type-index-variable.
#

proc \
fsim_setft { classifier classifiertype ulflows } \
{

    # default UL flows...
    set ULFLOWS { \
	{   ihv/ihl/tos/ttl/prot/src/dst \
	    FT_UL_NOPORT \
	    fsimstarttimeout \
	    - \
	    fsimdeleteflow} \
	{   ihv/ihl/tos/ttl/prot/src/dst/sport/dport \
	    FT_UL_PORT \
	    fsimstarttimeout \
	    - \
	    fsimdeleteflow}}

    set ftindex 0

    # the following is like atoft in the .c file:
    set alltags { ihv ihl tos len id foff ttl prot sum src dst sport dport }


    if {$ulflows == {}} {
	set ulflows $ULFLOWS
    }
    if {$classifier == {}} {
	set classifier fsimclassifier
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
    puts "fsim_set_flow_type -f $ftindex -n $classifier -t fsimll_delete $type1"
    fsim_set_flow_type -f $ftindex -n $classifier -t fsimll_delete $type1
    incr ftindex
    if {$portsseen != 0} {
	puts "# flowtype $ftindex $type2 $classifier"
	fsim_set_flow_type -f $ftindex -n $classifier -t fsimll_delete $type2
	incr ftindex
    }

    incr ftindex			; # leave a gap between LL and UL

    # now, scan thru the input list again, setting flows...
    for {set whichflow 0} {$whichflow < [llength $ulflows]} \
					{ incr whichflow; incr ftindex } {
	set flow [lindex $ulflows $whichflow]
	puts "# flowtype $ftindex $flow"
	set len [llength $flow]
	if {$len >= 2} {
	    global [lindex $flow 1]
	    set [lindex $flow 1] $ftindex
	}
	if {$len >= 3} {
	    set newflow "[lindex $flow 2]"
	} else {
	    set newflow "-"
	}
	if {$len >= 4} {
	    set recv "[lindex $flow 3]"
	} else {
	    set recv "-"
	}
	if {$len >= 5} {
	    set timeout "[lindex $flow 4]"
	} else {
	    set timeout "-"
	}
	puts "fsim_set_flow_type -f $ftindex -n $newflow \
				-r $recv -t $timeout [lindex $flow 0]"
	fsim_set_flow_type -f $ftindex -n $newflow \
				-r $recv -t $timeout [lindex $flow 0]
    }
}

proc \
fsim_setup { fixortcpd filename {binsecs 1} {classifier {}} \
				{classifiertype {}} { ulflows {} }} \
{
    set fname [glob $filename]

    if [regexp -nocase fix $fixortcpd] {
	fsim_set_fix_file $fname
    } elseif [regexp -nocase tcpd $fixortcpd] {
	fsim_set_tcpd_file $fname
    } else {
	puts "bad fixortcpd"
	return
    }

    file stat $fname filestats
    puts [format "# file %s size %d last written %d" \
			$fname $filestats(size) $filestats(mtime)]

    puts "#"
    fsim_setft $classifier $classifiertype $ulflows

    puts "#"
    puts "# binsecs $binsecs"

    puts "#"
}


proc \
fsim_flow_details { fixortcpd filename {binsecs 1} {classifier {}} \
					{classifiertype {}} { ulflows {} }} \
{
    fsim_setup $fixortcpd $filename $binsecs $classifier \
					$classifiertype $ulflows

    while {1} {
	set bintime [lindex [split [time { \
			set binno [fsim_read_one_bin $binsecs]}]] 0]
	if {$binno == -1} {
	    break;	# eof
	}
	fsim_start_enumeration
	while { [set x [fsim_continue_enumeration]] != ""} {
	    puts "$binno $x"
	}
    }
}


proc \
fsim_class_details { fixortcpd filename {binsecs 1} {classifier {}} \
					{classifiertype {}} { ulflows {} }}\
{
    global CL_NONSWITCHED CL_TO_BE_SWITCHED CL_SWITCHED

    fsim_setup $fixortcpd $filename $binsecs $classifier \
					$classifiertype $ulflows

    puts "# plotvars 1 binno 2 pktsrouted 3 bytesrouted 4 pktsswitched"
    puts "# plotvars 5 bytesswitched 6 pktsdropped 7 bytesdropped"
    puts "# plotvars 8 created 9 deleted 10 numflows "
#    puts "# plotvars 11 bintime 12 vsz 13 rsz 14 cputime"

    # we look at 3 classes: CL_NONSWITCHED, CL_TO_BE_SWITCHED, CL_SWITCHED

    set pid [pid]


    # preload the stats counters
    set pre non
    subst [fsimget_summary_vec $CL_NONSWITCHED]
    set pre waiting
    subst [fsimget_summary_vec $CL_TO_BE_SWITCHED]
    set pre switched
    subst [fsimget_summary_vec $CL_SWITCHED]
    set pre gstats
    subst [fsimget_summary_vec 0]

    while {1} {
	set bintime [lindex [split [time { \
			set binno [fsim_read_one_bin $binsecs]}]] 0]
	if {$binno == -1} {
	    break;	# eof
	}

	# get differences from previous stats counters
	set pre non
	subst [fsimget_diff_vec $CL_NONSWITCHED]
	set pre waiting
	subst [fsimget_diff_vec $CL_TO_BE_SWITCHED]
	set pre switched
	subst [fsimget_diff_vec $CL_SWITCHED]
	set pre gstats
	subst [fsimget_diff_vec 0]

	# now, update the stats counters
	set pre non
	subst [fsimget_summary_vec $CL_NONSWITCHED]
	set pre waiting
	subst [fsimget_summary_vec $CL_TO_BE_SWITCHED]
	set pre switched
	subst [fsimget_summary_vec $CL_SWITCHED]
	set pre gstats
	subst [fsimget_summary_vec 0]
	set xx [exec ps lp$pid]
	set xx [lrange [split [join $xx]] 19 24]
	puts [format \
	    "%-7d %7d %7d %7d %7d %7d %7d %7d %7d %7d" \
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
					$waiting_removed + $switched_removed)]]
		; # $bintime
		; # [lindex $xx 0]
		; # [lindex $xx 1]
		; # [lindex $xx 5] ]
	flush stdout
    }
}

proc\
fsim_startup { }\
{
    global tcl_RcFileName

    set tcl_RcFileName "~/.flowsim.tcl"
}
